use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u8};
use nom::IResult;

/// Extract the SNI (Server Name Indication) hostname from a TLS ClientHello payload.
///
/// Returns `None` if the payload is not a valid ClientHello or has no SNI extension.
pub fn extract_sni(payload: &[u8]) -> Option<String> {
    parse_client_hello(payload).ok().and_then(|(_, sni)| sni)
}

fn parse_client_hello(input: &[u8]) -> IResult<&[u8], Option<String>> {
    // TLS Record Header
    let (input, content_type) = be_u8(input)?;
    if content_type != 0x16 {
        // Not a TLS Handshake record
        return Ok((input, None));
    }

    let (input, _version) = be_u16(input)?; // TLS version (e.g., 0x0301)
    let (input, record_length) = be_u16(input)?;
    let (input, _record_data) = take(record_length)(input)?;

    // Use the record data for the rest of parsing
    let record_data = _record_data;
    let input_after = input;

    // Handshake Header
    let (data, handshake_type) = be_u8(record_data)?;
    if handshake_type != 0x01 {
        // Not a ClientHello
        return Ok((input_after, None));
    }

    // Handshake length (3 bytes, big-endian)
    let (data, len_bytes) = take(3u8)(data)?;
    let _handshake_length =
        ((len_bytes[0] as u32) << 16) | ((len_bytes[1] as u32) << 8) | (len_bytes[2] as u32);

    // Client version (2 bytes)
    let (data, _client_version) = be_u16(data)?;

    // Random (32 bytes)
    let (data, _random) = take(32u8)(data)?;

    // Session ID (1 byte length + variable)
    let (data, session_id_len) = be_u8(data)?;
    let (data, _session_id) = take(session_id_len)(data)?;

    // Cipher Suites (2 byte length + variable)
    let (data, cipher_suites_len) = be_u16(data)?;
    let (data, _cipher_suites) = take(cipher_suites_len)(data)?;

    // Compression Methods (1 byte length + variable)
    let (data, compression_len) = be_u8(data)?;
    let (data, _compression) = take(compression_len)(data)?;

    // Extensions (2 byte total length)
    if data.is_empty() {
        return Ok((input_after, None));
    }
    let (data, extensions_len) = be_u16(data)?;
    let (_, extensions_data) = take(extensions_len)(data)?;

    // Parse extensions looking for SNI (type 0x0000)
    let sni = parse_extensions(extensions_data);
    Ok((input_after, sni))
}

fn parse_extensions(mut data: &[u8]) -> Option<String> {
    while data.len() >= 4 {
        let (rest, ext_type) = be_u16::<&[u8], nom::error::Error<&[u8]>>(data).ok()?;
        let (rest, ext_length) = be_u16::<&[u8], nom::error::Error<&[u8]>>(rest).ok()?;

        if rest.len() < ext_length as usize {
            return None;
        }

        if ext_type == 0x0000 {
            // Server Name extension
            let ext_data = &rest[..ext_length as usize];
            return parse_sni_extension(ext_data);
        }

        let (rest, _) =
            take::<usize, &[u8], nom::error::Error<&[u8]>>(ext_length as usize)(rest).ok()?;
        data = rest;
    }

    None
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    // Server Name List Length (2 bytes)
    let (data, _list_length) = be_u16::<&[u8], nom::error::Error<&[u8]>>(data).ok()?;

    // Server Name Type (1 byte) — 0x00 = hostname
    let (data, name_type) = be_u8::<&[u8], nom::error::Error<&[u8]>>(data).ok()?;
    if name_type != 0x00 {
        return None;
    }

    // Server Name Length (2 bytes)
    let (data, name_length) = be_u16::<&[u8], nom::error::Error<&[u8]>>(data).ok()?;
    let (_, name_bytes) =
        take::<usize, &[u8], nom::error::Error<&[u8]>>(name_length as usize)(data).ok()?;

    std::str::from_utf8(name_bytes).ok().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS ClientHello with the given SNI hostname.
    fn build_client_hello(hostname: &str) -> Vec<u8> {
        let mut pkt = Vec::new();

        // SNI extension data
        let name_bytes = hostname.as_bytes();
        let sni_ext = {
            let mut ext = Vec::new();
            // server_name_list_length
            let list_len = (name_bytes.len() + 3) as u16;
            ext.extend_from_slice(&list_len.to_be_bytes());
            // name_type: host_name (0x00)
            ext.push(0x00);
            // name_length
            ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
            ext.extend_from_slice(name_bytes);
            ext
        };

        // Extensions block
        let extensions = {
            let mut exts = Vec::new();
            // SNI extension (type 0x0000)
            exts.extend_from_slice(&[0x00, 0x00]); // extension type
            exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
            exts.extend_from_slice(&sni_ext);
            exts
        };

        // ClientHello body
        let mut hello_body = Vec::new();
        hello_body.extend_from_slice(&[0x03, 0x03]); // client version TLS 1.2
        hello_body.extend_from_slice(&[0x00; 32]); // random
        hello_body.push(0x00); // session ID length: 0
        hello_body.extend_from_slice(&[0x00, 0x02]); // cipher suites length: 2
        hello_body.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
        hello_body.push(0x01); // compression methods length: 1
        hello_body.push(0x00); // null compression
        hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello_body.extend_from_slice(&extensions);

        // Handshake header
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let hs_len = hello_body.len() as u32;
        handshake.push((hs_len >> 16) as u8);
        handshake.push((hs_len >> 8) as u8);
        handshake.push(hs_len as u8);
        handshake.extend_from_slice(&hello_body);

        // TLS Record header
        pkt.push(0x16); // content type: Handshake
        pkt.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 (record layer version)
        pkt.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&handshake);

        pkt
    }

    fn build_client_hello_with_preceding_extension(hostname: &str) -> Vec<u8> {
        let mut pkt = Vec::new();

        // SNI extension data
        let name_bytes = hostname.as_bytes();
        let sni_ext = {
            let mut ext = Vec::new();
            let list_len = (name_bytes.len() + 3) as u16;
            ext.extend_from_slice(&list_len.to_be_bytes());
            ext.push(0x00);
            ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
            ext.extend_from_slice(name_bytes);
            ext
        };

        // Extensions block: put a dummy extension before SNI
        let extensions = {
            let mut exts = Vec::new();
            // Dummy extension (type 0x0023 = session_ticket)
            exts.extend_from_slice(&[0x00, 0x23]); // extension type
            exts.extend_from_slice(&[0x00, 0x00]); // length: 0

            // SNI extension (type 0x0000)
            exts.extend_from_slice(&[0x00, 0x00]);
            exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
            exts.extend_from_slice(&sni_ext);
            exts
        };

        // ClientHello body
        let mut hello_body = Vec::new();
        hello_body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        hello_body.extend_from_slice(&[0x00; 32]); // random
        hello_body.push(0x00); // session ID length
        hello_body.extend_from_slice(&[0x00, 0x02]); // cipher suites length
        hello_body.extend_from_slice(&[0x00, 0x2f]); // cipher suite
        hello_body.push(0x01); // compression methods length
        hello_body.push(0x00); // null compression
        hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello_body.extend_from_slice(&extensions);

        // Handshake header
        let mut handshake = Vec::new();
        handshake.push(0x01);
        let hs_len = hello_body.len() as u32;
        handshake.push((hs_len >> 16) as u8);
        handshake.push((hs_len >> 8) as u8);
        handshake.push(hs_len as u8);
        handshake.extend_from_slice(&hello_body);

        // TLS Record header
        pkt.push(0x16);
        pkt.extend_from_slice(&[0x03, 0x01]);
        pkt.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&handshake);

        pkt
    }

    #[test]
    fn extract_sni_github() {
        let hello = build_client_hello("github.com");
        let sni = extract_sni(&hello);
        assert_eq!(sni.as_deref(), Some("github.com"));
    }

    #[test]
    fn extract_sni_long_hostname() {
        let hello = build_client_hello("api.us-east-1.amazonaws.com");
        let sni = extract_sni(&hello);
        assert_eq!(sni.as_deref(), Some("api.us-east-1.amazonaws.com"));
    }

    #[test]
    fn extract_sni_with_preceding_extension() {
        let hello = build_client_hello_with_preceding_extension("example.org");
        let sni = extract_sni(&hello);
        assert_eq!(sni.as_deref(), Some("example.org"));
    }

    #[test]
    fn non_tls_returns_none() {
        assert!(extract_sni(&[]).is_none());
        assert!(extract_sni(&[0x15, 0x03, 0x03]).is_none()); // Not handshake (0x15 = alert)
        assert!(extract_sni(&[0x00; 50]).is_none());
    }

    #[test]
    fn truncated_returns_none() {
        let hello = build_client_hello("github.com");
        // Truncate at various points
        assert!(extract_sni(&hello[..5]).is_none());
        assert!(extract_sni(&hello[..20]).is_none());
    }

    #[test]
    fn non_client_hello_handshake_returns_none() {
        // Build a valid TLS record but with ServerHello (type 0x02) instead
        let mut pkt = Vec::new();
        pkt.push(0x16); // Handshake
        pkt.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        let body = vec![0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00]; // type 0x02 = ServerHello
        pkt.extend_from_slice(&(body.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&body);
        assert!(extract_sni(&pkt).is_none());
    }
}
