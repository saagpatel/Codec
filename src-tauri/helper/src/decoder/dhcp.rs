use std::net::{IpAddr, Ipv4Addr};

/// Result of decoding a DHCP packet.
#[derive(Debug, Clone)]
#[allow(dead_code)] // assigned_ip used by aggregator for IP→MAC tracking
pub struct DhcpResult {
    pub hostname: Option<String>,
    pub client_mac: [u8; 6],
    pub assigned_ip: Option<IpAddr>,
}

const DHCP_MIN_LEN: usize = 240;
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Decode a DHCP packet payload (UDP ports 67/68).
///
/// Extracts client MAC, hostname (option 12), and assigned IP (yiaddr).
pub fn decode_dhcp(payload: &[u8]) -> Option<DhcpResult> {
    if payload.len() < DHCP_MIN_LEN {
        return None;
    }

    // Verify magic cookie at bytes 236-239
    if payload[236..240] != MAGIC_COOKIE {
        return None;
    }

    // Extract client MAC from chaddr (bytes 28-33)
    let mut client_mac = [0u8; 6];
    client_mac.copy_from_slice(&payload[28..34]);

    // Extract yiaddr (bytes 16-19) — assigned IP
    let yiaddr_bytes = &payload[16..20];
    let assigned_ip = if yiaddr_bytes != [0, 0, 0, 0] {
        Some(IpAddr::V4(Ipv4Addr::new(
            yiaddr_bytes[0],
            yiaddr_bytes[1],
            yiaddr_bytes[2],
            yiaddr_bytes[3],
        )))
    } else {
        None
    };

    // Parse options starting at byte 240
    let mut hostname: Option<String> = None;
    let mut i = 240;

    while i < payload.len() {
        let option_type = payload[i];

        match option_type {
            255 => break, // End of options
            0 => {
                // Padding — no length byte
                i += 1;
                continue;
            }
            _ => {
                if i + 1 >= payload.len() {
                    break;
                }
                let option_len = payload[i + 1] as usize;
                let data_start = i + 2;
                let data_end = data_start + option_len;

                if data_end > payload.len() {
                    break;
                }

                if option_type == 12 {
                    // Hostname
                    if let Ok(name) = std::str::from_utf8(&payload[data_start..data_end]) {
                        let name = name.trim();
                        if !name.is_empty() {
                            hostname = Some(name.to_string());
                        }
                    }
                }

                i = data_end;
            }
        }
    }

    Some(DhcpResult {
        hostname,
        client_mac,
        assigned_ip,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DHCP packet with the given fields.
    fn build_dhcp_packet(client_mac: [u8; 6], yiaddr: [u8; 4], hostname: Option<&str>) -> Vec<u8> {
        let mut pkt = vec![0u8; 240];

        // op=1 (request), htype=1 (ethernet), hlen=6
        pkt[0] = 1;
        pkt[1] = 1;
        pkt[2] = 6;

        // yiaddr at bytes 16-19
        pkt[16..20].copy_from_slice(&yiaddr);

        // chaddr at bytes 28-43 (first 6 = MAC)
        pkt[28..34].copy_from_slice(&client_mac);

        // Magic cookie at 236-239
        pkt[236..240].copy_from_slice(&MAGIC_COOKIE);

        // Options
        if let Some(name) = hostname {
            let name_bytes = name.as_bytes();
            pkt.push(12); // option type: hostname
            pkt.push(name_bytes.len() as u8);
            pkt.extend_from_slice(name_bytes);
        }

        // Option 53: message type (DHCP Request = 3)
        pkt.push(53);
        pkt.push(1);
        pkt.push(3);

        // End of options
        pkt.push(255);

        pkt
    }

    #[test]
    fn decode_dhcp_with_hostname() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let pkt = build_dhcp_packet(mac, [0, 0, 0, 0], Some("MyLaptop"));
        let result = decode_dhcp(&pkt).expect("should decode");
        assert_eq!(result.hostname.as_deref(), Some("MyLaptop"));
        assert_eq!(result.client_mac, mac);
        assert!(result.assigned_ip.is_none());
    }

    #[test]
    fn decode_dhcp_with_assigned_ip() {
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let pkt = build_dhcp_packet(mac, [192, 168, 1, 50], None);
        let result = decode_dhcp(&pkt).expect("should decode");
        assert!(result.hostname.is_none());
        assert_eq!(
            result.assigned_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)))
        );
    }

    #[test]
    fn decode_dhcp_with_all_fields() {
        let mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let pkt = build_dhcp_packet(mac, [10, 0, 0, 42], Some("iPhone"));
        let result = decode_dhcp(&pkt).expect("should decode");
        assert_eq!(result.hostname.as_deref(), Some("iPhone"));
        assert_eq!(result.client_mac, mac);
        assert_eq!(
            result.assigned_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)))
        );
    }

    #[test]
    fn decode_short_packet_returns_none() {
        assert!(decode_dhcp(&[]).is_none());
        assert!(decode_dhcp(&[0u8; 100]).is_none());
        assert!(decode_dhcp(&[0u8; 239]).is_none());
    }

    #[test]
    fn decode_bad_magic_cookie_returns_none() {
        let mut pkt = vec![0u8; 244];
        pkt[236..240].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // wrong cookie
        pkt[243] = 255; // end of options
        assert!(decode_dhcp(&pkt).is_none());
    }

    #[test]
    fn decode_no_hostname_still_extracts_mac() {
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let pkt = build_dhcp_packet(mac, [0, 0, 0, 0], None);
        let result = decode_dhcp(&pkt).expect("should decode");
        assert!(result.hostname.is_none());
        assert_eq!(result.client_mac, mac);
    }
}
