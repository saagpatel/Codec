use simple_dns::rdata::RData;
use simple_dns::Packet as DnsPacket;
use std::net::IpAddr;

/// Result of decoding an mDNS packet.
#[derive(Debug, Clone)]
#[allow(dead_code)] // source_ip used in tests and for future device correlation
pub struct MdnsResult {
    pub source_ip: IpAddr,
    pub hostname: Option<String>,
    pub device_type_hint: Option<String>,
}

/// Decode an mDNS packet (same wire format as DNS, port 5353).
///
/// Extracts device type hints from PTR records and hostnames from A/AAAA/SRV records.
pub fn decode_mdns(payload: &[u8], source_ip: IpAddr) -> Option<MdnsResult> {
    if payload.is_empty() {
        return None;
    }

    let packet = DnsPacket::parse(payload).ok()?;

    let mut hostname: Option<String> = None;
    let mut device_type_hint: Option<String> = None;

    // Scan all record sections: answers, authority, additional
    let all_records = packet
        .answers
        .iter()
        .chain(packet.additional_records.iter())
        .chain(packet.name_servers.iter());

    for record in all_records {
        let name = record.name.to_string();
        let name_lower = name.to_lowercase();

        match &record.rdata {
            RData::PTR(ptr) => {
                let ptr_str = ptr.0.to_string().to_lowercase();
                // Map well-known service types to device type hints
                let hint = classify_service(&ptr_str).or_else(|| classify_service(&name_lower));
                if hint.is_some() && device_type_hint.is_none() {
                    device_type_hint = hint;
                }
            }
            RData::A(a) => {
                let h = strip_local_suffix(&name);
                if !h.is_empty() {
                    let record_ip = IpAddr::V4(a.address.into());
                    // Prefer hostname from A record matching source_ip; fall back to first seen
                    if record_ip == source_ip || hostname.is_none() {
                        hostname = Some(h);
                    }
                }
            }
            RData::AAAA(aaaa) => {
                let h = strip_local_suffix(&name);
                if !h.is_empty() {
                    let record_ip = IpAddr::V6(aaaa.address.into());
                    if record_ip == source_ip || hostname.is_none() {
                        hostname = Some(h);
                    }
                }
            }
            RData::SRV(srv) => {
                // SRV target field contains the hostname
                let target = srv.target.to_string();
                let h = strip_local_suffix(&target);
                if !h.is_empty() && hostname.is_none() {
                    hostname = Some(h);
                }
            }
            _ => {}
        }
    }

    // Also check questions section for PTR queries (device announcements)
    for question in &packet.questions {
        let qname = question.qname.to_string().to_lowercase();
        let hint = classify_service(&qname);
        if hint.is_some() && device_type_hint.is_none() {
            device_type_hint = hint;
        }
    }

    // Only return Some if we got something useful
    if hostname.is_some() || device_type_hint.is_some() {
        Some(MdnsResult {
            source_ip,
            hostname,
            device_type_hint,
        })
    } else {
        None
    }
}

/// Map known mDNS service type strings to device type hints.
fn classify_service(s: &str) -> Option<String> {
    if s.contains("_apple-mobdev2._tcp") {
        Some("iPhone".to_string())
    } else if s.contains("_companion-link._tcp") {
        Some("Mac".to_string())
    } else if s.contains("_googlecast._tcp") {
        Some("SmartTV".to_string())
    } else if s.contains("_spotify-connect._tcp") {
        Some("speaker".to_string())
    } else if s.contains("_airplay._tcp") || s.contains("_raop._tcp") {
        Some("AirPlay".to_string())
    } else if s.contains("_smb._tcp") {
        Some("laptop".to_string())
    } else if s.contains("_printer._tcp") || s.contains("_http._tcp") {
        Some("IoT".to_string())
    } else {
        None
    }
}

/// Strip `.local.` or `.local` suffix from an mDNS name.
fn strip_local_suffix(name: &str) -> String {
    let trimmed = name.trim_end_matches('.');
    if let Some(base) = trimmed.strip_suffix(".local") {
        base.to_string()
    } else {
        // Don't return non-.local names as hostnames
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal mDNS response with a single PTR record.
    ///
    /// ptr_owner: the domain name owning the PTR record (e.g. `_googlecast._tcp.local`)
    /// ptr_target: what it points to (can be any string, mDNS PTR targets are instance names)
    fn build_mdns_ptr_response(ptr_owner: &str, ptr_target: &str) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Header: transaction ID 0, QR=1 (response), AA=1, 0 questions, 1 answer
        pkt.extend_from_slice(&[0x00, 0x00]); // transaction ID
        pkt.extend_from_slice(&[0x84, 0x00]); // flags: response + authoritative
        pkt.extend_from_slice(&[0x00, 0x00]); // questions: 0
        pkt.extend_from_slice(&[0x00, 0x01]); // answers: 1
        pkt.extend_from_slice(&[0x00, 0x00]); // authority: 0
        pkt.extend_from_slice(&[0x00, 0x00]); // additional: 0

        // PTR record owner name
        let owner_offset = pkt.len();
        encode_dns_name(&mut pkt, ptr_owner);

        // PTR record: type=12 (PTR), class=IN (1), TTL, rdlength, rdata
        pkt.extend_from_slice(&[0x00, 0x0c]); // type: PTR
        pkt.extend_from_slice(&[0x00, 0x01]); // class: IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x11, 0x94]); // TTL: 4500

        // RDATA: target name (encode, then patch rdlength)
        let rdlen_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]); // placeholder for rdlength
        let rdata_start = pkt.len();
        encode_dns_name(&mut pkt, ptr_target);
        let rdata_end = pkt.len();

        // Patch rdlength
        let rdlen = (rdata_end - rdata_start) as u16;
        pkt[rdlen_pos] = (rdlen >> 8) as u8;
        pkt[rdlen_pos + 1] = rdlen as u8;

        let _ = owner_offset; // suppress unused warning
        pkt
    }

    /// Build a minimal mDNS response with a single A record.
    fn build_mdns_a_response(hostname: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Header
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x84, 0x00]); // response + authoritative
        pkt.extend_from_slice(&[0x00, 0x00]); // questions: 0
        pkt.extend_from_slice(&[0x00, 0x01]); // answers: 1
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);

        // A record owner name (e.g. "MyiPhone.local")
        encode_dns_name(&mut pkt, hostname);

        // A record: type=1, class=IN (flush bit set: 0x8001), TTL, rdlength=4, IP
        pkt.extend_from_slice(&[0x00, 0x01]); // type: A
        pkt.extend_from_slice(&[0x00, 0x01]); // class: IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0xf0]); // TTL: 240
        pkt.extend_from_slice(&[0x00, 0x04]); // rdlength: 4
        pkt.extend_from_slice(&ip); // IP address

        pkt
    }

    /// Encode a domain name in DNS wire format (labels).
    fn encode_dns_name(buf: &mut Vec<u8>, name: &str) {
        for label in name.trim_end_matches('.').split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // root label
    }

    #[test]
    fn ptr_googlecast_returns_smart_tv_hint() {
        let pkt = build_mdns_ptr_response("_googlecast._tcp.local", "MyTV._googlecast._tcp.local");
        let src: IpAddr = "192.168.1.50".parse().unwrap();
        let result = decode_mdns(&pkt, src).expect("should decode");
        assert_eq!(result.device_type_hint.as_deref(), Some("SmartTV"));
    }

    #[test]
    fn a_record_hostname_extracted() {
        let pkt = build_mdns_a_response("MyiPhone.local", [192, 168, 1, 100]);
        let src: IpAddr = "192.168.1.100".parse().unwrap();
        let result = decode_mdns(&pkt, src).expect("should decode");
        assert_eq!(result.hostname.as_deref(), Some("MyiPhone"));
    }

    #[test]
    fn malformed_empty_packet_returns_none() {
        let src: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(decode_mdns(&[], src).is_none());
        // A packet that's too short to parse
        assert!(decode_mdns(&[0x00, 0x00, 0x84, 0x00, 0x00], src).is_none());
    }

    #[test]
    fn multiple_records_most_specific_hint() {
        // Build a response with _smb._tcp.local (laptop) AND _apple-mobdev2._tcp.local (iPhone)
        // iPhone hint should win (found first in iteration — both are inserted, first non-None wins)
        let mut pkt = Vec::new();

        // Header: 0 questions, 2 answers
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x84, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x02]); // 2 answers
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);

        // PTR record 1: _apple-mobdev2._tcp.local
        let owner1 = "_apple-mobdev2._tcp.local";
        let target1 = "MyDevice._apple-mobdev2._tcp.local";
        encode_dns_name_to(&mut pkt, owner1);
        pkt.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x94]);
        let rdlen_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]);
        let rdata_start = pkt.len();
        encode_dns_name_to(&mut pkt, target1);
        let rdlen = (pkt.len() - rdata_start) as u16;
        pkt[rdlen_pos] = (rdlen >> 8) as u8;
        pkt[rdlen_pos + 1] = rdlen as u8;

        // PTR record 2: _smb._tcp.local
        let owner2 = "_smb._tcp.local";
        let target2 = "MyDevice._smb._tcp.local";
        encode_dns_name_to(&mut pkt, owner2);
        pkt.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x94]);
        let rdlen_pos2 = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]);
        let rdata_start2 = pkt.len();
        encode_dns_name_to(&mut pkt, target2);
        let rdlen2 = (pkt.len() - rdata_start2) as u16;
        pkt[rdlen_pos2] = (rdlen2 >> 8) as u8;
        pkt[rdlen_pos2 + 1] = rdlen2 as u8;

        let src: IpAddr = "192.168.1.5".parse().unwrap();
        let result = decode_mdns(&pkt, src).expect("should decode");
        // First match wins — _apple-mobdev2 maps to "iPhone"
        assert_eq!(result.device_type_hint.as_deref(), Some("iPhone"));
    }

    fn encode_dns_name_to(buf: &mut Vec<u8>, name: &str) {
        for label in name.trim_end_matches('.').split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
    }

    #[test]
    fn classify_service_all_types() {
        assert_eq!(
            classify_service("_apple-mobdev2._tcp.local").as_deref(),
            Some("iPhone")
        );
        assert_eq!(
            classify_service("_companion-link._tcp.local").as_deref(),
            Some("Mac")
        );
        assert_eq!(
            classify_service("_googlecast._tcp.local").as_deref(),
            Some("SmartTV")
        );
        assert_eq!(
            classify_service("_spotify-connect._tcp.local").as_deref(),
            Some("speaker")
        );
        assert_eq!(
            classify_service("_airplay._tcp.local").as_deref(),
            Some("AirPlay")
        );
        assert_eq!(
            classify_service("_raop._tcp.local").as_deref(),
            Some("AirPlay")
        );
        assert_eq!(
            classify_service("_smb._tcp.local").as_deref(),
            Some("laptop")
        );
        assert_eq!(
            classify_service("_printer._tcp.local").as_deref(),
            Some("IoT")
        );
        assert_eq!(classify_service("_http._tcp.local").as_deref(), Some("IoT"));
        assert_eq!(classify_service("_unknown._tcp.local"), None);
    }

    #[test]
    fn strip_local_suffix_works() {
        assert_eq!(strip_local_suffix("MyPhone.local"), "MyPhone");
        assert_eq!(strip_local_suffix("MyPhone.local."), "MyPhone");
        assert_eq!(strip_local_suffix("notlocal.com"), "");
        assert_eq!(strip_local_suffix(""), "");
    }
}
