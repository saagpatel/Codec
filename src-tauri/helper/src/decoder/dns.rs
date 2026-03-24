use log::debug;
use simple_dns::rdata::RData;
use simple_dns::Packet as DnsPacket;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// Result of parsing a DNS packet.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in tests and later phases
pub struct DnsResult {
    /// Query names (from the question section).
    pub queries: Vec<String>,
    /// Resolved IP → hostname mappings (from A/AAAA answer records).
    pub answers: Vec<(IpAddr, String)>,
}

/// Thread-safe DNS resolution cache mapping IP addresses to hostnames.
#[derive(Debug, Clone)]
pub struct DnsCache {
    inner: Arc<RwLock<HashMap<IpAddr, CacheEntry>>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    hostname: String,
    inserted_at: Instant,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn insert(&self, ip: IpAddr, hostname: String) {
        if let Ok(mut cache) = self.inner.write() {
            cache.insert(
                ip,
                CacheEntry {
                    hostname,
                    inserted_at: Instant::now(),
                },
            );
        }
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        if let Ok(cache) = self.inner.read() {
            cache
                .get(ip)
                .filter(|entry| entry.inserted_at.elapsed() < CACHE_TTL)
                .map(|entry| entry.hostname.clone())
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.inner.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Remove entries older than the TTL.
    #[allow(dead_code)] // Called periodically in later phases
    pub fn cleanup(&self) {
        if let Ok(mut cache) = self.inner.write() {
            cache.retain(|_, entry| entry.inserted_at.elapsed() < CACHE_TTL);
        }
    }
}

/// Decode a DNS packet payload and return query/answer information.
pub fn decode_dns(payload: &[u8]) -> Option<DnsResult> {
    let packet = DnsPacket::parse(payload).ok()?;

    let queries: Vec<String> = packet
        .questions
        .iter()
        .map(|q| q.qname.to_string().trim_end_matches('.').to_string())
        .collect();

    let mut answers: Vec<(IpAddr, String)> = Vec::new();

    // Get the primary query name for mapping answers
    let query_name = queries.first().cloned().unwrap_or_default();

    for answer in &packet.answers {
        let name = answer.name.to_string().trim_end_matches('.').to_string();
        let hostname = if name == query_name || query_name.is_empty() {
            name.clone()
        } else {
            // CNAME chain — use the original query name
            query_name.clone()
        };

        match &answer.rdata {
            RData::A(a) => {
                let ip = IpAddr::V4(a.address.into());
                answers.push((ip, hostname));
            }
            RData::AAAA(aaaa) => {
                let ip = IpAddr::V6(aaaa.address.into());
                answers.push((ip, hostname));
            }
            _ => {}
        }
    }

    if queries.is_empty() && answers.is_empty() {
        return None;
    }

    Some(DnsResult { queries, answers })
}

/// Process a DNS packet: decode and populate the cache.
pub fn process_dns(payload: &[u8], cache: &DnsCache) {
    if let Some(result) = decode_dns(payload) {
        for (ip, hostname) in &result.answers {
            debug!("dns_cache: {} → {}", ip, hostname);
            cache.insert(*ip, hostname.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal DNS response for "example.com" → 93.184.216.34
    // Built manually: header (12 bytes) + question + answer
    fn build_dns_a_response() -> Vec<u8> {
        let mut pkt = Vec::new();

        // Header
        pkt.extend_from_slice(&[0x00, 0x01]); // Transaction ID
        pkt.extend_from_slice(&[0x81, 0x80]); // Flags: response, no error
        pkt.extend_from_slice(&[0x00, 0x01]); // Questions: 1
        pkt.extend_from_slice(&[0x00, 0x01]); // Answers: 1
        pkt.extend_from_slice(&[0x00, 0x00]); // Authority: 0
        pkt.extend_from_slice(&[0x00, 0x00]); // Additional: 0

        // Question: example.com, type A, class IN
        pkt.push(7); // length of "example"
        pkt.extend_from_slice(b"example");
        pkt.push(3); // length of "com"
        pkt.extend_from_slice(b"com");
        pkt.push(0); // root label
        pkt.extend_from_slice(&[0x00, 0x01]); // type A
        pkt.extend_from_slice(&[0x00, 0x01]); // class IN

        // Answer: example.com → 93.184.216.34
        pkt.extend_from_slice(&[0xc0, 0x0c]); // name pointer to question
        pkt.extend_from_slice(&[0x00, 0x01]); // type A
        pkt.extend_from_slice(&[0x00, 0x01]); // class IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // TTL: 256
        pkt.extend_from_slice(&[0x00, 0x04]); // RDLENGTH: 4
        pkt.extend_from_slice(&[93, 184, 216, 34]); // RDATA: 93.184.216.34

        pkt
    }

    fn build_dns_aaaa_response() -> Vec<u8> {
        let mut pkt = Vec::new();

        // Header
        pkt.extend_from_slice(&[0x00, 0x02]); // Transaction ID
        pkt.extend_from_slice(&[0x81, 0x80]); // Flags: response
        pkt.extend_from_slice(&[0x00, 0x01]); // Questions: 1
        pkt.extend_from_slice(&[0x00, 0x01]); // Answers: 1
        pkt.extend_from_slice(&[0x00, 0x00]); // Authority: 0
        pkt.extend_from_slice(&[0x00, 0x00]); // Additional: 0

        // Question: example.com, type AAAA
        pkt.push(7);
        pkt.extend_from_slice(b"example");
        pkt.push(3);
        pkt.extend_from_slice(b"com");
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x1c]); // type AAAA
        pkt.extend_from_slice(&[0x00, 0x01]); // class IN

        // Answer: example.com → 2606:2800:220:1:248:1893:25c8:1946
        pkt.extend_from_slice(&[0xc0, 0x0c]); // name pointer
        pkt.extend_from_slice(&[0x00, 0x1c]); // type AAAA
        pkt.extend_from_slice(&[0x00, 0x01]); // class IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // TTL
        pkt.extend_from_slice(&[0x00, 0x10]); // RDLENGTH: 16
        pkt.extend_from_slice(&[
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8,
            0x19, 0x46,
        ]);

        pkt
    }

    #[test]
    fn decode_dns_a_record() {
        let data = build_dns_a_response();
        let result = decode_dns(&data).expect("should parse");

        assert_eq!(result.queries.len(), 1);
        assert_eq!(result.queries[0], "example.com");
        assert_eq!(result.answers.len(), 1);

        let (ip, hostname) = &result.answers[0];
        assert_eq!(hostname, "example.com");
        assert_eq!(*ip, "93.184.216.34".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn decode_dns_aaaa_record() {
        let data = build_dns_aaaa_response();
        let result = decode_dns(&data).expect("should parse");

        assert_eq!(result.queries[0], "example.com");
        assert_eq!(result.answers.len(), 1);

        let (ip, hostname) = &result.answers[0];
        assert_eq!(hostname, "example.com");
        assert!(ip.is_ipv6());
    }

    #[test]
    fn decode_malformed_returns_none() {
        assert!(decode_dns(&[]).is_none());
        assert!(decode_dns(&[0x00]).is_none());
        assert!(decode_dns(&[0xff; 20]).is_none());
    }

    #[test]
    fn dns_cache_insert_and_lookup() {
        let cache = DnsCache::new();
        let ip: IpAddr = "93.184.216.34".parse().unwrap();

        assert!(cache.lookup(&ip).is_none());

        cache.insert(ip, "example.com".to_string());
        assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn dns_cache_overwrite() {
        let cache = DnsCache::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        cache.insert(ip, "old.com".to_string());
        cache.insert(ip, "new.com".to_string());
        assert_eq!(cache.lookup(&ip), Some("new.com".to_string()));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn process_dns_populates_cache() {
        let cache = DnsCache::new();
        let data = build_dns_a_response();

        process_dns(&data, &cache);

        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));
    }
}
