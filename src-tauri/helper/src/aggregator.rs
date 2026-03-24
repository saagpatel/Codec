use crate::decoder::dns::DnsCache;
use crate::models::{CaptureStats, DeviceEntry, DeviceHint, FlowBatch, FlowEntry};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Thread-safe SNI cache: maps (dst_ip, dst_port) → hostname.
pub type SniCache = HashMap<(IpAddr, u16), String>;

/// In-memory flow table that aggregates packets into flows.
pub struct FlowTable {
    flows: HashMap<String, FlowEntry>,
    modified_keys: HashSet<String>,
    new_keys: HashSet<String>,
    packet_count: u64,
    last_flush: Instant,
    local_ips: HashSet<IpAddr>,
    ip_to_mac: HashMap<IpAddr, [u8; 6]>,
    device_hints: HashMap<[u8; 6], DeviceHint>,
    dirty_macs: HashSet<[u8; 6]>,
}

impl FlowTable {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            modified_keys: HashSet::new(),
            new_keys: HashSet::new(),
            packet_count: 0,
            last_flush: Instant::now(),
            local_ips: HashSet::new(),
            ip_to_mac: HashMap::new(),
            device_hints: HashMap::new(),
            dirty_macs: HashSet::new(),
        }
    }

    /// Record a parsed packet into the flow table.
    #[allow(clippy::too_many_arguments)]
    pub fn record_packet(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
        total_len: u32,
        dns_cache: &DnsCache,
        sni_cache: &SniCache,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
    ) {
        let (flow_key, is_canonical) = normalize_flow_key(
            &src_ip.to_string(),
            src_port,
            &dst_ip.to_string(),
            dst_port,
            protocol,
        );

        // Track local IPs and their MAC addresses for device identification
        let zero_mac = [0u8; 6];
        if is_local_ip(&src_ip) {
            self.local_ips.insert(src_ip);
            if src_mac != zero_mac {
                self.ip_to_mac.insert(src_ip, src_mac);
                self.dirty_macs.insert(src_mac);
            }
        }
        if is_local_ip(&dst_ip) {
            self.local_ips.insert(dst_ip);
            if dst_mac != zero_mac {
                self.ip_to_mac.insert(dst_ip, dst_mac);
                self.dirty_macs.insert(dst_mac);
            }
        }

        // Resolve service name from SNI or DNS caches
        let service_name = sni_cache
            .get(&(dst_ip, dst_port))
            .cloned()
            .or_else(|| dns_cache.lookup(&dst_ip))
            .or_else(|| sni_cache.get(&(src_ip, src_port)).cloned())
            .or_else(|| dns_cache.lookup(&src_ip));

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        self.packet_count += 1;

        if let Some(flow) = self.flows.get_mut(&flow_key) {
            // Update existing flow
            if is_canonical {
                flow.bytes_sent += total_len as u64;
            } else {
                flow.bytes_received += total_len as u64;
            }
            flow.packet_count += 1;
            flow.last_seen = now_ms;
            if service_name.is_some() && flow.service_name.is_none() {
                flow.service_name = service_name;
            }
            self.modified_keys.insert(flow_key);
        } else {
            // New flow
            let (canonical_src, canonical_dst, canonical_sp, canonical_dp) = if is_canonical {
                (src_ip.to_string(), dst_ip.to_string(), src_port, dst_port)
            } else {
                (dst_ip.to_string(), src_ip.to_string(), dst_port, src_port)
            };

            let (bytes_sent, bytes_received) = if is_canonical {
                (total_len as u64, 0u64)
            } else {
                (0u64, total_len as u64)
            };

            let flow = FlowEntry {
                flow_key: flow_key.clone(),
                src_ip: canonical_src,
                dst_ip: canonical_dst,
                src_port: Some(canonical_sp),
                dst_port: Some(canonical_dp),
                protocol: protocol.to_string(),
                service_name,
                bytes_sent,
                bytes_received,
                packet_count: 1,
                first_seen: now_ms,
                last_seen: now_ms,
                summary_text: String::new(), // Filled on flush
            };

            self.flows.insert(flow_key.clone(), flow);
            self.new_keys.insert(flow_key.clone());
            self.modified_keys.insert(flow_key);
        }
    }

    /// Record a device identification hint from mDNS/DHCP.
    pub fn record_device_hint(&mut self, mac: [u8; 6], hint: DeviceHint) {
        let entry = self.device_hints.entry(mac).or_default();
        if hint.hostname.is_some() {
            entry.hostname = hint.hostname;
        }
        if hint.device_type.is_some() {
            entry.device_type = hint.device_type;
        }
        self.dirty_macs.insert(mac);
    }

    /// Flush the flow table, producing a delta batch.
    pub fn flush(&mut self) -> FlowBatch {
        let elapsed = self.last_flush.elapsed();
        let pps = if elapsed.as_secs_f64() > 0.0 {
            self.packet_count as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        let mut new_flows = Vec::new();
        let mut updated_flows = Vec::new();

        for key in &self.modified_keys {
            if let Some(flow) = self.flows.get_mut(key) {
                // Generate summary text
                flow.summary_text = generate_summary(flow);

                if self.new_keys.contains(key) {
                    new_flows.push(flow.clone());
                } else {
                    updated_flows.push(flow.clone());
                }
            }
        }

        let stats = CaptureStats {
            packets_per_second: pps,
            active_flows: self.flows.len(),
            total_devices: self.local_ips.len(),
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // Build device updates from dirty MACs
        let mut device_updates = Vec::new();
        for mac in &self.dirty_macs {
            let mac_str = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );

            let ip = self
                .ip_to_mac
                .iter()
                .find(|(_, m)| *m == mac)
                .map(|(ip, _)| ip.to_string());

            let hints = self.device_hints.get(mac);

            device_updates.push(DeviceEntry {
                mac_address: mac_str,
                ip_address: ip,
                hostname: hints.and_then(|h| h.hostname.clone()),
                oui_manufacturer: None, // Enriched by Tauri main process
                device_type: hints
                    .and_then(|h| h.device_type.clone())
                    .unwrap_or_else(|| "Unknown".to_string()),
                display_name: None,
                icon: "device".to_string(),
                is_visible: true,
            });
        }

        // Reset tracking state
        self.modified_keys.clear();
        self.new_keys.clear();
        self.dirty_macs.clear();
        self.packet_count = 0;
        self.last_flush = Instant::now();

        FlowBatch {
            timestamp,
            new_flows,
            updated_flows,
            device_updates,
            stats,
        }
    }

    #[cfg(test)]
    pub fn active_flow_count(&self) -> usize {
        self.flows.len()
    }
}

/// Normalize a flow key so the lexicographically lower ip:port is always first.
/// Returns (normalized_key, is_canonical) where is_canonical=true means src was the lower side.
pub fn normalize_flow_key(
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    proto: &str,
) -> (String, bool) {
    let src = format!("{}:{}", src_ip, src_port);
    let dst = format!("{}:{}", dst_ip, dst_port);

    if src <= dst {
        (format!("{}-{}-{}", src, dst, proto), true)
    } else {
        (format!("{}-{}-{}", dst, src, proto), false)
    }
}

fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local
        }
    }
}

fn generate_summary(flow: &FlowEntry) -> String {
    let target = flow.service_name.as_deref().unwrap_or(&flow.dst_ip);

    let total_bytes = flow.bytes_sent + flow.bytes_received;
    let bytes_str = format_bytes(total_bytes);

    format!("{}: {}, {}", target, flow.protocol, bytes_str)
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_flow_key_canonical_order() {
        let (key, canonical) = normalize_flow_key("10.0.0.1", 80, "192.168.1.10", 52000, "TCP");
        assert_eq!(key, "10.0.0.1:80-192.168.1.10:52000-TCP");
        assert!(canonical); // "10.0.0.1:80" < "192.168.1.10:52000"
    }

    #[test]
    fn normalize_flow_key_reversed() {
        let (key, canonical) = normalize_flow_key("192.168.1.10", 52000, "10.0.0.1", 80, "TCP");
        assert_eq!(key, "10.0.0.1:80-192.168.1.10:52000-TCP");
        assert!(!canonical); // reversed
    }

    #[test]
    fn normalize_flow_key_same_both_directions() {
        let (key1, _) = normalize_flow_key("10.0.0.1", 80, "192.168.1.10", 52000, "TCP");
        let (key2, _) = normalize_flow_key("192.168.1.10", 52000, "10.0.0.1", 80, "TCP");
        assert_eq!(key1, key2);
    }

    #[test]
    fn bidirectional_traffic_merges() {
        let dns_cache = DnsCache::new();
        let sni_cache = SniCache::new();
        let mut table = FlowTable::new();

        // Packet from A to B
        table.record_packet(
            "192.168.1.10".parse().unwrap(),
            "93.184.216.34".parse().unwrap(),
            52000,
            443,
            "TCP",
            100,
            &dns_cache,
            &sni_cache,
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        );

        // Packet from B to A (same flow, reverse direction)
        table.record_packet(
            "93.184.216.34".parse().unwrap(),
            "192.168.1.10".parse().unwrap(),
            443,
            52000,
            "TCP",
            200,
            &dns_cache,
            &sni_cache,
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        );

        assert_eq!(table.active_flow_count(), 1);

        let batch = table.flush();
        assert_eq!(batch.new_flows.len(), 1);
        assert_eq!(batch.updated_flows.len(), 0);

        let flow = &batch.new_flows[0];
        assert!(flow.bytes_sent > 0);
        assert!(flow.bytes_received > 0);
        assert_eq!(flow.packet_count, 2);
    }

    #[test]
    fn flush_partitions_new_and_updated() {
        let dns_cache = DnsCache::new();
        let sni_cache = SniCache::new();
        let mut table = FlowTable::new();

        // First packet creates a new flow
        table.record_packet(
            "192.168.1.10".parse().unwrap(),
            "93.184.216.34".parse().unwrap(),
            52000,
            443,
            "TCP",
            100,
            &dns_cache,
            &sni_cache,
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        );

        let batch1 = table.flush();
        assert_eq!(batch1.new_flows.len(), 1);
        assert_eq!(batch1.updated_flows.len(), 0);

        // Second packet updates the existing flow
        table.record_packet(
            "192.168.1.10".parse().unwrap(),
            "93.184.216.34".parse().unwrap(),
            52000,
            443,
            "TCP",
            150,
            &dns_cache,
            &sni_cache,
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        );

        let batch2 = table.flush();
        assert_eq!(batch2.new_flows.len(), 0);
        assert_eq!(batch2.updated_flows.len(), 1);
    }

    #[test]
    fn flush_clears_tracking_state() {
        let dns_cache = DnsCache::new();
        let sni_cache = SniCache::new();
        let mut table = FlowTable::new();

        table.record_packet(
            "192.168.1.10".parse().unwrap(),
            "93.184.216.34".parse().unwrap(),
            52000,
            443,
            "TCP",
            100,
            &dns_cache,
            &sni_cache,
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        );

        table.flush();

        // No new packets — flush should return empty
        let batch = table.flush();
        assert_eq!(batch.new_flows.len(), 0);
        assert_eq!(batch.updated_flows.len(), 0);
    }

    #[test]
    fn service_name_from_dns_cache() {
        let dns_cache = DnsCache::new();
        dns_cache.insert("93.184.216.34".parse().unwrap(), "example.com".to_string());
        let sni_cache = SniCache::new();
        let mut table = FlowTable::new();

        table.record_packet(
            "192.168.1.10".parse().unwrap(),
            "93.184.216.34".parse().unwrap(),
            52000,
            443,
            "TCP",
            100,
            &dns_cache,
            &sni_cache,
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        );

        let batch = table.flush();
        assert_eq!(
            batch.new_flows[0].service_name.as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn service_name_from_sni_cache() {
        let dns_cache = DnsCache::new();
        let mut sni_cache = SniCache::new();
        sni_cache.insert(
            ("93.184.216.34".parse().unwrap(), 443),
            "example.com".to_string(),
        );
        let mut table = FlowTable::new();

        table.record_packet(
            "192.168.1.10".parse().unwrap(),
            "93.184.216.34".parse().unwrap(),
            52000,
            443,
            "TCP",
            100,
            &dns_cache,
            &sni_cache,
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        );

        let batch = table.flush();
        assert_eq!(
            batch.new_flows[0].service_name.as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn format_bytes_human_readable() {
        assert_eq!(format_bytes(0), "0B");
        assert_eq!(format_bytes(512), "512B");
        assert_eq!(format_bytes(1024), "1.0KB");
        assert_eq!(format_bytes(1536), "1.5KB");
        assert_eq!(format_bytes(1048576), "1.0MB");
        assert_eq!(format_bytes(1073741824), "1.0GB");
    }

    #[test]
    fn stats_track_pps_and_counts() {
        let dns_cache = DnsCache::new();
        let sni_cache = SniCache::new();
        let mut table = FlowTable::new();

        for i in 0..10u16 {
            table.record_packet(
                "192.168.1.10".parse().unwrap(),
                "93.184.216.34".parse().unwrap(),
                50000 + i,
                443,
                "TCP",
                100,
                &dns_cache,
                &sni_cache,
                [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
                [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            );
        }

        let batch = table.flush();
        assert!(batch.stats.packets_per_second > 0.0);
        assert_eq!(batch.stats.active_flows, 10);
        assert!(batch.stats.total_devices >= 1); // at least the local IP
    }

    #[test]
    fn summary_text_generated_on_flush() {
        let dns_cache = DnsCache::new();
        dns_cache.insert("93.184.216.34".parse().unwrap(), "example.com".to_string());
        let sni_cache = SniCache::new();
        let mut table = FlowTable::new();

        table.record_packet(
            "192.168.1.10".parse().unwrap(),
            "93.184.216.34".parse().unwrap(),
            52000,
            443,
            "TCP",
            2048,
            &dns_cache,
            &sni_cache,
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        );

        let batch = table.flush();
        let summary = &batch.new_flows[0].summary_text;
        assert!(summary.contains("example.com"));
        assert!(summary.contains("TCP"));
    }
}
