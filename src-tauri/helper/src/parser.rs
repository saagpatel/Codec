use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;
use std::net::IpAddr;

/// Parsed packet metadata — no payload content stored.
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
    #[allow(dead_code)] // Used in Phase 1 for bandwidth display
    pub payload_len: usize,
    pub total_len: u32,
    pub payload: Vec<u8>,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

impl TransportProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportProtocol::Tcp => "TCP",
            TransportProtocol::Udp => "UDP",
        }
    }
}

/// Parse raw Ethernet frame into structured packet metadata.
pub fn parse_packet(data: &[u8]) -> Option<ParsedPacket> {
    let ethernet = EthernetPacket::new(data)?;

    let mut src_mac = [0u8; 6];
    let mut dst_mac = [0u8; 6];
    src_mac.copy_from_slice(&ethernet.get_source().octets());
    dst_mac.copy_from_slice(&ethernet.get_destination().octets());

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => parse_ipv4(ethernet.payload(), src_mac, dst_mac),
        EtherTypes::Ipv6 => parse_ipv6(ethernet.payload(), src_mac, dst_mac),
        _ => None,
    }
}

fn parse_ipv4(data: &[u8], src_mac: [u8; 6], dst_mac: [u8; 6]) -> Option<ParsedPacket> {
    let ipv4 = Ipv4Packet::new(data)?;
    let src_ip = IpAddr::V4(ipv4.get_source());
    let dst_ip = IpAddr::V4(ipv4.get_destination());
    let total_len = ipv4.get_total_length() as u32;

    parse_transport(
        ipv4.get_next_level_protocol(),
        ipv4.payload(),
        src_ip,
        dst_ip,
        total_len,
        src_mac,
        dst_mac,
    )
}

fn parse_ipv6(data: &[u8], src_mac: [u8; 6], dst_mac: [u8; 6]) -> Option<ParsedPacket> {
    let ipv6 = Ipv6Packet::new(data)?;
    let src_ip = IpAddr::V6(ipv6.get_source());
    let dst_ip = IpAddr::V6(ipv6.get_destination());
    let total_len = (ipv6.get_payload_length() as u32) + 40; // IPv6 header is 40 bytes

    parse_transport(
        ipv6.get_next_header(),
        ipv6.payload(),
        src_ip,
        dst_ip,
        total_len,
        src_mac,
        dst_mac,
    )
}

fn parse_transport(
    next_proto: pnet_packet::ip::IpNextHeaderProtocol,
    transport_data: &[u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    total_len: u32,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
) -> Option<ParsedPacket> {
    match next_proto {
        IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(transport_data)?;
            Some(ParsedPacket {
                src_ip,
                dst_ip,
                src_port: tcp.get_source(),
                dst_port: tcp.get_destination(),
                protocol: TransportProtocol::Tcp,
                payload_len: tcp.payload().len(),
                total_len,
                payload: tcp.payload().to_vec(),
                src_mac,
                dst_mac,
            })
        }
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(transport_data)?;
            Some(ParsedPacket {
                src_ip,
                dst_ip,
                src_port: udp.get_source(),
                dst_port: udp.get_destination(),
                protocol: TransportProtocol::Udp,
                payload_len: udp.payload().len(),
                total_len,
                payload: udp.payload().to_vec(),
                src_mac,
                dst_mac,
            })
        }
        _ => None, // Skip ICMP, IGMP, etc.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_protocol_as_str() {
        assert_eq!(TransportProtocol::Tcp.as_str(), "TCP");
        assert_eq!(TransportProtocol::Udp.as_str(), "UDP");
    }

    #[test]
    fn parse_too_short_returns_none() {
        assert!(parse_packet(&[]).is_none());
        assert!(parse_packet(&[0u8; 10]).is_none());
    }

    #[test]
    fn parse_non_ip_returns_none() {
        // Valid Ethernet header but ARP ethertype (0x0806)
        let mut frame = vec![0u8; 60];
        // Destination MAC
        frame[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // Source MAC
        frame[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // EtherType: ARP
        frame[12] = 0x08;
        frame[13] = 0x06;
        assert!(parse_packet(&frame).is_none());
    }

    // Build a minimal valid IPv4/TCP Ethernet frame for testing
    fn build_ipv4_tcp_frame(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = Vec::new();

        // Ethernet header (14 bytes)
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // dst MAC
        frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src MAC
        frame.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes, no options)
        frame.push(0x45); // version + IHL
        frame.push(0x00); // DSCP/ECN
        let total_len: u16 = 40; // 20 IP + 20 TCP
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00]); // identification
        frame.extend_from_slice(&[0x40, 0x00]); // flags + fragment offset
        frame.push(64); // TTL
        frame.push(6); // protocol: TCP
        frame.extend_from_slice(&[0x00, 0x00]); // checksum (skip)
        frame.extend_from_slice(&[192, 168, 1, 10]); // src IP
        frame.extend_from_slice(&[93, 184, 216, 34]); // dst IP

        // TCP header (20 bytes, no options)
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // seq
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
        frame.push(0x50); // data offset (5 * 4 = 20)
        frame.push(0x02); // flags: SYN
        frame.extend_from_slice(&[0xff, 0xff]); // window
        frame.extend_from_slice(&[0x00, 0x00]); // checksum
        frame.extend_from_slice(&[0x00, 0x00]); // urgent

        frame
    }

    #[test]
    fn parse_ipv4_tcp_packet() {
        let frame = build_ipv4_tcp_frame(52000, 443);
        let parsed = parse_packet(&frame).expect("should parse");

        assert_eq!(parsed.src_ip, "192.168.1.10".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst_ip, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.src_port, 52000);
        assert_eq!(parsed.dst_port, 443);
        assert_eq!(parsed.protocol, TransportProtocol::Tcp);
        assert_eq!(parsed.total_len, 40);
        assert_eq!(parsed.src_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(parsed.dst_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }
}
