use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEntry {
    pub flow_key: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub service_name: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packet_count: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub summary_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub mac_address: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub oui_manufacturer: Option<String>,
    pub device_type: String,
    pub display_name: Option<String>,
    pub icon: String,
    pub is_visible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStats {
    pub packets_per_second: f64,
    pub active_flows: usize,
    pub total_devices: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowBatch {
    pub timestamp: i64,
    pub new_flows: Vec<FlowEntry>,
    pub updated_flows: Vec<FlowEntry>,
    pub device_updates: Vec<DeviceEntry>,
    pub stats: CaptureStats,
}

/// Messages sent from the helper to the main app over the Unix socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HelperMessage {
    Heartbeat { timestamp: i64 },
    FlowBatch { payload: FlowBatch },
}

/// Device identification hint from mDNS/DHCP decoding (internal to helper).
#[derive(Debug, Clone, Default)]
pub struct DeviceHint {
    pub hostname: Option<String>,
    pub device_type: Option<String>,
}

/// Messages sent from the main app to the helper (control commands).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    SetArpSpoof { enabled: bool },
    Shutdown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_serialization_roundtrip() {
        let msg = HelperMessage::Heartbeat {
            timestamp: 1711234567,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: HelperMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            HelperMessage::Heartbeat { timestamp } => assert_eq!(timestamp, 1711234567),
            _ => panic!("expected Heartbeat"),
        }
    }

    #[test]
    fn flow_batch_serialization_roundtrip() {
        let batch = FlowBatch {
            timestamp: 1711234567,
            new_flows: vec![FlowEntry {
                flow_key: "192.168.1.10:443-10.0.0.1:52000-TCP".to_string(),
                src_ip: "192.168.1.10".to_string(),
                dst_ip: "10.0.0.1".to_string(),
                src_port: Some(443),
                dst_port: Some(52000),
                protocol: "TCP".to_string(),
                service_name: Some("github.com".to_string()),
                bytes_sent: 1024,
                bytes_received: 2048,
                packet_count: 10,
                first_seen: 1711234560,
                last_seen: 1711234567,
                summary_text: "github.com: TLS, 3.0KB".to_string(),
            }],
            updated_flows: vec![],
            device_updates: vec![],
            stats: CaptureStats {
                packets_per_second: 42.5,
                active_flows: 12,
                total_devices: 5,
            },
        };

        let msg = HelperMessage::FlowBatch { payload: batch };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: HelperMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            HelperMessage::FlowBatch { payload } => {
                assert_eq!(payload.new_flows.len(), 1);
                assert_eq!(
                    payload.new_flows[0].service_name.as_deref(),
                    Some("github.com")
                );
                assert_eq!(payload.stats.active_flows, 12);
            }
            _ => panic!("expected FlowBatch"),
        }
    }

    #[test]
    fn control_message_serialization() {
        let msg = ControlMessage::SetArpSpoof { enabled: true };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("set_arp_spoof"));
        assert!(json.contains("true"));

        let parsed: ControlMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ControlMessage::SetArpSpoof { enabled } => assert!(enabled),
            _ => panic!("expected SetArpSpoof"),
        }
    }
}
