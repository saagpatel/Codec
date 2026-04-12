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

/// Messages sent from the main app to the helper (control commands).
/// Every message must include the IPC auth token generated at connection time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)] // Used in Phase 1 for ARP spoof toggle
pub enum ControlMessage {
    SetArpSpoof { token: String, enabled: bool },
    Shutdown { token: String },
}
