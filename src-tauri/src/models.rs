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

/// Topology node returned by get_topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    pub node_type: String, // "device" | "service" | "router"
    pub icon: String,
    pub total_bytes: u64,
}

/// Topology edge returned by get_topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub source: String,
    pub target: String,
    pub protocol: String,
    pub bytes: u64,
    pub active: bool,
}

/// Per-device statistics returned by get_device_stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStats {
    pub device_id: i64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub flow_count: u64,
    pub protocol_breakdown: Vec<ProtocolShare>,
    pub first_seen: String,
    pub last_seen: String,
}

/// Protocol percentage in a device's traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolShare {
    pub protocol: String,
    pub bytes: u64,
    pub percentage: f64,
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
