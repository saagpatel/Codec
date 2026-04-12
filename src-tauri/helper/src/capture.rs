use log::{error, info, warn};
use pcap::{Capture, Device};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Raw packet data from the capture thread.
#[derive(Debug, Clone)]
pub struct RawPacket {
    #[allow(dead_code)] // Used in Phase 1 for flow timestamps
    pub timestamp_us: i64,
    pub data: Vec<u8>,
}

/// Error type for capture operations.
#[derive(Debug)]
pub enum CaptureError {
    NoDevice(String),
    OpenFailed(String),
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::NoDevice(msg) => write!(f, "No capture device: {}", msg),
            CaptureError::OpenFailed(msg) => write!(f, "Failed to open capture: {}", msg),
        }
    }
}

impl std::error::Error for CaptureError {}

/// Start the packet capture on a dedicated OS thread.
///
/// Uses a real OS thread (not tokio) because macOS has issues with async
/// BPF file descriptors. Packets are bridged to the async runtime via mpsc.
pub fn start_capture(tx: mpsc::Sender<RawPacket>) -> Result<String, CaptureError> {
    let device = Device::lookup()
        .map_err(|e| CaptureError::NoDevice(e.to_string()))?
        .ok_or_else(|| CaptureError::NoDevice("No default device found".to_string()))?;

    let device_name = device.name.clone();
    info!("Opening capture on interface: {}", device_name);

    let mut cap = Capture::from_device(device)
        .map_err(|e| CaptureError::OpenFailed(e.to_string()))?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000) // Critical for macOS — zero timeout hangs
        .open()
        .map_err(|e| CaptureError::OpenFailed(e.to_string()))?;

    // Only capture IP traffic (skip ARP, etc. at the BPF level).
    // Abort if the filter cannot be set — falling back to unfiltered capture
    // would expose all local traffic to the helper process.
    cap.filter("ip or ip6", true)
        .map_err(|e| CaptureError::OpenFailed(format!("Failed to set BPF filter: {}", e)))?;

    let name = device_name.clone();
    std::thread::Builder::new()
        .name("pcap-capture".to_string())
        .spawn(move || {
            capture_loop(&mut cap, &tx);
        })
        .map_err(|e| CaptureError::OpenFailed(format!("Failed to spawn capture thread: {}", e)))?;

    Ok(name)
}

fn capture_loop(cap: &mut Capture<pcap::Active>, tx: &mpsc::Sender<RawPacket>) {
    info!("Capture loop started");
    let mut consecutive_errors = 0u32;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                consecutive_errors = 0;
                let timestamp_us = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as i64;

                let raw = RawPacket {
                    timestamp_us,
                    data: packet.data.to_vec(),
                };

                // blocking_send bridges the OS thread → tokio runtime
                if tx.blocking_send(raw).is_err() {
                    info!("Packet channel closed, stopping capture");
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Normal on macOS when no packets arrive within timeout
                continue;
            }
            Err(e) => {
                consecutive_errors += 1;
                if consecutive_errors > 100 {
                    error!("Too many consecutive capture errors, stopping: {}", e);
                    break;
                }
                warn!("Capture error: {}", e);
            }
        }
    }

    info!("Capture loop ended");
}
