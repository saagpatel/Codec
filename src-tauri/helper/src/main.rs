mod aggregator;
mod arp_spoof;
mod capture;
mod decoder;
mod models;
mod parser;
mod socket;

use aggregator::{FlowTable, SniCache};
use decoder::dns::DnsCache;
use log::{error, info};
use models::{ControlMessage, HelperMessage};
use parser::TransportProtocol;
use std::sync::Mutex;
use std::time::Duration;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("codec-helper starting");

    // Control message channel: socket → ARP engine
    let (control_tx, mut control_rx) = tokio::sync::mpsc::channel::<ControlMessage>(32);

    // Start socket server — returns a sender for pushing messages to clients
    let tx = socket::start_server(control_tx).await;

    // Shared state
    let dns_cache = DnsCache::new();
    let sni_cache = std::sync::Arc::new(Mutex::new(SniCache::new()));
    let flow_table = std::sync::Arc::new(Mutex::new(FlowTable::new()));

    // Start packet capture on a dedicated OS thread
    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel(10_000);
    let interface_name = match capture::start_capture(packet_tx) {
        Ok(name) => {
            info!("Capturing on interface: {}", name);
            name
        }
        Err(e) => {
            error!("Failed to start capture: {}. Falling back to heartbeat mode.", e);
            // No ARP spoofing available in heartbeat mode
            drop(control_rx);
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            loop {
                interval.tick().await;
                let msg = socket::heartbeat();
                if tx.send(msg).await.is_err() {
                    break;
                }
            }
            return;
        }
    };

    // ARP spoof control task: routes ControlMessages to the ARP engine
    let mut arp_engine = arp_spoof::ArpSpoofEngine::new(&interface_name);
    tokio::spawn(async move {
        while let Some(msg) = control_rx.recv().await {
            match msg {
                ControlMessage::SetArpSpoof { enabled } => {
                    if enabled {
                        arp_engine.start();
                    } else {
                        arp_engine.stop();
                    }
                }
                ControlMessage::Shutdown => {
                    info!("Shutdown command received");
                    break;
                }
            }
        }
    });

    // Packet processing task
    let dns_cache_clone = dns_cache.clone();
    let sni_cache_clone = sni_cache.clone();
    let flow_table_clone = flow_table.clone();
    tokio::spawn(async move {
        while let Some(raw) = packet_rx.recv().await {
            if let Some(parsed) = parser::parse_packet(&raw.data) {
                // DNS decoding: UDP port 53
                if parsed.protocol == TransportProtocol::Udp
                    && (parsed.src_port == 53 || parsed.dst_port == 53)
                    && !parsed.payload.is_empty()
                {
                    decoder::dns::process_dns(&parsed.payload, &dns_cache_clone);
                }

                // TLS SNI extraction: TCP port 443
                if parsed.protocol == TransportProtocol::Tcp
                    && parsed.dst_port == 443
                    && !parsed.payload.is_empty()
                {
                    if let Some(sni) = decoder::tls::extract_sni(&parsed.payload) {
                        log::debug!("sni: {} → {}:{}", sni, parsed.dst_ip, parsed.dst_port);
                        if let Ok(mut cache) = sni_cache_clone.lock() {
                            cache.insert((parsed.dst_ip, parsed.dst_port), sni);
                        }
                    }
                }

                // mDNS decoding: UDP port 5353
                if parsed.protocol == TransportProtocol::Udp
                    && parsed.dst_port == 5353
                    && !parsed.payload.is_empty()
                {
                    if let Some(result) =
                        decoder::mdns::decode_mdns(&parsed.payload, parsed.src_ip)
                    {
                        let hint = models::DeviceHint {
                            hostname: result.hostname,
                            device_type: result.device_type_hint,
                        };
                        if let Ok(mut table) = flow_table_clone.lock() {
                            table.record_device_hint(parsed.src_mac, hint);
                        }
                    }
                }

                // DHCP decoding: UDP ports 67/68
                if parsed.protocol == TransportProtocol::Udp
                    && (parsed.src_port == 67
                        || parsed.src_port == 68
                        || parsed.dst_port == 67
                        || parsed.dst_port == 68)
                    && !parsed.payload.is_empty()
                {
                    if let Some(result) = decoder::dhcp::decode_dhcp(&parsed.payload) {
                        let hint = models::DeviceHint {
                            hostname: result.hostname,
                            device_type: None,
                        };
                        if let Ok(mut table) = flow_table_clone.lock() {
                            table.record_device_hint(result.client_mac, hint);
                        }
                    }
                }

                // Record into flow table
                if let Ok(sni) = sni_cache_clone.lock() {
                    if let Ok(mut table) = flow_table_clone.lock() {
                        table.record_packet(
                            parsed.src_ip,
                            parsed.dst_ip,
                            parsed.src_port,
                            parsed.dst_port,
                            parsed.protocol.as_str(),
                            parsed.total_len,
                            &dns_cache_clone,
                            &sni,
                            parsed.src_mac,
                            parsed.dst_mac,
                        );
                    }
                }
            }
        }
    });

    // Flush timer: every 2 seconds, produce a FlowBatch and send over socket
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    loop {
        interval.tick().await;

        let batch = if let Ok(mut table) = flow_table.lock() {
            table.flush()
        } else {
            continue;
        };

        let dns_size = dns_cache.len();
        let sni_size = sni_cache.lock().map(|c| c.len()).unwrap_or(0);
        log::debug!(
            "Flush: {} new, {} updated, {:.0} pps, {} flows, dns_cache size: {}, sni_cache size: {}",
            batch.new_flows.len(),
            batch.updated_flows.len(),
            batch.stats.packets_per_second,
            batch.stats.active_flows,
            dns_size,
            sni_size,
        );

        let msg = HelperMessage::FlowBatch { payload: batch };
        if tx.send(msg).await.is_err() {
            info!("Socket server shut down, exiting");
            break;
        }
    }
}
