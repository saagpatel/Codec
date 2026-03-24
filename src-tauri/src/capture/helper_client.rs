use crate::capture::device_registry;
use crate::models::{ControlMessage, FlowBatch, HelperMessage};
use crate::{DbPool, OuiDb};
use log::{error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

const SOCKET_PATH: &str = "/tmp/codec-helper.sock";
const MAX_RETRIES: u32 = 3;
const BASE_RETRY_DELAY: Duration = Duration::from_secs(2);

/// Shared sender for pushing ControlMessages to the helper.
/// Held as None when the helper is disconnected.
pub type ControlSender = Arc<Mutex<Option<tokio::sync::mpsc::Sender<ControlMessage>>>>;

pub fn start(app_handle: AppHandle, db: DbPool, oui_db: OuiDb, control: ControlSender) {
    tokio::spawn(async move {
        run_client(app_handle, db, oui_db, control).await;
    });
}

async fn run_client(app_handle: AppHandle, db: DbPool, oui_db: OuiDb, control: ControlSender) {
    let mut retry_count: u32 = 0;

    loop {
        match UnixStream::connect(SOCKET_PATH).await {
            Ok(stream) => {
                info!("Connected to helper at {}", SOCKET_PATH);
                retry_count = 0;

                // Split stream so we can read and write simultaneously
                let (read_half, write_half) = stream.into_split();

                // Create a per-connection channel for outbound control messages
                let (cmd_tx, cmd_rx) =
                    tokio::sync::mpsc::channel::<ControlMessage>(32);

                // Register the sender so commands can reach the helper
                {
                    let mut guard = control.lock().await;
                    *guard = Some(cmd_tx);
                }

                // Spawn write task
                let write_handle = tokio::spawn(write_loop(write_half, cmd_rx));

                // Read loop (blocks until connection drops)
                if let Err(e) = read_loop(&app_handle, read_half, &db, &oui_db).await {
                    warn!("Helper connection lost: {}", e);
                }

                // Connection dropped — clear the sender and clean up
                write_handle.abort();
                {
                    let mut guard = control.lock().await;
                    *guard = None;
                }
            }
            Err(e) => {
                if retry_count < MAX_RETRIES {
                    retry_count += 1;
                    let delay = BASE_RETRY_DELAY * 2u32.saturating_pow(retry_count - 1);
                    warn!(
                        "Cannot connect to helper (attempt {}/{}): {}. Retrying in {:?}",
                        retry_count, MAX_RETRIES, e, delay
                    );
                    tokio::time::sleep(delay).await;
                } else {
                    info!(
                        "Helper not available after {} attempts. Will retry in 30s.",
                        MAX_RETRIES
                    );
                    retry_count = 0;
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                continue;
            }
        }

        // Connection dropped — wait before reconnecting
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn write_loop(
    mut write_half: tokio::net::unix::OwnedWriteHalf,
    mut rx: tokio::sync::mpsc::Receiver<ControlMessage>,
) {
    while let Some(msg) = rx.recv().await {
        match serde_json::to_string(&msg) {
            Ok(json) => {
                let line = format!("{}\n", json);
                if let Err(e) = write_half.write_all(line.as_bytes()).await {
                    warn!("Control write error: {}", e);
                    break;
                }
            }
            Err(e) => {
                error!("Control message serialization failed: {}", e);
            }
        }
    }
}

async fn read_loop(
    app_handle: &AppHandle,
    read_half: tokio::net::unix::OwnedReadHalf,
    db: &DbPool,
    oui_db: &OuiDb,
) -> Result<(), Box<dyn std::error::Error>> {
    let reader = BufReader::new(read_half);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        if line.is_empty() {
            continue;
        }

        match serde_json::from_str::<HelperMessage>(&line) {
            Ok(HelperMessage::Heartbeat { timestamp }) => {
                log::debug!("Heartbeat from helper: {}", timestamp);
            }
            Ok(HelperMessage::FlowBatch { payload }) => {
                process_batch(app_handle, payload, db, oui_db).await;
            }
            Err(e) => {
                error!(
                    "Failed to parse helper message: {} — line: {}",
                    e,
                    &line[..line.len().min(200)]
                );
            }
        }
    }

    Err("Helper closed connection".into())
}

async fn process_batch(
    app_handle: &AppHandle,
    mut batch: FlowBatch,
    db: &DbPool,
    oui_db: &OuiDb,
) {
    // 1. Enrich device_updates with OUI manufacturer + device type inference
    for device in &mut batch.device_updates {
        device_registry::enrich_device(oui_db, device);
    }

    // 2. Persist to SQLite (blocking operation)
    let db_clone = db.clone();
    let devices_for_db = batch.device_updates.clone();
    let flows_for_db: Vec<_> = batch
        .new_flows
        .iter()
        .chain(batch.updated_flows.iter())
        .cloned()
        .collect();

    if let Err(e) = tokio::task::spawn_blocking(move || {
        let conn = db_clone.lock().map_err(|e| format!("DB lock failed: {}", e))?;

        // Upsert devices first (flows reference device IDs)
        for device in &devices_for_db {
            if let Err(e) = crate::db::queries::upsert_device(&conn, device) {
                log::warn!("Failed to upsert device {}: {}", device.mac_address, e);
            }
        }

        // Upsert flows
        for flow in &flows_for_db {
            if let Err(e) = crate::db::queries::upsert_flow(&conn, flow) {
                log::warn!("Failed to upsert flow {}: {}", flow.flow_key, e);
            }
        }

        Ok::<(), String>(())
    })
    .await
    {
        error!("Database persistence failed: {}", e);
    }

    // 3. Emit to frontend
    if let Err(e) = app_handle.emit("flow-update", &batch) {
        error!("Failed to emit flow-update event: {}", e);
    }
}
