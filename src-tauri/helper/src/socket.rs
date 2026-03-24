use crate::models::{ControlMessage, HelperMessage};
use log::{error, info, warn};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

const SOCKET_PATH: &str = "/tmp/codec-helper.sock";

/// Channel for outbound messages (helper → client).
pub type MessageSender = mpsc::Sender<HelperMessage>;
pub type MessageReceiver = mpsc::Receiver<HelperMessage>;

/// Start the Unix socket server.
///
/// Returns a sender for pushing messages to connected clients.
/// Inbound ControlMessages are forwarded to `control_tx`.
pub async fn start_server(control_tx: mpsc::Sender<ControlMessage>) -> MessageSender {
    // Remove stale socket file from previous runs
    let _ = std::fs::remove_file(SOCKET_PATH);

    let listener = UnixListener::bind(SOCKET_PATH).expect("Failed to bind Unix socket");
    info!("Socket server listening at {}", SOCKET_PATH);

    // Set socket permissions (readable/writable by owner only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(SOCKET_PATH, perms).ok();
    }

    let (tx, rx) = mpsc::channel::<HelperMessage>(256);

    tokio::spawn(accept_loop(listener, rx, control_tx));

    tx
}

async fn accept_loop(
    listener: UnixListener,
    mut rx: MessageReceiver,
    control_tx: mpsc::Sender<ControlMessage>,
) {
    loop {
        info!("Waiting for client connection...");
        match listener.accept().await {
            Ok((stream, _addr)) => {
                info!("Client connected");
                handle_client(stream, &mut rx, &control_tx).await;
                info!("Client disconnected");
            }
            Err(e) => {
                error!("Accept error: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}

async fn handle_client(
    stream: UnixStream,
    rx: &mut MessageReceiver,
    control_tx: &mpsc::Sender<ControlMessage>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let reader = BufReader::new(read_half);
    let mut lines = reader.lines();

    let control_tx = control_tx.clone();

    // Spawn reader task for incoming control messages
    let read_handle = tokio::spawn(async move {
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if line.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<ControlMessage>(&line) {
                        Ok(msg) => {
                            info!("Received control message: {:?}", msg);
                            if let Err(e) = control_tx.send(msg).await {
                                error!("Failed to forward control message: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Invalid control message: {} — {}",
                                e,
                                &line[..line.len().min(100)]
                            );
                        }
                    }
                }
                Ok(None) => {
                    info!("Client read stream closed");
                    break;
                }
                Err(e) => {
                    warn!("Read error: {}", e);
                    break;
                }
            }
        }
    });

    // Write messages to client
    loop {
        match rx.recv().await {
            Some(msg) => {
                match serde_json::to_string(&msg) {
                    Ok(json) => {
                        let line = format!("{}\n", json);
                        if let Err(e) = write_half.write_all(line.as_bytes()).await {
                            warn!("Write error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Serialization error: {}", e);
                    }
                }
            }
            None => {
                info!("Message channel closed");
                break;
            }
        }
    }

    read_handle.abort();
}

/// Generate a heartbeat message with the current timestamp.
pub fn heartbeat() -> HelperMessage {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    HelperMessage::Heartbeat { timestamp }
}
