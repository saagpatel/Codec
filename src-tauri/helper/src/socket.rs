use crate::models::{ControlMessage, HelperMessage};
use log::{error, info, warn};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

const SOCKET_PATH: &str = "/tmp/codec-helper.sock";
const TOKEN_PATH: &str = "/Library/Application Support/com.codec.app/ipc-token";

/// Channel for outbound messages (helper → client).
pub type MessageSender = mpsc::Sender<HelperMessage>;
pub type MessageReceiver = mpsc::Receiver<HelperMessage>;

/// Load the IPC auth token from disk.
/// The token is written by the Tauri app on first launch with 0o600 permissions.
fn load_ipc_token() -> Option<String> {
    match std::fs::read_to_string(TOKEN_PATH) {
        Ok(contents) => {
            let token = contents.trim().to_string();
            if token.len() == 64 {
                Some(token)
            } else {
                error!(
                    "IPC token at {} has unexpected length {} (want 64 hex chars); rejecting all connections",
                    TOKEN_PATH,
                    token.len()
                );
                None
            }
        }
        Err(e) => {
            error!(
                "Cannot read IPC token from {}: {}. All control messages will be rejected.",
                TOKEN_PATH, e
            );
            None
        }
    }
}

/// Extract the token string from a ControlMessage for validation.
fn token_of(msg: &ControlMessage) -> &str {
    match msg {
        ControlMessage::SetArpSpoof { token, .. } => token,
        ControlMessage::Shutdown { token } => token,
    }
}

/// Start the Unix socket server.
///
/// Returns a sender for pushing messages to connected clients.
/// Inbound ControlMessages are authenticated via the IPC token and forwarded to `control_tx`.
pub async fn start_server(control_tx: mpsc::Sender<ControlMessage>) -> MessageSender {
    // Load the IPC token once at startup — the helper refuses to forward messages
    // that do not carry the matching token.
    let expected_token = load_ipc_token();

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

    tokio::spawn(accept_loop(listener, rx, control_tx, expected_token));

    tx
}

async fn accept_loop(
    listener: UnixListener,
    mut rx: MessageReceiver,
    control_tx: mpsc::Sender<ControlMessage>,
    expected_token: Option<String>,
) {
    loop {
        info!("Waiting for client connection...");
        match listener.accept().await {
            Ok((stream, _addr)) => {
                info!("Client connected");
                handle_client(stream, &mut rx, &control_tx, expected_token.as_deref()).await;
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
    expected_token: Option<&str>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let reader = BufReader::new(read_half);
    let mut lines = reader.lines();

    let control_tx = control_tx.clone();
    // Clone to an owned String so the async block can own it.
    let expected_token: Option<String> = expected_token.map(str::to_string);

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
                            // Authenticate before forwarding
                            match &expected_token {
                                None => {
                                    warn!(
                                        "Rejected control message — IPC token not loaded (check {})",
                                        TOKEN_PATH
                                    );
                                    continue;
                                }
                                Some(want) => {
                                    if token_of(&msg) != want.as_str() {
                                        warn!("Rejected control message — invalid IPC token");
                                        continue;
                                    }
                                }
                            }
                            info!("Authenticated control message: {:?}", msg);
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
