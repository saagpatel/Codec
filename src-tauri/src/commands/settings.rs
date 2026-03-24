use crate::capture::helper_client::ControlSender;
use crate::models::ControlMessage;
use crate::DbPool;
use tauri::State;

#[tauri::command]
pub async fn get_settings(
    db: State<'_, DbPool>,
) -> Result<std::collections::HashMap<String, String>, String> {
    let db = db.inner().clone();
    tokio::task::spawn_blocking(move || {
        let conn = db.lock().map_err(|e| format!("DB lock failed: {e}"))?;
        crate::db::queries::get_settings(&conn)
            .map_err(|e| format!("Query failed: {e}"))
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

#[tauri::command]
pub async fn update_setting(
    key: String,
    value: String,
    db: State<'_, DbPool>,
    control: State<'_, ControlSender>,
) -> Result<(), String> {
    // Persist to DB
    let db = db.inner().clone();
    let key_for_db = key.clone();
    let value_for_db = value.clone();
    let db_result = tokio::task::spawn_blocking(move || {
        let conn = db.lock().map_err(|e| format!("DB lock failed: {e}"))?;
        crate::db::queries::update_setting(&conn, &key_for_db, &value_for_db)
            .map_err(|e| format!("Update failed: {e}"))
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?;
    db_result?;

    // If ARP spoof toggled, send ControlMessage to helper
    if key == "arp_spoof_enabled" {
        let enabled = value == "true";
        let guard = control.lock().await;
        if let Some(tx) = guard.as_ref() {
            if let Err(e) = tx
                .send(ControlMessage::SetArpSpoof { enabled })
                .await
            {
                log::warn!("Failed to send ARP spoof control message: {}", e);
            }
        } else {
            log::warn!("Helper not connected — ARP spoof setting saved but not applied");
        }
    }

    Ok(())
}

#[tauri::command]
pub async fn rename_device(
    id: i64,
    name: String,
    db: State<'_, DbPool>,
) -> Result<(), String> {
    let db = db.inner().clone();
    tokio::task::spawn_blocking(move || {
        let conn = db.lock().map_err(|e| format!("DB lock failed: {e}"))?;
        crate::db::queries::rename_device(&conn, id, &name)
            .map_err(|e| format!("Rename failed: {e}"))
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

#[tauri::command]
pub async fn update_device_icon(
    id: i64,
    icon: String,
    db: State<'_, DbPool>,
) -> Result<(), String> {
    let db = db.inner().clone();
    tokio::task::spawn_blocking(move || {
        let conn = db.lock().map_err(|e| format!("DB lock failed: {e}"))?;
        crate::db::queries::update_device_icon(&conn, id, &icon)
            .map_err(|e| format!("Update failed: {e}"))
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

#[tauri::command]
pub async fn toggle_device_visibility(
    id: i64,
    visible: bool,
    db: State<'_, DbPool>,
) -> Result<(), String> {
    let db = db.inner().clone();
    tokio::task::spawn_blocking(move || {
        let conn = db.lock().map_err(|e| format!("DB lock failed: {e}"))?;
        crate::db::queries::toggle_device_visibility(&conn, id, visible)
            .map_err(|e| format!("Update failed: {e}"))
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}
