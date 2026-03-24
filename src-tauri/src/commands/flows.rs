use crate::DbPool;
use serde_json::Value;
use tauri::State;

#[tauri::command]
pub async fn get_recent_flows(
    limit: u32,
    db: State<'_, DbPool>,
) -> Result<Vec<Value>, String> {
    let db = db.inner().clone();
    tokio::task::spawn_blocking(move || {
        let conn = db.lock().map_err(|e| format!("DB lock failed: {e}"))?;
        crate::db::queries::get_recent_flows(&conn, limit)
            .map_err(|e| format!("Query failed: {e}"))
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

#[tauri::command]
pub async fn get_devices(
    db: State<'_, DbPool>,
) -> Result<Vec<Value>, String> {
    let db = db.inner().clone();
    tokio::task::spawn_blocking(move || {
        let conn = db.lock().map_err(|e| format!("DB lock failed: {e}"))?;
        crate::db::queries::get_devices(&conn)
            .map_err(|e| format!("Query failed: {e}"))
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}
