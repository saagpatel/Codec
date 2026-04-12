use crate::models::{DeviceStats, TopologyEdge, TopologyNode};
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

#[tauri::command]
pub async fn get_topology(
    window_secs: Option<i64>,
    db: State<'_, DbPool>,
) -> Result<(Vec<TopologyNode>, Vec<TopologyEdge>), String> {
    let db = db.inner().clone();
    let secs = window_secs.unwrap_or(60);
    tokio::task::spawn_blocking(move || {
        let conn = db.lock().map_err(|e| format!("DB lock failed: {e}"))?;
        crate::db::queries::get_topology(&conn, secs)
            .map_err(|e| format!("Query failed: {e}"))
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

#[tauri::command]
pub async fn get_device_stats(
    device_id: i64,
    db: State<'_, DbPool>,
) -> Result<DeviceStats, String> {
    let db = db.inner().clone();
    tokio::task::spawn_blocking(move || {
        let conn = db.lock().map_err(|e| format!("DB lock failed: {e}"))?;
        crate::db::queries::get_device_stats(&conn, device_id)
            .map_err(|e| format!("Query failed: {e}"))
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}

#[tauri::command]
pub async fn query_history(
    device_id: Option<i64>,
    start: String,
    end: String,
    limit: Option<u32>,
    db: State<'_, DbPool>,
) -> Result<Vec<Value>, String> {
    let db = db.inner().clone();
    let lim = limit.unwrap_or(500);
    tokio::task::spawn_blocking(move || {
        let conn = db.lock().map_err(|e| format!("DB lock failed: {e}"))?;
        crate::db::queries::query_history(&conn, device_id, &start, &end, lim)
            .map_err(|e| format!("Query failed: {e}"))
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
}
