mod capture;
mod commands;
mod db;
mod models;

use tauri::Manager;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub type DbPool = Arc<Mutex<rusqlite::Connection>>;
pub type OuiDb = Arc<HashMap<[u8; 3], String>>;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::init();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::flows::get_recent_flows,
            commands::flows::get_devices,
            commands::settings::get_settings,
            commands::settings::update_setting,
            commands::settings::rename_device,
            commands::settings::update_device_icon,
            commands::settings::toggle_device_visibility,
        ])
        .setup(|app| {
            // Init database at ~/.codec/codec.db
            let data_dir = dirs::home_dir()
                .expect("No home directory")
                .join(".codec");
            std::fs::create_dir_all(&data_dir)?;
            let db_path = data_dir.join("codec.db");
            let conn = db::schema::init_db(&db_path)
                .map_err(|e| format!("Failed to init database: {}", e))?;
            let db: DbPool = Arc::new(Mutex::new(conn));
            log::info!("Database initialized at {}", db_path.display());

            // Register DB as managed state for Tauri commands
            app.manage(db.clone());

            // Load OUI database from bundled resource
            let oui_path = app
                .path()
                .resolve("oui.csv", tauri::path::BaseDirectory::Resource)
                .unwrap_or_else(|_| std::path::PathBuf::from("assets/oui.csv"));
            let oui_db: OuiDb = Arc::new(capture::device_registry::load_oui(&oui_path));
            log::info!("Loaded {} OUI entries", oui_db.len());

            // Create control sender — allows commands to send messages to the helper
            let control: capture::helper_client::ControlSender =
                Arc::new(tokio::sync::Mutex::new(None));
            app.manage(control.clone());

            // Start helper client with DB + OUI enrichment + control channel
            let handle = app.handle().clone();
            capture::helper_client::start(handle, db.clone(), oui_db.clone(), control);

            // Spawn hourly purge timer
            let purge_db = db.clone();
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(3600));
                loop {
                    interval.tick().await;
                    if let Ok(conn) = purge_db.lock() {
                        match db::queries::purge_old_flows(&conn, 7) {
                            Ok(n) if n > 0 => log::info!("Purged {} old flows", n),
                            Err(e) => log::error!("Purge failed: {}", e),
                            _ => {}
                        }
                    }
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
