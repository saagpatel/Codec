use rusqlite::Connection;
use std::path::Path;

/// Open (or create) the SQLite database at `path`, run migrations, and return the connection.
pub fn init_db(path: &Path) -> Result<Connection, Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(path)?;

    // Enable WAL mode and foreign keys
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA foreign_keys=ON;",
    )?;

    let version: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

    if version == 0 {
        create_schema(&conn)?;
        conn.execute_batch("PRAGMA user_version = 1;")?;
    }

    Ok(conn)
}

fn create_schema(conn: &Connection) -> Result<(), Box<dyn std::error::Error>> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT UNIQUE NOT NULL,
            ip_address TEXT,
            hostname TEXT,
            oui_manufacturer TEXT,
            device_type TEXT DEFAULT 'Unknown',
            display_name TEXT,
            icon TEXT DEFAULT 'device',
            is_visible INTEGER DEFAULT 1,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            notes TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_device_mac ON devices(mac_address);
        CREATE INDEX IF NOT EXISTS idx_device_ip ON devices(ip_address);

        CREATE TABLE IF NOT EXISTS flow_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_key TEXT UNIQUE NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT NOT NULL,
            service_name TEXT,
            src_device_id INTEGER REFERENCES devices(id),
            dst_device_id INTEGER REFERENCES devices(id),
            bytes_sent INTEGER DEFAULT 0,
            bytes_received INTEGER DEFAULT 0,
            packet_count INTEGER DEFAULT 0,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            summary_text TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_flow_last_seen ON flow_summaries(last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_flow_device ON flow_summaries(src_device_id, last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_flow_key ON flow_summaries(flow_key);

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        INSERT OR IGNORE INTO settings VALUES ('arp_spoof_enabled', 'false', CURRENT_TIMESTAMP);
        INSERT OR IGNORE INTO settings VALUES ('capture_interface', 'auto', CURRENT_TIMESTAMP);
        INSERT OR IGNORE INTO settings VALUES ('history_retention_days', '7', CURRENT_TIMESTAMP);
        INSERT OR IGNORE INTO settings VALUES ('update_cadence_ms', '2000', CURRENT_TIMESTAMP);
        INSERT OR IGNORE INTO settings VALUES ('capture_active', 'false', CURRENT_TIMESTAMP);
        INSERT OR IGNORE INTO settings VALUES ('onboarding_complete', 'false', CURRENT_TIMESTAMP);
        ",
    )?;

    Ok(())
}

/// Test-only helper to create schema without the full init_db flow.
#[cfg(test)]
pub fn create_schema_for_test(conn: &Connection) {
    create_schema(conn).expect("test schema creation failed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn open_memory() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn test_schema_creation_succeeds() {
        let conn = open_memory();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .unwrap();
        create_schema(&conn).expect("schema creation should succeed");

        // Verify tables exist
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('devices','flow_summaries','settings')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 3, "all three tables should exist");
    }

    #[test]
    fn test_schema_is_idempotent() {
        let conn = open_memory();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .unwrap();
        create_schema(&conn).expect("first call should succeed");
        // Second call must not fail (CREATE IF NOT EXISTS + INSERT OR IGNORE)
        create_schema(&conn).expect("second call should also succeed");
    }

    #[test]
    fn test_settings_seeded_correctly() {
        let conn = open_memory();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        create_schema(&conn).unwrap();

        let expected = [
            ("arp_spoof_enabled", "false"),
            ("capture_interface", "auto"),
            ("history_retention_days", "7"),
            ("update_cadence_ms", "2000"),
            ("capture_active", "false"),
            ("onboarding_complete", "false"),
        ];

        for (key, expected_val) in &expected {
            let val: String = conn
                .query_row(
                    "SELECT value FROM settings WHERE key = ?1",
                    rusqlite::params![key],
                    |row| row.get(0),
                )
                .unwrap_or_else(|_| panic!("setting '{key}' should exist"));
            assert_eq!(
                val, *expected_val,
                "setting '{key}' should equal '{expected_val}'"
            );
        }
    }

    #[test]
    fn test_init_db_with_tempfile() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let conn = init_db(&db_path).expect("init_db should succeed");

        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
    }

    #[test]
    fn test_init_db_called_twice_does_not_increment_version() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let _conn1 = init_db(&db_path).unwrap();
        let conn2 = init_db(&db_path).unwrap();

        let version: u32 = conn2
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1, "version should remain 1 after second init");
    }

    #[test]
    fn test_foreign_key_constraint_on_flow_summaries() {
        let conn = open_memory();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .unwrap();
        create_schema(&conn).unwrap();

        // Attempting to insert a flow referencing a non-existent device should fail
        let result = conn.execute(
            "INSERT INTO flow_summaries
                (flow_key, src_ip, dst_ip, protocol, bytes_sent, bytes_received,
                 packet_count, first_seen, last_seen, src_device_id)
             VALUES ('fk-test', '1.2.3.4', '5.6.7.8', 'TCP', 0, 0, 0,
                     CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 99999)",
            [],
        );
        assert!(result.is_err(), "foreign key violation should be rejected");
    }

    #[test]
    fn test_devices_mac_uniqueness() {
        let conn = open_memory();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        create_schema(&conn).unwrap();

        conn.execute(
            "INSERT INTO devices (mac_address) VALUES ('aa:bb:cc:dd:ee:ff')",
            [],
        )
        .unwrap();
        let result = conn.execute(
            "INSERT INTO devices (mac_address) VALUES ('aa:bb:cc:dd:ee:ff')",
            [],
        );
        assert!(result.is_err(), "duplicate MAC address should be rejected");
    }

    #[test]
    fn test_expected_indexes_exist() {
        let conn = open_memory();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        create_schema(&conn).unwrap();

        let expected_indexes = [
            "idx_device_mac",
            "idx_device_ip",
            "idx_flow_last_seen",
            "idx_flow_device",
            "idx_flow_key",
        ];

        for idx in &expected_indexes {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?1",
                    rusqlite::params![idx],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "index '{idx}' should exist");
        }
    }
}
