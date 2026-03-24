use crate::models::{DeviceEntry, FlowEntry};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::collections::HashMap;

const ALLOWED_SETTINGS_KEYS: &[&str] = &[
    "arp_spoof_enabled",
    "capture_interface",
    "history_retention_days",
    "update_cadence_ms",
    "capture_active",
    "onboarding_complete",
];

/// Convert a millisecond epoch timestamp to an ISO 8601 datetime string.
fn ms_to_iso(ms: i64) -> String {
    let secs = ms / 1000;
    chrono_from_timestamp(secs)
}

fn chrono_from_timestamp(secs: i64) -> String {
    // Produce a simple ISO 8601 string from epoch seconds.
    // We avoid pulling in chrono; SQLite's datetime functions accept YYYY-MM-DD HH:MM:SS.
    let total_secs = if secs < 0 { 0i64 } else { secs };
    let ss = total_secs % 60;
    let total_min = total_secs / 60;
    let mm = total_min % 60;
    let total_hours = total_min / 60;
    let hh = total_hours % 24;
    let total_days = total_hours / 24;

    // Days since 1970-01-01
    let (year, month, day) = days_to_ymd(total_days as u32);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hh, mm, ss
    )
}

fn is_leap(y: u32) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

fn days_in_month(y: u32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

fn days_to_ymd(mut days: u32) -> (u32, u32, u32) {
    let mut year = 1970u32;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let mut month = 1u32;
    loop {
        let dim = days_in_month(year, month);
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }
    (year, month, days + 1)
}

/// INSERT OR REPLACE a device by mac_address, preserving user overrides.
/// Returns the rowid of the upserted row.
pub fn upsert_device(conn: &Connection, device: &DeviceEntry) -> Result<i64, rusqlite::Error> {
    // Check if this device already exists so we can preserve user overrides.
    struct Existing {
        id: i64,
        display_name: Option<String>,
        icon: String,
        is_visible: i64,
    }

    let existing: Option<Existing> = conn
        .query_row(
            "SELECT id, display_name, icon, is_visible FROM devices WHERE mac_address = ?1",
            params![device.mac_address],
            |row| {
                Ok(Existing {
                    id: row.get(0)?,
                    display_name: row.get(1)?,
                    icon: row.get(2)?,
                    is_visible: row.get(3)?,
                })
            },
        )
        .optional()?;

    // Resolve user-override fields
    let (preserved_display_name, preserved_icon, preserved_is_visible) = match &existing {
        Some(ex) => {
            let dn = if ex.display_name.is_some() {
                ex.display_name.clone()
            } else {
                device.display_name.clone()
            };
            let icon = if ex.icon != "device" {
                ex.icon.clone()
            } else {
                device.icon.clone()
            };
            let vis = if ex.is_visible == 0 {
                0i64
            } else {
                device.is_visible as i64
            };
            (dn, icon, vis)
        }
        None => (
            device.display_name.clone(),
            device.icon.clone(),
            device.is_visible as i64,
        ),
    };

    if let Some(ex) = &existing {
        conn.execute(
            "UPDATE devices SET
                ip_address = ?1,
                hostname = ?2,
                oui_manufacturer = ?3,
                device_type = ?4,
                display_name = ?5,
                icon = ?6,
                is_visible = ?7,
                last_seen = CURRENT_TIMESTAMP
             WHERE id = ?8",
            params![
                device.ip_address,
                device.hostname,
                device.oui_manufacturer,
                device.device_type,
                preserved_display_name,
                preserved_icon,
                preserved_is_visible,
                ex.id,
            ],
        )?;
        Ok(ex.id)
    } else {
        conn.execute(
            "INSERT INTO devices
                (mac_address, ip_address, hostname, oui_manufacturer, device_type,
                 display_name, icon, is_visible)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                device.mac_address,
                device.ip_address,
                device.hostname,
                device.oui_manufacturer,
                device.device_type,
                preserved_display_name,
                preserved_icon,
                preserved_is_visible,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }
}

/// Look up a device id by IP address.
fn device_id_for_ip(conn: &Connection, ip: &str) -> Option<i64> {
    conn.query_row(
        "SELECT id FROM devices WHERE ip_address = ?1 ORDER BY last_seen DESC LIMIT 1",
        params![ip],
        |row| row.get(0),
    )
    .optional()
    .unwrap_or(None)
}

/// INSERT OR REPLACE a flow summary by flow_key.
pub fn upsert_flow(conn: &Connection, flow: &FlowEntry) -> Result<(), rusqlite::Error> {
    let src_device_id = device_id_for_ip(conn, &flow.src_ip);
    let dst_device_id = device_id_for_ip(conn, &flow.dst_ip);

    let first_seen = ms_to_iso(flow.first_seen);
    let last_seen = ms_to_iso(flow.last_seen);

    conn.execute(
        "INSERT INTO flow_summaries
            (flow_key, src_ip, dst_ip, src_port, dst_port, protocol,
             service_name, src_device_id, dst_device_id,
             bytes_sent, bytes_received, packet_count,
             first_seen, last_seen, summary_text)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
         ON CONFLICT(flow_key) DO UPDATE SET
             src_ip = excluded.src_ip,
             dst_ip = excluded.dst_ip,
             src_port = excluded.src_port,
             dst_port = excluded.dst_port,
             protocol = excluded.protocol,
             service_name = COALESCE(excluded.service_name, flow_summaries.service_name),
             src_device_id = COALESCE(excluded.src_device_id, flow_summaries.src_device_id),
             dst_device_id = COALESCE(excluded.dst_device_id, flow_summaries.dst_device_id),
             bytes_sent = excluded.bytes_sent,
             bytes_received = excluded.bytes_received,
             packet_count = excluded.packet_count,
             last_seen = excluded.last_seen,
             summary_text = excluded.summary_text",
        params![
            flow.flow_key,
            flow.src_ip,
            flow.dst_ip,
            flow.src_port,
            flow.dst_port,
            flow.protocol,
            flow.service_name,
            src_device_id,
            dst_device_id,
            flow.bytes_sent as i64,
            flow.bytes_received as i64,
            flow.packet_count as i64,
            first_seen,
            last_seen,
            flow.summary_text,
        ],
    )?;

    Ok(())
}

/// Return recent flow summaries joined with device info.
pub fn get_recent_flows(conn: &Connection, limit: u32) -> Result<Vec<Value>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT
            f.id, f.flow_key, f.src_ip, f.dst_ip, f.src_port, f.dst_port,
            f.protocol, f.service_name,
            f.bytes_sent, f.bytes_received, f.packet_count,
            f.first_seen, f.last_seen, f.summary_text,
            sd.mac_address AS src_mac, sd.display_name AS src_display_name,
            sd.device_type AS src_device_type, sd.icon AS src_icon,
            dd.mac_address AS dst_mac, dd.display_name AS dst_display_name,
            dd.device_type AS dst_device_type, dd.icon AS dst_icon
         FROM flow_summaries f
         LEFT JOIN devices sd ON sd.id = f.src_device_id
         LEFT JOIN devices dd ON dd.id = f.dst_device_id
         ORDER BY f.last_seen DESC
         LIMIT ?1",
    )?;

    let rows = stmt.query_map(params![limit], |row| {
        Ok(json!({
            "id": row.get::<_, i64>(0)?,
            "flow_key": row.get::<_, String>(1)?,
            "src_ip": row.get::<_, String>(2)?,
            "dst_ip": row.get::<_, String>(3)?,
            "src_port": row.get::<_, Option<i64>>(4)?,
            "dst_port": row.get::<_, Option<i64>>(5)?,
            "protocol": row.get::<_, String>(6)?,
            "service_name": row.get::<_, Option<String>>(7)?,
            "bytes_sent": row.get::<_, i64>(8)?,
            "bytes_received": row.get::<_, i64>(9)?,
            "packet_count": row.get::<_, i64>(10)?,
            "first_seen": row.get::<_, String>(11)?,
            "last_seen": row.get::<_, String>(12)?,
            "summary_text": row.get::<_, Option<String>>(13)?,
            "src_device": {
                "mac_address": row.get::<_, Option<String>>(14)?,
                "display_name": row.get::<_, Option<String>>(15)?,
                "device_type": row.get::<_, Option<String>>(16)?,
                "icon": row.get::<_, Option<String>>(17)?
            },
            "dst_device": {
                "mac_address": row.get::<_, Option<String>>(18)?,
                "display_name": row.get::<_, Option<String>>(19)?,
                "device_type": row.get::<_, Option<String>>(20)?,
                "icon": row.get::<_, Option<String>>(21)?
            }
        }))
    })?;

    rows.collect()
}

/// Return all devices.
pub fn get_devices(conn: &Connection) -> Result<Vec<Value>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, mac_address, ip_address, hostname, oui_manufacturer,
                device_type, display_name, icon, is_visible, first_seen, last_seen, notes
         FROM devices
         ORDER BY last_seen DESC",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(json!({
            "id": row.get::<_, i64>(0)?,
            "mac_address": row.get::<_, String>(1)?,
            "ip_address": row.get::<_, Option<String>>(2)?,
            "hostname": row.get::<_, Option<String>>(3)?,
            "oui_manufacturer": row.get::<_, Option<String>>(4)?,
            "device_type": row.get::<_, Option<String>>(5)?,
            "display_name": row.get::<_, Option<String>>(6)?,
            "icon": row.get::<_, String>(7)?,
            "is_visible": row.get::<_, i64>(8)? != 0,
            "first_seen": row.get::<_, String>(9)?,
            "last_seen": row.get::<_, String>(10)?,
            "notes": row.get::<_, Option<String>>(11)?
        }))
    })?;

    rows.collect()
}

/// Return all settings as a HashMap.
pub fn get_settings(conn: &Connection) -> Result<HashMap<String, String>, rusqlite::Error> {
    let mut stmt = conn.prepare("SELECT key, value FROM settings")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;

    let mut map = HashMap::new();
    for row in rows {
        let (k, v) = row?;
        map.insert(k, v);
    }
    Ok(map)
}

/// Update a single setting value. Validates the key against the allowlist.
pub fn update_setting(conn: &Connection, key: &str, value: &str) -> Result<(), rusqlite::Error> {
    if !ALLOWED_SETTINGS_KEYS.contains(&key) {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "unknown settings key: {key}"
        )));
    }
    conn.execute(
        "UPDATE settings SET value = ?1, updated_at = CURRENT_TIMESTAMP WHERE key = ?2",
        params![value, key],
    )?;
    Ok(())
}

/// Update a device's display name.
pub fn rename_device(conn: &Connection, id: i64, name: &str) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE devices SET display_name = ?1 WHERE id = ?2",
        params![name, id],
    )?;
    Ok(())
}

/// Update a device's icon.
pub fn update_device_icon(conn: &Connection, id: i64, icon: &str) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE devices SET icon = ?1 WHERE id = ?2",
        params![icon, id],
    )?;
    Ok(())
}

/// Toggle device visibility.
pub fn toggle_device_visibility(
    conn: &Connection,
    id: i64,
    visible: bool,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE devices SET is_visible = ?1 WHERE id = ?2",
        params![visible as i64, id],
    )?;
    Ok(())
}

/// Delete flow summaries older than `retention_days`. Returns number of rows deleted.
pub fn purge_old_flows(conn: &Connection, retention_days: i64) -> Result<usize, rusqlite::Error> {
    let threshold = format!("datetime('now', '-{} days')", retention_days);
    let n = conn.execute(
        &format!("DELETE FROM flow_summaries WHERE last_seen < {threshold}"),
        [],
    )?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::init_db;
    use crate::models::{DeviceEntry, FlowEntry};

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        crate::db::schema::create_schema_for_test(&conn);
        conn
    }

    fn make_device(mac: &str, ip: Option<&str>) -> DeviceEntry {
        DeviceEntry {
            mac_address: mac.to_string(),
            ip_address: ip.map(str::to_string),
            hostname: None,
            oui_manufacturer: None,
            device_type: "Unknown".to_string(),
            display_name: None,
            icon: "device".to_string(),
            is_visible: true,
        }
    }

    fn make_flow(key: &str, src: &str, dst: &str) -> FlowEntry {
        FlowEntry {
            flow_key: key.to_string(),
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            src_port: Some(12345),
            dst_port: Some(443),
            protocol: "TCP".to_string(),
            service_name: Some("HTTPS".to_string()),
            bytes_sent: 1000,
            bytes_received: 2000,
            packet_count: 30,
            first_seen: 1_700_000_000_000,
            last_seen: 1_700_000_001_000,
            summary_text: "Test flow".to_string(),
        }
    }

    #[test]
    fn test_upsert_new_device() {
        let conn = setup();
        let device = make_device("aa:bb:cc:dd:ee:ff", Some("192.168.1.1"));
        let id = upsert_device(&conn, &device).unwrap();
        assert!(id > 0);
    }

    #[test]
    fn test_upsert_device_update() {
        let conn = setup();
        let mut device = make_device("aa:bb:cc:dd:ee:ff", Some("192.168.1.1"));
        let id1 = upsert_device(&conn, &device).unwrap();

        device.ip_address = Some("192.168.1.2".to_string());
        let id2 = upsert_device(&conn, &device).unwrap();

        // Same row should be updated, not a new one
        assert_eq!(id1, id2);

        let ip: String = conn
            .query_row(
                "SELECT ip_address FROM devices WHERE id = ?1",
                params![id1],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ip, "192.168.1.2");
    }

    #[test]
    fn test_device_override_preservation() {
        let conn = setup();
        let device = make_device("aa:bb:cc:dd:ee:ff", Some("192.168.1.1"));
        let id = upsert_device(&conn, &device).unwrap();

        // User renames and sets custom icon
        rename_device(&conn, id, "My MacBook").unwrap();
        update_device_icon(&conn, id, "laptop").unwrap();

        // Now upsert again (e.g. from capture engine) — overrides should be preserved
        let updated = DeviceEntry {
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            ip_address: Some("192.168.1.3".to_string()),
            hostname: Some("macbook.local".to_string()),
            oui_manufacturer: Some("Apple".to_string()),
            device_type: "Mac".to_string(),
            display_name: None,         // capture doesn't set a display name
            icon: "device".to_string(), // capture provides default icon
            is_visible: true,
        };
        upsert_device(&conn, &updated).unwrap();

        let (display_name, icon): (Option<String>, String) = conn
            .query_row(
                "SELECT display_name, icon FROM devices WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(
            display_name.as_deref(),
            Some("My MacBook"),
            "display_name should be preserved"
        );
        assert_eq!(icon, "laptop", "icon should be preserved");
    }

    #[test]
    fn test_device_visibility_preserved_when_hidden() {
        let conn = setup();
        let device = make_device("aa:bb:cc:dd:ee:ff", Some("192.168.1.1"));
        let id = upsert_device(&conn, &device).unwrap();
        toggle_device_visibility(&conn, id, false).unwrap();

        // Re-upsert with is_visible = true — should stay hidden
        upsert_device(&conn, &device).unwrap();
        let vis: i64 = conn
            .query_row(
                "SELECT is_visible FROM devices WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(vis, 0, "hidden device should stay hidden after upsert");
    }

    #[test]
    fn test_upsert_flow_with_device_linking() {
        let conn = setup();
        let src = make_device("aa:bb:cc:11:11:11", Some("10.0.0.1"));
        let dst = make_device("aa:bb:cc:22:22:22", Some("8.8.8.8"));
        upsert_device(&conn, &src).unwrap();
        upsert_device(&conn, &dst).unwrap();

        let flow = make_flow("tcp:10.0.0.1:12345->8.8.8.8:443", "10.0.0.1", "8.8.8.8");
        upsert_flow(&conn, &flow).unwrap();

        let (src_id, dst_id): (Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT src_device_id, dst_device_id FROM flow_summaries WHERE flow_key = ?1",
                params![flow.flow_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert!(src_id.is_some(), "src_device_id should be linked");
        assert!(dst_id.is_some(), "dst_device_id should be linked");
    }

    #[test]
    fn test_upsert_flow_idempotent() {
        let conn = setup();
        let flow = make_flow("test-flow", "1.2.3.4", "5.6.7.8");
        upsert_flow(&conn, &flow).unwrap();
        upsert_flow(&conn, &flow).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM flow_summaries WHERE flow_key = ?1",
                params![flow.flow_key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "duplicate upsert should not create multiple rows");
    }

    #[test]
    fn test_purge_old_flows() {
        let conn = setup();

        // Insert an ancient flow (manually set last_seen to a long time ago)
        conn.execute(
            "INSERT INTO flow_summaries
                (flow_key, src_ip, dst_ip, protocol, bytes_sent, bytes_received,
                 packet_count, first_seen, last_seen)
             VALUES ('old-flow', '1.1.1.1', '2.2.2.2', 'TCP', 0, 0, 0,
                     '2020-01-01 00:00:00', '2020-01-01 00:00:00')",
            [],
        )
        .unwrap();

        let n = purge_old_flows(&conn, 7).unwrap();
        assert_eq!(n, 1, "old flow should be purged");
    }

    #[test]
    fn test_purge_recent_flows_not_deleted() {
        let conn = setup();

        conn.execute(
            "INSERT INTO flow_summaries
                (flow_key, src_ip, dst_ip, protocol, bytes_sent, bytes_received,
                 packet_count, first_seen, last_seen)
             VALUES ('recent-flow', '1.1.1.1', '2.2.2.2', 'TCP', 0, 0, 0,
                     CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            [],
        )
        .unwrap();

        let n = purge_old_flows(&conn, 7).unwrap();
        assert_eq!(n, 0, "recent flow should not be purged");
    }

    #[test]
    fn test_settings_crud() {
        let conn = setup();

        let settings = get_settings(&conn).unwrap();
        assert!(settings.contains_key("arp_spoof_enabled"));
        assert_eq!(settings["arp_spoof_enabled"], "false");

        update_setting(&conn, "arp_spoof_enabled", "true").unwrap();
        let updated = get_settings(&conn).unwrap();
        assert_eq!(updated["arp_spoof_enabled"], "true");
    }

    #[test]
    fn test_update_setting_rejects_unknown_key() {
        let conn = setup();
        let result = update_setting(&conn, "malicious_key", "evil");
        assert!(result.is_err(), "unknown setting key should be rejected");
    }

    #[test]
    fn test_get_devices_and_flows() {
        let conn = setup();
        let device = make_device("de:ad:be:ef:00:01", Some("192.168.0.5"));
        upsert_device(&conn, &device).unwrap();

        let devices = get_devices(&conn).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0]["mac_address"], "de:ad:be:ef:00:01");

        let flow = make_flow("test:192.168.0.5->8.8.8.8:53", "192.168.0.5", "8.8.8.8");
        upsert_flow(&conn, &flow).unwrap();

        let flows = get_recent_flows(&conn, 10).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0]["flow_key"], "test:192.168.0.5->8.8.8.8:53");
    }
}
