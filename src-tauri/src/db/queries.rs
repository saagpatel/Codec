use crate::models::{
    DeviceEntry, DeviceStats, FlowEntry, ProtocolShare, TopologyEdge, TopologyNode,
};
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

/// Build topology graph from recent flows (last `window_secs` seconds).
/// Devices become nodes, unique service_names become service nodes,
/// flows become edges grouped by (src_node, dst_node, protocol).
pub fn get_topology(
    conn: &Connection,
    window_secs: i64,
) -> Result<(Vec<TopologyNode>, Vec<TopologyEdge>), rusqlite::Error> {
    let mut nodes: Vec<TopologyNode> = Vec::new();
    let mut node_ids: HashMap<String, usize> = HashMap::new();

    // 1) Device nodes — all visible devices
    {
        let mut stmt = conn.prepare(
            "SELECT id, mac_address, display_name, hostname, oui_manufacturer,
                    device_type, icon, ip_address
             FROM devices
             WHERE is_visible = 1
             ORDER BY last_seen DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let _id: i64 = row.get(0)?;
            let mac: String = row.get(1)?;
            let display_name: Option<String> = row.get(2)?;
            let hostname: Option<String> = row.get(3)?;
            let oui: Option<String> = row.get(4)?;
            let device_type: String = row.get(5)?;
            let icon: String = row.get(6)?;
            let ip: Option<String> = row.get(7)?;

            let label = display_name
                .or(hostname)
                .or(oui)
                .or(ip)
                .unwrap_or_else(|| mac.clone());

            let node_type = if device_type == "Router" {
                "router".to_string()
            } else {
                "device".to_string()
            };

            Ok((mac, label, node_type, icon))
        })?;

        for row in rows {
            let (mac, label, node_type, icon) = row?;
            let node_id = format!("dev:{}", mac);
            node_ids.insert(node_id.clone(), nodes.len());
            nodes.push(TopologyNode {
                id: node_id,
                label,
                node_type,
                icon,
                total_bytes: 0,
            });
        }
    }

    // 2) Query recent flows to build edges and service nodes
    let mut edge_map: HashMap<(String, String, String), (u64, String)> = HashMap::new();
    {
        let active_threshold: String =
            conn.query_row("SELECT datetime('now', '-10 seconds')", [], |row| {
                row.get(0)
            })?;

        let mut stmt = conn.prepare(
            "SELECT f.src_ip, f.dst_ip, f.protocol, f.service_name,
                    f.bytes_sent, f.bytes_received, f.last_seen,
                    sd.mac_address AS src_mac
             FROM flow_summaries f
             LEFT JOIN devices sd ON sd.id = f.src_device_id
             WHERE f.last_seen >= datetime('now', '-' || ?1 || ' seconds')",
        )?;

        let rows = stmt.query_map(params![window_secs], |row| {
            Ok((
                row.get::<_, String>(0)?,         // src_ip
                row.get::<_, String>(1)?,         // dst_ip
                row.get::<_, String>(2)?,         // protocol
                row.get::<_, Option<String>>(3)?, // service_name
                row.get::<_, i64>(4)? as u64,     // bytes_sent
                row.get::<_, i64>(5)? as u64,     // bytes_received
                row.get::<_, String>(6)?,         // last_seen
                row.get::<_, Option<String>>(7)?, // src_mac
            ))
        })?;

        for row in rows {
            let (
                src_ip,
                dst_ip,
                protocol,
                service_name,
                bytes_sent,
                bytes_received,
                last_seen,
                src_mac,
            ) = row?;
            let total = bytes_sent + bytes_received;

            let src_node_id = if let Some(ref mac) = src_mac {
                format!("dev:{}", mac)
            } else {
                format!("ip:{}", src_ip)
            };

            let service_label = service_name.unwrap_or_else(|| dst_ip.clone());
            let dst_node_id = format!("svc:{}", service_label);

            // Ensure service node exists
            if !node_ids.contains_key(&dst_node_id) {
                node_ids.insert(dst_node_id.clone(), nodes.len());
                nodes.push(TopologyNode {
                    id: dst_node_id.clone(),
                    label: service_label,
                    node_type: "service".to_string(),
                    icon: "globe".to_string(),
                    total_bytes: 0,
                });
            }

            // Ensure unknown-IP source node exists
            if !node_ids.contains_key(&src_node_id) {
                node_ids.insert(src_node_id.clone(), nodes.len());
                nodes.push(TopologyNode {
                    id: src_node_id.clone(),
                    label: src_ip,
                    node_type: "device".to_string(),
                    icon: "device".to_string(),
                    total_bytes: 0,
                });
            }

            if let Some(&idx) = node_ids.get(&src_node_id) {
                nodes[idx].total_bytes += total;
            }
            if let Some(&idx) = node_ids.get(&dst_node_id) {
                nodes[idx].total_bytes += total;
            }

            let edge_key = (src_node_id, dst_node_id, protocol);
            let entry = edge_map.entry(edge_key).or_insert((0, String::new()));
            entry.0 += total;
            if last_seen > entry.1 {
                entry.1 = last_seen;
            }
        }

        // Convert edge_map to TopologyEdge vec
        let edges: Vec<TopologyEdge> = edge_map
            .into_iter()
            .map(|((source, target, protocol), (bytes, last_seen))| {
                let active = last_seen >= active_threshold;
                TopologyEdge {
                    source,
                    target,
                    protocol,
                    bytes,
                    active,
                }
            })
            .collect();

        return Ok((nodes, edges));
    }
}

/// Per-device traffic statistics.
pub fn get_device_stats(conn: &Connection, device_id: i64) -> Result<DeviceStats, rusqlite::Error> {
    let (total_sent, total_received, flow_count, first_seen, last_seen): (
        i64,
        i64,
        i64,
        String,
        String,
    ) = conn.query_row(
        "SELECT COALESCE(SUM(f.bytes_sent), 0),
                    COALESCE(SUM(f.bytes_received), 0),
                    COUNT(*),
                    COALESCE(MIN(f.first_seen), ''),
                    COALESCE(MAX(f.last_seen), '')
             FROM flow_summaries f
             WHERE f.src_device_id = ?1 OR f.dst_device_id = ?1",
        params![device_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;

    let mut stmt = conn.prepare(
        "SELECT f.protocol, SUM(f.bytes_sent + f.bytes_received) as total
         FROM flow_summaries f
         WHERE f.src_device_id = ?1 OR f.dst_device_id = ?1
         GROUP BY f.protocol
         ORDER BY total DESC",
    )?;

    let grand_total = (total_sent + total_received) as f64;

    let protocol_rows = stmt.query_map(params![device_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
    })?;

    let mut protocol_breakdown = Vec::new();
    for row in protocol_rows {
        let (protocol, bytes) = row?;
        let percentage = if grand_total > 0.0 {
            (bytes as f64 / grand_total) * 100.0
        } else {
            0.0
        };
        protocol_breakdown.push(ProtocolShare {
            protocol,
            bytes,
            percentage,
        });
    }

    Ok(DeviceStats {
        device_id,
        total_bytes_sent: total_sent as u64,
        total_bytes_received: total_received as u64,
        flow_count: flow_count as u64,
        protocol_breakdown,
        first_seen,
        last_seen,
    })
}

/// Query flow history with optional device and time range filters.
pub fn query_history(
    conn: &Connection,
    device_id: Option<i64>,
    start: &str,
    end: &str,
    limit: u32,
) -> Result<Vec<Value>, rusqlite::Error> {
    let base_select = "SELECT
            f.id, f.flow_key, f.src_ip, f.dst_ip, f.src_port, f.dst_port,
            f.protocol, f.service_name,
            f.bytes_sent, f.bytes_received, f.packet_count,
            f.first_seen, f.last_seen, f.summary_text,
            sd.mac_address, sd.display_name, sd.device_type, sd.icon,
            dd.mac_address, dd.display_name, dd.device_type, dd.icon
         FROM flow_summaries f
         LEFT JOIN devices sd ON sd.id = f.src_device_id
         LEFT JOIN devices dd ON dd.id = f.dst_device_id";

    let row_mapper = |row: &rusqlite::Row<'_>| {
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
    };

    if let Some(dev_id) = device_id {
        let sql = format!(
            "{} WHERE f.last_seen >= ?1 AND f.last_seen <= ?2 AND (f.src_device_id = ?3 OR f.dst_device_id = ?3) ORDER BY f.last_seen DESC LIMIT ?4",
            base_select
        );
        let mut stmt = conn.prepare(&sql)?;
        let results: Result<Vec<Value>, rusqlite::Error> = stmt
            .query_map(params![start, end, dev_id, limit], row_mapper)?
            .collect();
        results
    } else {
        let sql = format!(
            "{} WHERE f.last_seen >= ?1 AND f.last_seen <= ?2 ORDER BY f.last_seen DESC LIMIT ?3",
            base_select
        );
        let mut stmt = conn.prepare(&sql)?;
        let results: Result<Vec<Value>, rusqlite::Error> = stmt
            .query_map(params![start, end, limit], row_mapper)?
            .collect();
        results
    }
}

/// Delete flow summaries older than `retention_days`. Returns number of rows deleted.
pub fn purge_old_flows(conn: &Connection, retention_days: i64) -> Result<usize, rusqlite::Error> {
    // Use parameterized binding: concatenate the interval string inside SQLite so the
    // retention_days value is bound as a parameter, never interpolated into the SQL text.
    let n = conn.execute(
        "DELETE FROM flow_summaries WHERE last_seen < datetime('now', '-' || ?1 || ' days')",
        params![retention_days],
    )?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_ms_to_iso_epoch() {
        // 0ms = 1970-01-01 00:00:00
        assert_eq!(ms_to_iso(0), "1970-01-01 00:00:00");
    }

    #[test]
    fn test_ms_to_iso_known_timestamp() {
        // 2023-11-14 22:13:20 UTC = 1700000000 seconds = 1700000000000 ms
        assert_eq!(ms_to_iso(1_700_000_000_000), "2023-11-14 22:13:20");
    }

    #[test]
    fn test_ms_to_iso_negative_clamped_to_epoch() {
        // Negative timestamps clamp to epoch
        assert_eq!(ms_to_iso(-1000), "1970-01-01 00:00:00");
    }

    #[test]
    fn test_days_in_month_leap_year() {
        assert_eq!(days_in_month(2000, 2), 29); // 2000 is a leap year
        assert_eq!(days_in_month(1900, 2), 28); // 1900 is NOT a leap year
        assert_eq!(days_in_month(2024, 2), 29); // 2024 is a leap year
    }

    #[test]
    fn test_days_in_month_standard() {
        assert_eq!(days_in_month(2023, 1), 31);
        assert_eq!(days_in_month(2023, 4), 30);
        assert_eq!(days_in_month(2023, 12), 31);
    }

    #[test]
    fn test_is_leap_century_rules() {
        assert!(is_leap(2000)); // divisible by 400 → leap
        assert!(!is_leap(1900)); // divisible by 100 but not 400 → not leap
        assert!(is_leap(2024)); // divisible by 4, not 100 → leap
        assert!(!is_leap(2023)); // not divisible by 4 → not leap
    }

    #[test]
    fn test_update_setting_all_allowed_keys_succeed() {
        let conn = setup();
        // All keys in ALLOWED_SETTINGS_KEYS must succeed
        for key in ALLOWED_SETTINGS_KEYS {
            let result = update_setting(&conn, key, "test-value");
            assert!(result.is_ok(), "allowed key '{key}' should be accepted");
        }
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

    // --- Topology tests ---

    /// Insert a flow with CURRENT_TIMESTAMP so it appears in get_topology's time window.
    fn insert_recent_flow(
        conn: &Connection,
        key: &str,
        src_ip: &str,
        dst_ip: &str,
        protocol: &str,
        service: Option<&str>,
        bytes_sent: i64,
        bytes_recv: i64,
    ) {
        let src_dev = device_id_for_ip(conn, src_ip);
        let dst_dev = device_id_for_ip(conn, dst_ip);
        conn.execute(
            "INSERT INTO flow_summaries
                (flow_key, src_ip, dst_ip, protocol, service_name,
                 src_device_id, dst_device_id,
                 bytes_sent, bytes_received, packet_count,
                 first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 10, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            params![
                key, src_ip, dst_ip, protocol, service, src_dev, dst_dev, bytes_sent, bytes_recv
            ],
        )
        .unwrap();
    }

    #[test]
    fn test_get_topology_returns_device_nodes() {
        let conn = setup();
        let d1 = make_device("aa:bb:cc:00:00:01", Some("192.168.1.10"));
        let d2 = make_device("aa:bb:cc:00:00:02", Some("192.168.1.20"));
        upsert_device(&conn, &d1).unwrap();
        upsert_device(&conn, &d2).unwrap();

        let (nodes, _edges) = get_topology(&conn, 3600).unwrap();
        let device_nodes: Vec<_> = nodes.iter().filter(|n| n.node_type == "device").collect();
        assert!(
            device_nodes.len() >= 2,
            "should have at least 2 device nodes"
        );
    }

    #[test]
    fn test_get_topology_creates_service_nodes_from_flows() {
        let conn = setup();
        let d1 = make_device("aa:bb:cc:00:00:01", Some("192.168.1.10"));
        upsert_device(&conn, &d1).unwrap();

        insert_recent_flow(
            &conn,
            "f1",
            "192.168.1.10",
            "17.253.144.10",
            "TLS",
            Some("icloud.com"),
            5000,
            10000,
        );
        insert_recent_flow(
            &conn,
            "f2",
            "192.168.1.10",
            "8.8.8.8",
            "DNS",
            Some("dns.google"),
            100,
            200,
        );

        let (nodes, edges) = get_topology(&conn, 3600).unwrap();
        let svc_nodes: Vec<_> = nodes.iter().filter(|n| n.node_type == "service").collect();
        assert_eq!(
            svc_nodes.len(),
            2,
            "should have 2 service nodes (icloud.com, dns.google)"
        );
        assert!(edges.len() >= 2, "should have at least 2 edges");
    }

    #[test]
    fn test_get_topology_accumulates_bytes_on_nodes() {
        let conn = setup();
        let d1 = make_device("aa:bb:cc:00:00:01", Some("192.168.1.10"));
        upsert_device(&conn, &d1).unwrap();

        insert_recent_flow(
            &conn,
            "f1",
            "192.168.1.10",
            "1.1.1.1",
            "TLS",
            Some("example.com"),
            1000,
            2000,
        );
        insert_recent_flow(
            &conn,
            "f2",
            "192.168.1.10",
            "1.1.1.2",
            "TLS",
            Some("example.com"),
            500,
            500,
        );

        let (nodes, _edges) = get_topology(&conn, 3600).unwrap();
        let dev = nodes
            .iter()
            .find(|n| n.id == "dev:aa:bb:cc:00:00:01")
            .unwrap();
        assert_eq!(dev.total_bytes, 4000, "device node bytes should accumulate");

        let svc = nodes.iter().find(|n| n.id == "svc:example.com").unwrap();
        assert_eq!(
            svc.total_bytes, 4000,
            "service node bytes should accumulate"
        );
    }

    #[test]
    fn test_get_topology_hidden_devices_excluded() {
        let conn = setup();
        let d1 = make_device("aa:bb:cc:00:00:01", Some("192.168.1.10"));
        let id = upsert_device(&conn, &d1).unwrap();
        toggle_device_visibility(&conn, id, false).unwrap();

        let (nodes, _) = get_topology(&conn, 3600).unwrap();
        let dev_nodes: Vec<_> = nodes
            .iter()
            .filter(|n| n.id == "dev:aa:bb:cc:00:00:01")
            .collect();
        assert!(
            dev_nodes.is_empty(),
            "hidden device should not appear as node"
        );
    }

    #[test]
    fn test_get_topology_edges_grouped_by_protocol() {
        let conn = setup();
        let d1 = make_device("aa:bb:cc:00:00:01", Some("192.168.1.10"));
        upsert_device(&conn, &d1).unwrap();

        insert_recent_flow(
            &conn,
            "f1",
            "192.168.1.10",
            "8.8.8.8",
            "DNS",
            Some("dns.google"),
            100,
            200,
        );
        insert_recent_flow(
            &conn,
            "f2",
            "192.168.1.10",
            "8.8.4.4",
            "DNS",
            Some("dns.google"),
            150,
            250,
        );
        insert_recent_flow(
            &conn,
            "f3",
            "192.168.1.10",
            "17.0.0.1",
            "TLS",
            Some("dns.google"),
            1000,
            2000,
        );

        let (_, edges) = get_topology(&conn, 3600).unwrap();
        // DNS flows to dns.google should merge into one edge, TLS is separate
        let dns_edges: Vec<_> = edges
            .iter()
            .filter(|e| e.protocol == "DNS" && e.target == "svc:dns.google")
            .collect();
        assert_eq!(dns_edges.len(), 1, "DNS edges to same service should merge");
        assert_eq!(dns_edges[0].bytes, 700, "merged DNS edge should sum bytes");
    }

    #[test]
    fn test_get_topology_router_node_type() {
        let conn = setup();
        let mut d1 = make_device("aa:bb:cc:00:00:01", Some("192.168.1.1"));
        d1.device_type = "Router".to_string();
        upsert_device(&conn, &d1).unwrap();

        let (nodes, _) = get_topology(&conn, 3600).unwrap();
        let router = nodes
            .iter()
            .find(|n| n.id == "dev:aa:bb:cc:00:00:01")
            .unwrap();
        assert_eq!(router.node_type, "router");
    }

    // --- Device stats tests ---

    #[test]
    fn test_get_device_stats_totals() {
        let conn = setup();
        let d1 = make_device("aa:bb:cc:00:00:01", Some("192.168.1.10"));
        let id = upsert_device(&conn, &d1).unwrap();

        insert_recent_flow(
            &conn,
            "f1",
            "192.168.1.10",
            "8.8.8.8",
            "DNS",
            None,
            100,
            200,
        );
        insert_recent_flow(
            &conn,
            "f2",
            "192.168.1.10",
            "1.1.1.1",
            "TLS",
            None,
            5000,
            10000,
        );

        let stats = get_device_stats(&conn, id).unwrap();
        assert_eq!(stats.device_id, id);
        assert_eq!(stats.total_bytes_sent, 5100);
        assert_eq!(stats.total_bytes_received, 10200);
        assert_eq!(stats.flow_count, 2);
    }

    #[test]
    fn test_get_device_stats_protocol_breakdown() {
        let conn = setup();
        let d1 = make_device("aa:bb:cc:00:00:01", Some("192.168.1.10"));
        let id = upsert_device(&conn, &d1).unwrap();

        insert_recent_flow(
            &conn,
            "f1",
            "192.168.1.10",
            "8.8.8.8",
            "DNS",
            None,
            100,
            200,
        );
        insert_recent_flow(
            &conn,
            "f2",
            "192.168.1.10",
            "1.1.1.1",
            "TLS",
            None,
            5000,
            10000,
        );

        let stats = get_device_stats(&conn, id).unwrap();
        assert_eq!(stats.protocol_breakdown.len(), 2);
        // TLS should be first (most bytes)
        assert_eq!(stats.protocol_breakdown[0].protocol, "TLS");
        assert!(stats.protocol_breakdown[0].percentage > 90.0);
    }

    #[test]
    fn test_get_device_stats_empty() {
        let conn = setup();
        let d1 = make_device("aa:bb:cc:00:00:01", Some("192.168.1.10"));
        let id = upsert_device(&conn, &d1).unwrap();

        let stats = get_device_stats(&conn, id).unwrap();
        assert_eq!(stats.flow_count, 0);
        assert_eq!(stats.total_bytes_sent, 0);
        assert!(stats.protocol_breakdown.is_empty());
    }

    #[test]
    fn test_get_device_stats_counts_as_dst() {
        let conn = setup();
        let d1 = make_device("aa:bb:cc:00:00:01", Some("192.168.1.10"));
        let d2 = make_device("aa:bb:cc:00:00:02", Some("192.168.1.20"));
        let id1 = upsert_device(&conn, &d1).unwrap();
        upsert_device(&conn, &d2).unwrap();

        // d2 sends to d1 — d1 is dst
        insert_recent_flow(
            &conn,
            "f1",
            "192.168.1.20",
            "192.168.1.10",
            "TCP",
            None,
            500,
            300,
        );

        let stats = get_device_stats(&conn, id1).unwrap();
        assert_eq!(
            stats.flow_count, 1,
            "device should appear in stats as dst too"
        );
    }

    // --- History query tests ---

    #[test]
    fn test_query_history_returns_recent() {
        let conn = setup();
        let d1 = make_device("aa:bb:cc:00:00:01", Some("192.168.1.10"));
        upsert_device(&conn, &d1).unwrap();

        insert_recent_flow(
            &conn,
            "f1",
            "192.168.1.10",
            "8.8.8.8",
            "DNS",
            Some("dns.google"),
            100,
            200,
        );

        let results = query_history(
            &conn,
            None,
            "2020-01-01 00:00:00",
            "2099-12-31 23:59:59",
            100,
        )
        .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["flow_key"], "f1");
    }

    #[test]
    fn test_query_history_filters_by_device() {
        let conn = setup();
        let d1 = make_device("aa:bb:cc:00:00:01", Some("192.168.1.10"));
        let d2 = make_device("aa:bb:cc:00:00:02", Some("192.168.1.20"));
        let id1 = upsert_device(&conn, &d1).unwrap();
        upsert_device(&conn, &d2).unwrap();

        insert_recent_flow(
            &conn,
            "f1",
            "192.168.1.10",
            "8.8.8.8",
            "DNS",
            None,
            100,
            200,
        );
        insert_recent_flow(
            &conn,
            "f2",
            "192.168.1.20",
            "1.1.1.1",
            "TLS",
            None,
            500,
            1000,
        );

        let results = query_history(
            &conn,
            Some(id1),
            "2020-01-01 00:00:00",
            "2099-12-31 23:59:59",
            100,
        )
        .unwrap();
        assert_eq!(results.len(), 1, "should only return flows for device 1");
        assert_eq!(results[0]["flow_key"], "f1");
    }

    #[test]
    fn test_query_history_respects_time_range() {
        let conn = setup();
        // Insert one old flow and one recent
        conn.execute(
            "INSERT INTO flow_summaries
                (flow_key, src_ip, dst_ip, protocol, bytes_sent, bytes_received,
                 packet_count, first_seen, last_seen)
             VALUES ('old', '1.1.1.1', '2.2.2.2', 'TCP', 100, 200, 5,
                     '2020-06-15 00:00:00', '2020-06-15 00:00:00')",
            [],
        )
        .unwrap();
        insert_recent_flow(&conn, "recent", "1.1.1.1", "3.3.3.3", "DNS", None, 50, 50);

        let results = query_history(
            &conn,
            None,
            "2020-06-01 00:00:00",
            "2020-07-01 00:00:00",
            100,
        )
        .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["flow_key"], "old");
    }

    #[test]
    fn test_query_history_respects_limit() {
        let conn = setup();
        for i in 0..10 {
            insert_recent_flow(
                &conn,
                &format!("f{}", i),
                "1.1.1.1",
                "2.2.2.2",
                "TCP",
                None,
                100,
                100,
            );
        }

        let results =
            query_history(&conn, None, "2020-01-01 00:00:00", "2099-12-31 23:59:59", 3).unwrap();
        assert_eq!(results.len(), 3, "should respect limit");
    }

    #[test]
    fn test_query_history_joins_device_info() {
        let conn = setup();
        let mut d1 = make_device("aa:bb:cc:00:00:01", Some("192.168.1.10"));
        d1.display_name = Some("My iPhone".to_string());
        upsert_device(&conn, &d1).unwrap();

        insert_recent_flow(
            &conn,
            "f1",
            "192.168.1.10",
            "8.8.8.8",
            "DNS",
            None,
            100,
            200,
        );

        let results = query_history(
            &conn,
            None,
            "2020-01-01 00:00:00",
            "2099-12-31 23:59:59",
            100,
        )
        .unwrap();
        assert_eq!(results[0]["src_device"]["display_name"], "My iPhone");
        assert_eq!(results[0]["src_device"]["mac_address"], "aa:bb:cc:00:00:01");
    }
}
