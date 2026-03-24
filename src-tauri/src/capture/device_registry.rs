use std::collections::HashMap;
use std::path::Path;

/// Load the IEEE OUI database from a CSV file.
///
/// Expected format: Registry,Assignment,Organization Name,Organization Address
/// Assignment is a 6-char hex string (e.g., "A4B1C1") representing the first 3 bytes of a MAC.
pub fn load_oui(path: &Path) -> HashMap<[u8; 3], String> {
    let mut db = HashMap::new();

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Failed to load OUI database from {}: {}", path.display(), e);
            return db;
        }
    };

    for (i, line) in content.lines().enumerate() {
        if i == 0 {
            continue; // Skip header
        }

        // Parse CSV: Registry,Assignment,Organization Name,...
        let fields: Vec<&str> = line.splitn(4, ',').collect();
        if fields.len() < 3 {
            continue;
        }

        let hex = fields[1].trim();
        if hex.len() != 6 {
            continue;
        }

        let Ok(b0) = u8::from_str_radix(&hex[0..2], 16) else {
            continue;
        };
        let Ok(b1) = u8::from_str_radix(&hex[2..4], 16) else {
            continue;
        };
        let Ok(b2) = u8::from_str_radix(&hex[4..6], 16) else {
            continue;
        };

        let org_name = fields[2].trim().trim_matches('"').to_string();
        if !org_name.is_empty() {
            db.insert([b0, b1, b2], org_name);
        }
    }

    db
}

/// Look up the manufacturer for a MAC address string like "aa:bb:cc:dd:ee:ff".
pub fn lookup_manufacturer(oui_db: &HashMap<[u8; 3], String>, mac: &str) -> Option<String> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() < 3 {
        return None;
    }

    let b0 = u8::from_str_radix(parts[0], 16).ok()?;
    let b1 = u8::from_str_radix(parts[1], 16).ok()?;
    let b2 = u8::from_str_radix(parts[2], 16).ok()?;

    oui_db.get(&[b0, b1, b2]).cloned()
}

/// Infer device type and icon from manufacturer name and optional hostname.
/// Returns (device_type, icon).
pub fn infer_device_type(manufacturer: Option<&str>, hostname: Option<&str>) -> (String, String) {
    let mfr = manufacturer.unwrap_or("").to_lowercase();
    let host = hostname.unwrap_or("").to_lowercase();

    // Check hostname for TV indicators combined with TV manufacturer
    if (host.contains("tv") || host.contains("samsung"))
        && (mfr.contains("samsung") || mfr.contains("lg") || mfr.contains("sony"))
    {
        return ("SmartTV".to_string(), "tv".to_string());
    }

    if mfr.contains("apple") {
        return ("Mac".to_string(), "laptop".to_string());
    }

    if mfr.contains("samsung")
        || mfr.contains("oneplus")
        || mfr.contains("xiaomi")
        || mfr.contains("huawei")
        || mfr.contains("oppo")
        || mfr.contains("vivo")
        || mfr.contains("google") && host.contains("pixel")
    {
        return ("iPhone".to_string(), "phone".to_string());
    }

    if mfr.contains("amazon") {
        return ("IoT".to_string(), "speaker".to_string());
    }

    if mfr.contains("google") || mfr.contains("nest") {
        return ("IoT".to_string(), "speaker".to_string());
    }

    if mfr.contains("tp-link")
        || mfr.contains("netgear")
        || mfr.contains("asus")
        || mfr.contains("ubiquiti")
        || mfr.contains("cisco")
        || mfr.contains("arris")
        || mfr.contains("motorola")
    {
        return ("Router".to_string(), "router".to_string());
    }

    if mfr.contains("sonos") || mfr.contains("bose") {
        return ("IoT".to_string(), "speaker".to_string());
    }

    ("Unknown".to_string(), "device".to_string())
}

/// Enrich a DeviceEntry with OUI manufacturer and inferred device type.
pub fn enrich_device(oui_db: &HashMap<[u8; 3], String>, device: &mut crate::models::DeviceEntry) {
    if device.oui_manufacturer.is_none() {
        device.oui_manufacturer = lookup_manufacturer(oui_db, &device.mac_address);
    }

    let (device_type, icon) = infer_device_type(
        device.oui_manufacturer.as_deref(),
        device.hostname.as_deref(),
    );

    // Only override if the device type is still Unknown
    if device.device_type == "Unknown" {
        device.device_type = device_type;
        device.icon = icon;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_known_mac() {
        let mut db = HashMap::new();
        db.insert([0xA4, 0xB1, 0xC1], "Apple, Inc.".to_string());

        assert_eq!(
            lookup_manufacturer(&db, "a4:b1:c1:dd:ee:ff"),
            Some("Apple, Inc.".to_string())
        );
    }

    #[test]
    fn lookup_unknown_mac() {
        let db: HashMap<[u8; 3], String> = HashMap::new();
        assert!(lookup_manufacturer(&db, "ff:ff:ff:00:00:00").is_none());
    }

    #[test]
    fn lookup_invalid_mac_format() {
        let db: HashMap<[u8; 3], String> = HashMap::new();
        assert!(lookup_manufacturer(&db, "invalid").is_none());
        assert!(lookup_manufacturer(&db, "").is_none());
    }

    #[test]
    fn infer_apple_device() {
        let (dt, icon) = infer_device_type(Some("Apple, Inc."), None);
        assert_eq!(dt, "Mac");
        assert_eq!(icon, "laptop");
    }

    #[test]
    fn infer_samsung_phone() {
        let (dt, icon) = infer_device_type(Some("Samsung Electronics"), None);
        assert_eq!(dt, "iPhone"); // generic phone type
        assert_eq!(icon, "phone");
    }

    #[test]
    fn infer_router() {
        let (dt, icon) = infer_device_type(Some("TP-Link Technologies"), None);
        assert_eq!(dt, "Router");
        assert_eq!(icon, "router");
    }

    #[test]
    fn infer_unknown() {
        let (dt, icon) = infer_device_type(None, None);
        assert_eq!(dt, "Unknown");
        assert_eq!(icon, "device");
    }

    #[test]
    fn enrich_device_sets_manufacturer() {
        let mut db = HashMap::new();
        db.insert([0xAA, 0xBB, 0xCC], "Apple, Inc.".to_string());

        let mut device = crate::models::DeviceEntry {
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            ip_address: Some("192.168.1.10".to_string()),
            hostname: None,
            oui_manufacturer: None,
            device_type: "Unknown".to_string(),
            display_name: None,
            icon: "device".to_string(),
            is_visible: true,
        };

        enrich_device(&db, &mut device);
        assert_eq!(device.oui_manufacturer.as_deref(), Some("Apple, Inc."));
        assert_eq!(device.device_type, "Mac");
        assert_eq!(device.icon, "laptop");
    }
}
