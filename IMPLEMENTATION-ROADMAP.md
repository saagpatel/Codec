# Codec — Implementation Roadmap

## Architecture

### System Overview

```
[Home Network Devices]
        |
        | (raw ethernet frames, promiscuous mode)
        ↓
[codec-helper binary]                      — runs as root via LaunchDaemon
  ├── libpcap (pcap crate) → packet capture loop
  ├── pnet → ARP spoofing engine (opt-in toggle)
  ├── Protocol Decoders: DNS, TLS-SNI, HTTP, mDNS, DHCP
  ├── Flow Aggregator (in-memory HashMap, 2s flush cadence)
  └── Unix domain socket server → pushes FlowBatch JSON

        |
        | (Unix socket at /tmp/codec-helper.sock, newline-delimited JSON)
        ↓
[codec Tauri backend]                      — runs as logged-in user
  ├── helper_client.rs → socket reader, deserializes FlowBatch
  ├── rusqlite → upserts flow_summaries + devices to ~/.codec/codec.db
  ├── device_registry.rs → OUI lookup, mDNS/DHCP identification, user overrides
  └── Tauri event emitter → fires "flow-update" event to frontend

        |
        | (Tauri IPC events + invoke() commands)
        ↓
[React Frontend]
  ├── Zustand flowStore → live FlowSummary[] state
  ├── Zustand deviceStore → Device[] registry
  ├── ConversationView → live timeline, device↔service threads
  ├── TopologyView → D3 force-directed graph (SVG)
  ├── DevicePanel → device list, rename, icon, visibility
  └── HistoryPanel → query past flows via Tauri invoke()
```

---

### File Structure

```
codec/
├── src-tauri/
│   ├── src/
│   │   ├── main.rs                          # Tauri app entry, registers all commands
│   │   ├── models.rs                        # Shared Rust structs: FlowEntry, DeviceEntry, FlowBatch, CaptureStats
│   │   ├── commands/
│   │   │   ├── mod.rs
│   │   │   ├── flows.rs                     # get_recent_flows, query_history, get_topology
│   │   │   └── settings.rs                  # get_settings, update_setting, rename_device, update_device_icon, toggle_device_visibility
│   │   ├── capture/
│   │   │   ├── mod.rs
│   │   │   ├── helper_client.rs             # Unix socket client, reconnecting reader, fires Tauri events
│   │   │   ├── flow_table.rs                # Arc<Mutex<HashMap<String, FlowEntry>>> — in-memory live state
│   │   │   └── device_registry.rs           # OUI HashMap, device identification pipeline, user override lookup
│   │   └── db/
│   │       ├── mod.rs
│   │       ├── schema.rs                    # SQLite schema, PRAGMA user_version migrations
│   │       └── queries.rs                   # upsert_flow, upsert_device, query_history, purge_old_flows
│   ├── helper/                              # Separate binary — DO NOT merge into main process
│   │   ├── src/
│   │   │   ├── main.rs                      # Entry point: starts socket server + capture loop
│   │   │   ├── capture.rs                   # libpcap interface, packet loop, mpsc channel
│   │   │   ├── aggregator.rs                # Flow table, 2s flush, FlowBatch serialization to socket
│   │   │   ├── arp_spoof.rs                 # pnet ARP reply crafting, IP forwarding toggle via sysctl
│   │   │   └── decoder/
│   │   │       ├── mod.rs
│   │   │       ├── dns.rs                   # UDP port 53: query/response parsing, IP→hostname cache
│   │   │       ├── tls.rs                   # TCP port 443: ClientHello SNI extraction via nom
│   │   │       ├── http.rs                  # TCP port 80: method, URL, status parsing
│   │   │       ├── mdns.rs                  # UDP port 5353: PTR record parsing, device type hints
│   │   │       └── dhcp.rs                  # UDP ports 67/68: option 12 (hostname), option 61 (client ID)
│   │   └── Cargo.toml
│   ├── Cargo.toml                           # Workspace root — both binaries
│   └── tauri.conf.json
├── src/                                     # React frontend
│   ├── main.tsx
│   ├── App.tsx                              # Root: reads storage, renders active view, subscribes to Tauri events
│   ├── types/
│   │   └── index.ts                         # All shared TypeScript interfaces (source of truth)
│   ├── store/
│   │   ├── flowStore.ts                     # Zustand: FlowSummary[], merges delta updates
│   │   └── deviceStore.ts                   # Zustand: Device[], handles user overrides optimistically
│   ├── components/
│   │   ├── ConversationView/
│   │   │   ├── ConversationView.tsx         # Timeline container, groups flows by (src_device, service_name)
│   │   │   ├── ConversationThread.tsx       # Expandable thread: device icon, service name, protocol badge
│   │   │   └── MessageBubble.tsx            # Single flow entry: summary_text, timestamp, bytes
│   │   ├── TopologyView/
│   │   │   ├── TopologyView.tsx             # SVG container, calls useForceGraph hook
│   │   │   ├── useForceGraph.ts             # D3 lifecycle: init simulation, update nodes/links on store change
│   │   │   └── NodeTooltip.tsx              # Hover tooltip: device name, IP, bytes today
│   │   ├── DevicePanel/
│   │   │   ├── DevicePanel.tsx              # Sidebar device list
│   │   │   └── DeviceRow.tsx                # Inline rename, icon picker, visibility toggle
│   │   ├── HistoryPanel/
│   │   │   └── HistoryPanel.tsx             # Date range + device filter, calls get_history Tauri command
│   │   └── shared/
│   │       ├── StatusBar.tsx                # Bottom bar: capture status dot, pps, active flows, device count
│   │       └── ProtocolBadge.tsx            # Colored badge: DNS / TLS / HTTP / mDNS / DHCP
│   └── lib/
│       ├── tauri.ts                         # Typed wrappers: invoke<T>(), listenFlowUpdate()
│       └── formatters.ts                    # flow → summary_text, bytes → human-readable, ms → "2s ago"
├── assets/
│   ├── oui.csv                              # Bundled IEEE OUI database (~6MB, updated per release)
│   └── GeoLite2-Country.mmdb                # MaxMind GeoIP (Phase 3 only — anomaly detection)
├── scripts/
│   ├── install-helper.sh                    # Copies helper binary, writes LaunchDaemon plist, loads it
│   └── grant-bpf.sh                         # Fallback: sudo chmod 644 /dev/bpf*
├── package.json
├── tsconfig.json
├── tailwind.config.js
├── CLAUDE.md
└── IMPLEMENTATION-ROADMAP.md
```

---

### Data Model

```sql
-- ~/.codec/codec.db
-- PRAGMA user_version = 1  (increment on schema changes)

CREATE TABLE flow_summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_key TEXT NOT NULL,              -- "{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT NOT NULL,             -- "DNS"|"TLS"|"HTTP"|"mDNS"|"DHCP"|"TCP"|"UDP"
    service_name TEXT,                  -- Human-readable: "iCloud", "Netflix", "weather.apple.com"
    src_device_id INTEGER REFERENCES devices(id),
    dst_device_id INTEGER REFERENCES devices(id),
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    packet_count INTEGER DEFAULT 0,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    summary_text TEXT,                  -- "iPhone → iCloud: Syncing (HTTPS, 2.4MB)"
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_flow_last_seen ON flow_summaries(last_seen DESC);
CREATE INDEX idx_flow_device ON flow_summaries(src_device_id, last_seen DESC);
CREATE INDEX idx_flow_key ON flow_summaries(flow_key);

CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT UNIQUE NOT NULL,   -- "aa:bb:cc:dd:ee:ff"
    ip_address TEXT,
    hostname TEXT,                      -- DHCP option 12 or mDNS
    oui_manufacturer TEXT,              -- From bundled OUI CSV
    device_type TEXT DEFAULT 'Unknown', -- "iPhone"|"Mac"|"SmartTV"|"IoT"|"Router"|"Unknown"
    display_name TEXT,                  -- User override; NULL = fallback to hostname → OUI → mac
    icon TEXT DEFAULT 'device',         -- Icon key: "phone"|"laptop"|"tv"|"speaker"|"camera"|"router"|"iot"|"device"
    is_visible INTEGER DEFAULT 1,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    notes TEXT
);
CREATE INDEX idx_device_mac ON devices(mac_address);
CREATE INDEX idx_device_ip ON devices(ip_address);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
-- Seed on first launch:
INSERT OR IGNORE INTO settings VALUES ('arp_spoof_enabled', 'false', CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO settings VALUES ('capture_interface', 'auto', CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO settings VALUES ('history_retention_days', '7', CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO settings VALUES ('update_cadence_ms', '2000', CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO settings VALUES ('capture_active', 'false', CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO settings VALUES ('onboarding_complete', 'false', CURRENT_TIMESTAMP);
```

---

### Rust Type Definitions

```rust
// src-tauri/src/models.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEntry {
    pub flow_key: String,               // "{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub service_name: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packet_count: u64,
    pub first_seen: i64,                // Unix timestamp ms
    pub last_seen: i64,
    pub summary_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub mac_address: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub oui_manufacturer: Option<String>,
    pub device_type: String,
    pub display_name: Option<String>,
    pub icon: String,
    pub is_visible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStats {
    pub packets_per_second: f64,
    pub active_flows: usize,
    pub total_devices: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowBatch {
    pub timestamp: i64,
    pub new_flows: Vec<FlowEntry>,
    pub updated_flows: Vec<FlowEntry>,
    pub device_updates: Vec<DeviceEntry>,
    pub stats: CaptureStats,
}

// Topology shapes (serialized for frontend)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyNode {
    pub id: String,                     // device mac or service name
    pub label: String,
    pub node_type: String,              // "device"|"service"|"router"
    pub device: Option<DeviceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub source: String,                 // node id
    pub target: String,
    pub protocol: String,
    pub bytes: u64,
    pub active: bool,                   // last_seen within 10s
}
```

### TypeScript Type Definitions

```typescript
// src/types/index.ts

export type Protocol = 'DNS' | 'TLS' | 'HTTP' | 'mDNS' | 'DHCP' | 'TCP' | 'UDP';
export type DeviceType = 'iPhone' | 'Mac' | 'SmartTV' | 'IoT' | 'Router' | 'Unknown';
export type IconKey = 'phone' | 'laptop' | 'tv' | 'speaker' | 'camera' | 'router' | 'iot' | 'device';

export interface Device {
  id: number;
  mac_address: string;
  ip_address: string | null;
  hostname: string | null;
  oui_manufacturer: string | null;
  device_type: DeviceType;
  display_name: string | null;          // UI: display_name ?? hostname ?? oui_manufacturer ?? mac_address
  icon: IconKey;
  is_visible: boolean;
  first_seen: string;                   // ISO datetime
  last_seen: string;
}

export interface FlowSummary {
  id: number;
  flow_key: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: Protocol;
  service_name: string | null;
  src_device: Device | null;
  dst_device: Device | null;
  bytes_sent: number;
  bytes_received: number;
  packet_count: number;
  first_seen: string;
  last_seen: string;
  summary_text: string;
}

// Delta payload pushed from backend every 2 seconds via Tauri event "flow-update"
export interface FlowBatch {
  timestamp: string;
  new_flows: FlowSummary[];
  updated_flows: FlowSummary[];         // Merge by flow_key into existing store state
  device_updates: Device[];
  stats: {
    packets_per_second: number;
    active_flows: number;
    total_devices: number;
  };
}

// D3 force graph shapes
export interface TopologyNode {
  id: string;                           // Device mac or service name
  label: string;
  type: 'device' | 'service' | 'router';
  device?: Device;
  x?: number;
  y?: number;
  fx?: number | null;                   // D3 fixed position on drag
  fy?: number | null;
}

export interface TopologyEdge {
  source: string;
  target: string;
  protocol: Protocol;
  bytes: number;
  active: boolean;
}

// Tauri command return shapes
export interface HistoryQuery {
  device_id?: number;
  start: string;                        // ISO datetime
  end: string;
}
```

---

### Dependencies

```toml
# src-tauri/helper/Cargo.toml
[package]
name = "codec-helper"
version = "0.1.0"
edition = "2021"

[dependencies]
pcap = "2.0"
pnet = "0.34"
pnet_macros_support = "0.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
dns-parser = "0.8"
nom = "7"
log = "0.4"
env_logger = "0.11"
```

```toml
# src-tauri/Cargo.toml
[workspace]
members = [".", "helper"]

[package]
name = "codec"
version = "0.1.0"
edition = "2021"

[dependencies]
tauri = { version = "2", features = [] }
rusqlite = { version = "0.31", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
log = "0.4"
env_logger = "0.11"
```

```bash
# Frontend
npm install zustand@4 d3@7 lucide-react
npm install -D @types/d3@7 tailwindcss postcss autoprefixer

# System (required for pcap crate to compile)
brew install libpcap
```

---

## Scope Boundaries

**In scope (v1):**
- Full subnet capture via libpcap + opt-in ARP spoofing
- Protocol decoding: DNS, TLS-SNI, HTTP, mDNS, DHCP
- Conversation view: live timeline of device↔service threads
- Topology graph: D3 force-directed, router + devices + services
- Device identification: OUI + mDNS + DHCP + user rename/icon
- 7-day flow history in SQLite, queryable by device + date range
- ARP spoof toggle with onboarding explanation
- macOS menu bar item
- Anomaly hints: new country, bandwidth spike, tracker domain

**Out of scope (v1):**
- TLS/HTTPS decryption — SNI only, no MITM
- VLAN / separate IoT network capture — Mac must be on the same subnet
- API-level decoding (e.g., "Alexa: voice command") — connection-level only
- Mac App Store distribution — open-source/GitHub only
- Windows or Linux support

**Deferred to v2:**
- Router-level capture via SSH + tcpdump
- Anomaly detection ML model
- Per-device traffic report cards (export/share)
- Plugin architecture for custom protocol decoders
- Blocklist integration (ad/tracker domain visualization)

---

## Security & Credentials

- **No credentials stored.** Codec makes no authenticated outbound API calls.
- **Privilege boundary:** `codec-helper` runs as root and owns all raw socket access. Main Tauri process runs as the logged-in user. The two communicate only via Unix domain socket at `/tmp/codec-helper.sock` (chmod 600, owned by current user).
- **Helper input validation:** All control messages from the main process (e.g., ARP spoof toggle) are validated against a strict allowlist — no shell exec, no arbitrary commands.
- **Data stored:** Metadata only — IPs, ports, protocols, SNI hostnames, DNS names, byte counts, device MACs. Zero payload content, zero packet bodies.
- **Database location:** `~/.codec/codec.db` — local only, no cloud sync, no telemetry.
- **Bundled databases:** `oui.csv` (IEEE, public domain), `GeoLite2-Country.mmdb` (MaxMind free tier — requires attribution in README), `hosts.txt` blocklist (Steven Black, MIT license).
- **ARP spoofing disclosure:** Opt-in only. Onboarding modal explains the behavior in plain English before the user can enable it. IP forwarding enabled before first ARP reply to prevent packet drops.

---

## Phase 0: Capture Engine + Privileged Helper (Weeks 1–2)

**Objective:** Privileged helper captures packets promiscuously, decodes DNS and TLS-SNI, aggregates flows, and delivers valid `FlowBatch` JSON to the main process over a Unix socket. No UI. Fully verifiable from CLI.

**Tasks:**

1. Scaffold Tauri 2 Cargo workspace with two binaries: `codec` (main) and `codec-helper` (helper). Confirm both compile.
   **Acceptance:** `cargo build --workspace` succeeds with zero errors. `npm run tauri dev` launches an empty Tauri window.

2. Implement Unix domain socket server in `helper/src/main.rs`. Server listens at `/tmp/codec-helper.sock`, accepts one client, sends a `{"type":"heartbeat"}` JSON line every 2 seconds.
   **Acceptance:** `nc -U /tmp/codec-helper.sock` receives heartbeat lines every ~2 seconds.

3. Implement libpcap capture loop in `helper/src/capture.rs`. Open default interface in promiscuous mode. Extract Ethernet → IP → TCP/UDP headers per packet. Push to mpsc channel.
   **Acceptance:** Running helper as root produces per-packet log lines to stderr within 3 seconds. Cross-check against Wireshark on same interface — packet counts within 5%.

4. Implement DNS decoder in `helper/src/decoder/dns.rs` using `dns-parser`. Parse UDP port 53 packets. Maintain `HashMap<IpAddr, String>` DNS cache. On A/AAAA responses, insert IP→hostname.
   **Acceptance:** After 30 seconds of capture, DNS cache has >10 entries. `RUST_LOG=debug ./codec-helper 2>&1 | grep dns_cache` confirms populated entries.

5. Implement TLS SNI decoder in `helper/src/decoder/tls.rs` using `nom`. Parse TCP port 443 payload: locate TLS record type `0x16`, parse ClientHello, extract SNI extension `(0x00, 0x00)`. Return hostname string.
   **Acceptance:** Opening any HTTPS URL on any device produces an SNI log entry. `grep "sni:" /tmp/codec-debug.log` returns matches.

6. Implement flow aggregator in `helper/src/aggregator.rs`. Maintain `Mutex<HashMap<String, FlowEntry>>`. Key = `"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"`. Update bytes/packets per packet. Every 2 seconds: compute delta (new vs updated entries since last flush), serialize as `FlowBatch` JSON, write to socket.
   **Acceptance:** Main process receives valid `FlowBatch` JSON lines every ~2 seconds. `echo "" | nc -U /tmp/codec-helper.sock | python3 -m json.tool` parses successfully. `new_flows` and `updated_flows` arrays populated correctly.

7. Implement `helper_client.rs` in main Tauri backend. Background Tokio task connects to `/tmp/codec-helper.sock`, reads newline-delimited JSON, deserializes to `FlowBatch`, fires Tauri event `"flow-update"` with payload.
   **Acceptance:** Add temporary `console.log` listener in frontend for `"flow-update"` — DevTools console shows `FlowBatch` objects arriving every ~2 seconds.

8. Write install scripts. `install-helper.sh`: copy helper binary to `/Library/PrivilegedHelperTools/com.codec.helper`, write LaunchDaemon plist to `/Library/LaunchDaemons/com.codec.helper.plist`, run `launchctl load`. `grant-bpf.sh`: `sudo chmod 644 /dev/bpf*`.
   **Acceptance:** After `install-helper.sh`, helper starts on next login without password prompt. Capture works without `sudo` in terminal.

**Verification checklist:**
- [ ] `cargo build --workspace` → zero errors, zero warnings
- [ ] `sudo ./target/debug/codec-helper` → packet logs visible within 3 seconds
- [ ] DNS cache after 60s: `grep "dns_cache size" /tmp/codec-debug.log | tail -1` → count >10
- [ ] TLS SNI: open `https://github.com` → `grep "github.com" /tmp/codec-debug.log` → match found
- [ ] `nc -U /tmp/codec-helper.sock | head -1 | python3 -m json.tool` → valid JSON, no parse errors
- [ ] `FlowBatch.new_flows` non-empty on first batch, `FlowBatch.updated_flows` non-empty after 10s
- [ ] Frontend DevTools console: `flow-update` events arriving every ~2s

**Risks:**
- BPF permission denied even after install script → run `scripts/grant-bpf.sh`, add UI error state with instructions
- `pcap` crate linker error on M4 → `brew install libpcap` + set `LIBPCAP_LIBDIR=$(brew --prefix libpcap)/lib`

---

## Phase 1: Tauri Backend + Conversation View (Weeks 3–5)

**Objective:** Tauri app persists flows to SQLite, identifies devices, and renders a live conversation view. ARP spoofing toggle operational for full subnet visibility.

**Tasks:**

1. Initialize SQLite at `~/.codec/codec.db` on first launch. Run schema from Data Model section. Use `PRAGMA user_version` for migration tracking. Seed settings table with defaults.
   **Acceptance:** `sqlite3 ~/.codec/codec.db ".schema"` shows all tables. Second launch doesn't error or duplicate tables.

2. Implement `queries.rs`: `upsert_flow(flow: &FlowEntry)` (INSERT OR REPLACE by flow_key), `upsert_device(device: &DeviceEntry)`, `purge_old_flows(retention_days: i64)` (DELETE WHERE last_seen < now - retention).
   **Acceptance:** After 5 minutes, `SELECT COUNT(*) FROM flow_summaries` > 20. After manually setting retention to 0 days and calling purge, count drops to 0.

3. Load `assets/oui.csv` into `HashMap<[u8;3], String>` in `device_registry.rs` at startup. For each new device MAC seen: parse first 3 bytes, lookup manufacturer, assign device type heuristic.
   **Acceptance:** `SELECT oui_manufacturer FROM devices` returns non-null values for Apple/Samsung/etc. devices. Startup time increase for OUI load < 2 seconds.

4. Implement mDNS decoder (`decoder/mdns.rs`): parse UDP port 5353 multicast, extract PTR records, feed device type hints to device registry (e.g., `_apple-mobdev2._tcp` → `iPhone`).
   **Acceptance:** At least one device in `devices` table has `device_type != 'Unknown'` after 2 minutes of capture.

5. Implement DHCP decoder (`decoder/dhcp.rs`): parse UDP 67/68, extract option 12 (hostname) from DHCP Request/ACK, feed to device registry.
   **Acceptance:** At least one device has non-null `hostname` in `devices` table.

6. Implement Tauri commands in `commands/flows.rs` and `commands/settings.rs`:
   - `get_recent_flows(limit: u32) -> Vec<FlowSummary>`
   - `get_devices() -> Vec<Device>`
   - `get_settings() -> HashMap<String, String>`
   - `update_setting(key: String, value: String) -> Result<(), String>`
   - `rename_device(id: i64, name: String) -> Result<(), String>`
   - `update_device_icon(id: i64, icon: String) -> Result<(), String>`
   - `toggle_device_visibility(id: i64, visible: bool) -> Result<(), String>`
   **Acceptance:** All commands callable from DevTools console via `window.__TAURI__.invoke()`. No errors. Return types match TypeScript interfaces.

7. Build Zustand stores. `flowStore.ts`: state = `FlowSummary[]`. On `"flow-update"` event: append `new_flows`, merge `updated_flows` by `flow_key`, trim to last 500 entries. `deviceStore.ts`: state = `Device[]`. On `"flow-update"` event: merge `device_updates` by `mac_address`.
   **Acceptance:** `useFlowStore.getState().flows.length` > 0 after 10 seconds in DevTools. Updating a flow that already exists replaces it (check by flow_key), doesn't duplicate.

8. Build `ConversationView`. Group `FlowSummary[]` from store by `(src_device?.mac_address ?? src_ip, service_name ?? dst_ip)` pair. Sort threads by `last_seen` desc. Show top 10 by default, "Show all" button reveals full list. Each `ConversationThread` shows: device icon (Lucide), device display name, service name, `ProtocolBadge`, `summary_text`, relative time. Expandable to show last 5 flow entries in that thread.
   **Acceptance:** App shows >5 live threads after 30 seconds. Threads update in-place (not re-appended) on new packets. Expanded thread shows multiple MessageBubbles. "Show all" reveals additional threads.

9. Implement ARP spoof engine in `helper/src/arp_spoof.rs`. Use `pnet` to craft ARP reply packets: advertise Mac's MAC as the router IP for all local devices. Enable IP forwarding via `sysctl -w net.inet.ip.forwarding=1` before sending first reply. Add control channel (second message type on existing socket): `{"type":"set_arp_spoof","enabled":true}`. Wire to `update_setting('arp_spoof_enabled', 'true')` Tauri command.
   **Acceptance:** After enabling ARP spoof in settings, devices other than the Mac appear in ConversationView within 60 seconds. Disabling stops new foreign-device flows.

**Verification checklist:**
- [ ] App launches → ConversationView visible within 3 seconds, no blank screen
- [ ] `window.__TAURI__.invoke('get_devices')` → non-empty array with manufacturer data
- [ ] `window.__TAURI__.invoke('get_recent_flows', {limit: 20})` → >10 flows
- [ ] ConversationView threads update without page refresh
- [ ] ARP spoof toggle ON → iOS/Android device traffic visible within 60 seconds
- [ ] `sqlite3 ~/.codec/codec.db "SELECT COUNT(*) FROM flow_summaries"` → >20 after 5 minutes
- [ ] Rename device via DevicePanel → restart app → name persists

**Risks:**
- ARP spoofing causes internet loss for other devices → enable IP forwarding BEFORE sending first ARP reply; test with one device before full subnet
- pnet raw socket permission → helper must run as root; verify `sysctl net.inet.ip.forwarding` is 1 before any ARP replies

---

## Phase 2: Topology Graph + History + Device Management (Weeks 6–8)

**Objective:** Force-directed topology graph renders live. 7-day history queryable by device. Device panel functional with rename, icon, visibility controls.

**Tasks:**

1. Implement `get_topology() -> (Vec<TopologyNode>, Vec<TopologyEdge>)` Tauri command. Derive from recent flows (last 60 seconds): devices → nodes, unique `service_name` values → service nodes, flows → edges. Edge `active = last_seen > now - 10s`. Edge `bytes = bytes_sent + bytes_received`.
   **Acceptance:** `invoke('get_topology')` returns >5 nodes and >5 edges after capture running. All node IDs unique. All edge source/target IDs exist in node list.

2. Build `useForceGraph.ts` hook. `useRef<SVGSVGElement>`. In `useEffect`: initialize `d3.forceSimulation()` with `d3.forceLink().id(d => d.id)`, `d3.forceManyBody().strength(-200)`, `d3.forceCenter(width/2, height/2)`. Subscribe to `flowStore` — on batch update, call `simulation.nodes(updatedNodes)` and `simulation.force('link').links(updatedEdges)`, then `simulation.alpha(0.1).restart()`. Nodes draggable via `d3.drag()`. Double-click device node → sets `flowStore.deviceFilter` to that device's mac.
   **Acceptance:** Graph renders. Nodes stabilize within 3 seconds of launch. Adding a new device (connect phone to wifi) produces new node within 4 seconds. Dragging nodes works. Double-click filters ConversationView.

3. Implement edge animation. Active edges (`active: true`) get CSS class `edge-active` with a `stroke-dasharray` + `stroke-dashoffset` animation (flowing dashes). Edge stroke-width proportional to `Math.log(bytes + 1)` clamped to [1, 8]px.
   **Acceptance:** Edges for currently active connections visually animate. Inactive edges are static. Bandwidth-heavy connections (video stream) have visibly thicker edges.

4. Build `NodeTooltip.tsx`. On `mouseover` SVG node: position a `div` at mouse coords showing device name, IP, MAC, manufacturer, total bytes in last 24h (queried from SQLite via `get_device_stats(mac, window: '24h')`).
   **Acceptance:** Hovering any node shows populated tooltip within 200ms. Tooltip disappears on `mouseout`.

5. Implement `query_history` Tauri command: `query_history(device_id: Option<i64>, start: String, end: String, limit: Option<u32>) -> Vec<FlowSummary>`. Queries `flow_summaries` with optional `src_device_id` filter and datetime range on `last_seen`. Default limit 500.
   **Acceptance:** Query for "last 24 hours, device X" returns results in <500ms (test with 50,000 row seed database). Result count matches `sqlite3` direct query.

6. Build `HistoryPanel.tsx`. Date range picker (two `<input type="date">` fields). Device dropdown (from `deviceStore`). "Query" button calls `query_history`. Results rendered as read-only ConversationThread list. "Clear" button resets filters.
   **Acceptance:** Select "yesterday" + a specific device → flows appear. Selecting no device returns all devices' flows for the range.

7. Build `DevicePanel.tsx` and `DeviceRow.tsx`. Device list sorted by `last_seen` desc. Inline rename: click name → `<input>`, blur/enter → `invoke('rename_device', {id, name})` → optimistic store update. Icon picker: 8-icon grid popover. Visibility toggle: eye icon → `invoke('toggle_device_visibility')` → hidden devices filtered from ConversationView and topology.
   **Acceptance:** Rename persists after app restart. Hidden devices absent from both views. Icon change persists.

8. Build `StatusBar.tsx`. Fixed bottom bar: green/red dot (capture_active setting), `{pps} pkt/s`, `{active_flows} flows`, `{total_devices} devices`, ARP mode indicator (orange when active). Updates every 2 seconds from `flowStore.stats`.
   **Acceptance:** Status bar always visible in both views. Numbers change every ~2 seconds. ARP indicator shows correctly.

**Verification checklist:**
- [ ] Topology graph renders >5 nodes without DevTools errors
- [ ] Graph stabilizes within 3 seconds of launch
- [ ] Active edge animations visible when a device is actively streaming
- [ ] History query: "last 7 days" returns results in <500ms (verify with sqlite3 `EXPLAIN QUERY PLAN`)
- [ ] Rename → restart → name persists in both ConversationView and TopologyView
- [ ] Hidden device: toggle visibility off → device disappears from both views immediately
- [ ] StatusBar numbers update every ~2 seconds

**Risks:**
- D3 force simulation CPU usage in Tauri WebView → profile on M4 at 50 nodes; if >30% CPU, reduce `forceManyBody` strength and increase `alphaDecay`
- SQLite query performance at 50k rows → ensure `idx_flow_device` and `idx_flow_last_seen` indexes exist; use `EXPLAIN QUERY PLAN` to verify

---

## Phase 3: Polish + Open Source Prep (Weeks 9–10)

**Objective:** First-launch onboarding, anomaly detection hints, macOS menu bar integration, README/LICENSE. Ship-ready open-source release.

**Tasks:**

1. Build onboarding modal (shown when `onboarding_complete = 'false'`). 3-step wizard: (1) what Codec does + privacy statement, (2) BPF permission grant (button runs `scripts/grant-bpf.sh` via `tauri::api::shell::Command`, shows success/fail), (3) ARP spoof opt-in with plain-English explanation + toggle. Completion sets `onboarding_complete = 'true'`.
   **Acceptance:** Fresh install shows wizard. Completing it starts capture. Subsequent launches skip wizard directly to ConversationView.

2. Implement anomaly detection in `aggregator.rs`. Per `FlowBatch` flush: (a) load `GeoLite2-Country.mmdb` at startup, check each flow's dst_ip — if country not seen before for this device, set `anomaly: 'new_country'`; (b) compare device's current minute bytes to 30-day average — if >10x, set `anomaly: 'bandwidth_spike'`; (c) check dst hostname against bundled `hosts.txt` blocklist (loaded into `HashSet<String>`) — if match, set `anomaly: 'tracker'`. Include `anomaly` field in `FlowEntry`.
   **Acceptance:** Connect a device to a known tracker domain from the blocklist → 🔒 badge appears in ConversationThread within 4 seconds. Test new-country detection by DNS lookup of a known CN-hosted domain.

3. Implement macOS menu bar via Tauri `SystemTray`. Items: "Show Codec" (toggle window), separator, "Start/Stop Capture" (toggle `capture_active` setting), separator, "{pps} pkt/s" (dynamic, updates every 5s), "Quit". Icon: red when capture off, green when on.
   **Acceptance:** App can be fully hidden (no Dock icon in LSUIElement mode) and controlled from menu bar. Quit from menu bar exits cleanly.

4. Write README.md. Sections: What it is (screenshots), How it works (plain English: ARP spoof explained), Install (build from source: prerequisites + `npm run tauri build`), Permissions (BPF setup), FAQ (privacy, ARP spoof ethics, VLAN limitations), Attribution (MaxMind, Steven Black blocklist, IEEE OUI).
   **Acceptance:** A developer unfamiliar with the project can build and run Codec from the README without asking questions. All bundled database attributions present.

5. Performance audit. Run capture for 30 minutes at 20 active devices. Check: RSS <200MB in Activity Monitor, ConversationView re-render time <16ms (React DevTools profiler), D3 graph frame rate >30fps, SQLite history query for 7 days <500ms.
   **Acceptance:** All 5 success metrics from Exec Summary pass. No memory growth trend visible over 30 minutes.

**Verification checklist:**
- [ ] Fresh install → onboarding wizard appears → completion starts capture
- [ ] ARP spoof toggle in onboarding correctly updates `arp_spoof_enabled` setting
- [ ] Known tracker domain connection → 🔒 badge within 4 seconds
- [ ] Menu bar present, start/stop capture toggles capture correctly
- [ ] RSS after 30 min capture session: `ps aux | grep codec | awk '{print $6}'` < 200MB
- [ ] `npm run tauri build` → unsigned `.dmg` produced, app launches from it

---

## Open Questions — Resolved

| Question | Resolution |
|----------|-----------|
| VLAN / separate IoT network | Not in v1. Documented as known limitation. V2: SSH into router + tcpdump piped to Codec. |
| API-level decoding (e.g., "Alexa: voice command") | Not in v1. Connection-level only. V2: plugin architecture for protocol decoders as dylibs. |
| MIT vs GPL | MIT. Maximizes adoption. All dependencies (libpcap BSD, pnet MIT, rusqlite MIT) compatible. |
| First-launch with 50+ connections | Progressive disclosure: show top 10 threads by byte volume, "Show all" reveals rest. Topology starts device-only, toggle to expand service nodes. |
| ARP spoofing legality/ethics | Opt-in with disclosure. User explicitly enables on their own network. Documented in README FAQ. |
