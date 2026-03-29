# Codec

[![Tauri 2](https://img.shields.io/badge/Tauri-2.x-blue?logo=tauri)](https://tauri.app)
[![Rust](https://img.shields.io/badge/Rust-1.78%2B-orange?logo=rust)](https://www.rust-lang.org)
[![React](https://img.shields.io/badge/React-18.x-61DAFB?logo=react)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript)](https://www.typescriptlang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A macOS ambient network awareness tool. Codec captures traffic on your local home network subnet and presents it as two synchronized views: a conversation timeline (devices talking to services, styled like a messaging app) and a live force-directed topology graph. Built for curious technical people who want a living window into what their devices are actually doing — not a security scanner, not a packet sniffer, just ambient clarity.

---

## Screenshot

> _Screenshot placeholder — add an image of the app running here._

---

## Features

- **Conversation timeline** — see each device's outbound connections as a message-thread metaphor, showing destination service, protocol, and byte volume
- **Force-directed topology graph** — D3-powered live graph of devices and the services they communicate with
- **Device registry** — OUI-based vendor identification combined with mDNS/DHCP hostname resolution; rename and customise device labels
- **7-day flow history** — aggregated flow summaries stored locally in SQLite; query past activity without storing any packet payloads
- **SNI extraction** — TLS ClientHello parsing gives service identity for HTTPS traffic without any MITM decryption
- **Protocol decoders** — DNS, TLS-SNI, HTTP, mDNS, and DHCP decoded in the privileged helper
- **ARP spoofing (opt-in)** — whole-subnet visibility toggle; off by default, explicitly enabled by the user

---

## Tech Stack

| Layer | Technology |
|---|---|
| Desktop shell | Tauri 2 |
| Frontend | React 18, TypeScript 5 (strict), Tailwind CSS 3 |
| State management | Zustand 4 |
| Graph visualisation | D3.js 7 (raw, no wrapper) |
| Rust backend | Tauri main process + separate `codec-helper` binary |
| Packet capture | libpcap via `pcap` crate |
| ARP spoofing | `pnet` 0.34 |
| Local storage | SQLite via `rusqlite` 0.31 (bundled) |

---

## Prerequisites

- **macOS** (required — uses macOS LaunchDaemon for the privileged helper)
- [Rust](https://rustup.rs) 1.78 or later
- [Node.js](https://nodejs.org) 20+ and npm
- [Xcode Command Line Tools](https://developer.apple.com/xcode/resources/) (`xcode-select --install`)
- `libpcap` — ships with macOS, no separate install needed

---

## Getting Started

```bash
# Install frontend dependencies
npm install

# Run in development mode (Tauri + Vite)
npm run tauri dev

# Build a production .app bundle
npm run tauri build
```

The privileged capture helper (`codec-helper`) runs as root via a LaunchDaemon. On first launch you will be prompted to install the helper — this requires administrator authorisation. The main Tauri process never runs as root.

---

## Project Structure

```
codec/
├── src/                        # React frontend
│   ├── App.tsx
│   ├── components/
│   │   ├── ConversationView/   # Device↔service timeline
│   │   └── shared/             # Reusable UI components
│   ├── store/                  # Zustand stores (flows, devices)
│   ├── types/                  # Shared TypeScript types
│   └── lib/                    # Utilities and formatters
└── src-tauri/
    ├── src/
    │   ├── main.rs             # Tauri entry point
    │   ├── models.rs           # Shared structs (FlowEntry, DeviceEntry, FlowBatch)
    │   ├── capture/            # Helper socket client, flow table, device registry
    │   ├── commands/           # Tauri IPC command handlers
    │   └── db/                 # SQLite schema and queries
    └── helper/                 # Privileged capture binary (runs as root)
        └── src/
            ├── capture.rs      # libpcap packet loop
            ├── aggregator.rs   # 2-second flow batch flush to Unix socket
            ├── arp_spoof.rs    # ARP reply engine (opt-in)
            └── decoder/        # DNS, TLS-SNI, HTTP, mDNS, DHCP parsers
```

---

## Privacy

Codec stores **metadata only** — no packet payloads, no TLS decryption, no raw packet logs. Flow summaries are kept for 7 days in a local SQLite database at `~/.codec/codec.db` and are never transmitted anywhere.

---

## License

MIT — see [LICENSE](LICENSE) for details.
