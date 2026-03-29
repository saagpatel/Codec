# Codec

[![Rust](https://img.shields.io/badge/rust-%23dea584?style=flat-square&logo=rust)](#) [![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](#)

> Not a packet sniffer, not a security scanner — just ambient clarity about what your devices are actually doing.

Codec captures traffic on your local home network subnet and presents it as two synchronized views: a conversation timeline (devices talking to services, styled like a messaging app) and a live force-directed topology graph. Built for curious technical people who want a living window into their home network.

## Features

- **Conversation timeline** — each device's outbound connections as a message-thread metaphor with destination service, protocol, and byte volume
- **Force-directed topology graph** — D3-powered live graph of devices and their service connections
- **Device registry** — OUI-based vendor identification + mDNS/DHCP hostname resolution with custom labels
- **7-day flow history** — aggregated flow summaries in local SQLite; no packet payloads stored
- **SNI extraction** — TLS ClientHello parsing for HTTPS service identity without MITM
- **Protocol decoders** — DNS, TLS-SNI, HTTP, mDNS, and DHCP
- **ARP spoofing (opt-in)** — whole-subnet visibility toggle, explicitly off by default

## Quick Start

### Prerequisites
- Rust stable toolchain
- Node.js 20+ and pnpm
- macOS (uses pcap + privileged network helper)

### Installation
```bash
git clone https://github.com/saagpatel/Codec
cd Codec
pnpm install
```

### Usage
```bash
# Development (requires sudo for pcap)
pnpm tauri dev

# Build release app
pnpm tauri build
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Desktop shell | Tauri 2 |
| Backend | Rust 2021 — tokio, rusqlite, privileged helper |
| Frontend | React 18 + TypeScript 5 + Tailwind CSS 3 + Zustand 4 |
| Graph | D3 force-directed layout |
| Persistence | SQLite (bundled rusqlite) |

## License

MIT
