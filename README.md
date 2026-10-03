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
- Node.js 20.19+ or 22.12+ and npm
- macOS (uses pcap + privileged network helper)

### Installation
```bash
git clone https://github.com/saagpatel/Codec
cd Codec
npm ci
```

### Usage
```bash
# Development (normal user; live helper/capture setup is separate)
npm run tauri dev

# Build release app
npm run tauri build
```

## Verification

Run from the repository root on macOS with Rust stable, developer tools,
libpcap for the helper, and Node.js 20.19+ or 22.12+ (the locked Vite engine
requirement). The canonical local commands are in
[`.codex/verify.commands`](.codex/verify.commands):

```bash
npm ci
npm run build
cargo test --locked --manifest-path src-tauri/Cargo.toml
# Focused example: temporary SQLite database tests, without capture
cargo test --locked --manifest-path src-tauri/Cargo.toml db::
# Helper's packet/parser fixture tests, without launching its main function
cargo test --locked --manifest-path src-tauri/Cargo.toml -p codec-helper
```

Cargo tests use fixtures/temporary databases; they do not install or run the
helper. `npm test` currently prints a placeholder and is not a behavior test.
No JavaScript lint/format script is configured. Optional Rust checks are
`cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check` and
`cargo clippy --locked --manifest-path src-tauri/Cargo.toml --workspace -- -D warnings`;
existing warnings may require a separately scoped code change.

These gates do not require sudo, packet capture, ARP spoofing, a LaunchDaemon,
or helper installation. Run the main Tauri app as your normal user. Live
network capture/helper installation is a separate privileged operation and
must not be used as a routine verification step. For changed timeline, graph,
device panel or capture controls, check rendering with synthetic metadata in
the browser (`npm run dev`); native IPC/capture behavior needs its own explicitly
scoped evidence. Preserve existing device/flow databases.

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
