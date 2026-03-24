# Codec

## Overview
Codec is a macOS desktop app that captures all traffic on the local home network subnet and presents it as two synchronized views: a conversation timeline (devices talking to services, styled like a messaging app) and a live force-directed topology graph. Built for curious technical people who want a living window into what their devices are actually doing. Not a security tool — an ambient awareness tool.

## Tech Stack
- Tauri: 2.x — desktop shell, IPC bridge between Rust and React
- React: 18.x — hooks-based frontend, no class components
- TypeScript: 5.x strict mode — all shared types in `src/types/index.ts`
- Rust: 1.78+ — two binaries: `codec` (main Tauri process) and `codec-helper` (privileged capture)
- SQLite via rusqlite: 0.31 (bundled) — local history at `~/.codec/codec.db`
- D3.js: 7.x — force simulation for topology graph, raw (no wrapper library)
- Zustand: 4.x — frontend state for live flows and device registry
- libpcap via `pcap` crate: 2.x — packet capture
- pnet: 0.34 — raw sockets for ARP spoofing
- Tailwind CSS: 3.x — all styling, utility classes only

## Development Conventions
- TypeScript strict mode: no `any` types, no `as` casts except in D3 DOM selections
- File naming: kebab-case for files, PascalCase for React components
- Rust: `clippy` clean before each phase commit, `unwrap()` only in tests
- Git commits: conventional commits — `feat:`, `fix:`, `chore:`, `refactor:`
- Unit tests: required for all Rust decoders and all TypeScript formatters before phase completion
- Error handling: all `window.storage` (if used) and Tauri `invoke()` calls wrapped in try/catch

## Current Phase
**Phase 0: Capture Engine + Privileged Helper**
See IMPLEMENTATION-ROADMAP.md for full phase details, tasks, and acceptance criteria.

## Key Decisions
| Decision | Choice | Why |
|----------|--------|-----|
| Capture scope | Whole home subnet via ARP spoofing | Full network visibility is the core value prop |
| ARP spoof | Opt-in toggle, off by default | Ethical disclosure; user explicitly enables |
| Privileged helper | LaunchDaemon + Unix domain socket | Standard macOS pattern; main app never runs as root |
| Flow update cadence | 2-second delta batches | Balances real-time feel with IPC overhead |
| History storage | Aggregated flow summaries, 7-day retention | No raw packets stored; metadata only |
| OUI database | Bundled at build time (~6MB) | No runtime network dependency |
| D3 | Raw D3 v7, no wrapper library | Wrapper libraries fight D3's mutation model |
| License | MIT | Maximizes adoption; all dependencies compatible |
| TLS handling | SNI extraction only, no MITM decryption | Privacy-respecting; SNI gives service identity |

## Do NOT
- Do not run `codec-helper` as part of the main Tauri process — it must be a separate binary running as root via LaunchDaemon
- Do not push raw packets to the React frontend — aggregate into FlowBatch deltas in Rust, push every 2 seconds
- Do not store or log payload content — metadata and SNI hostnames only, no packet bodies
- Do not use localStorage or sessionStorage — Tauri IPC commands for all persistence
- Do not use a D3 wrapper library (react-force-graph, etc.) — use raw D3 v7 with useRef + useEffect
- Do not attempt TLS decryption — SNI from ClientHello + DNS resolution is sufficient
- Do not add features not in the current phase of IMPLEMENTATION-ROADMAP.md
- Do not scaffold the entire project in one session — build phase by phase, verify each
