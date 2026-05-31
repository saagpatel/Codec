# Codec Codex Playbook

## Communication Contract

Follow the global Codex communication contract. Keep updates short, PM-readable, operator-grade, and focused on what changed, what passed, and what still needs attention.

## Project Goal

Codec is a macOS Tauri 2 app for local home-network awareness. It captures local subnet traffic through a privileged helper, stores only flow metadata locally, and presents device conversations plus a live topology graph.

## First Read

- `README.md`
- `CLAUDE.md`
- `IMPLEMENTATION-ROADMAP.md`
- `src-tauri/Cargo.toml`
- `.codex/verify.commands`

## Core Rules

- Treat packet capture, ARP spoofing, helper installation, and LaunchDaemon behavior as security-sensitive.
- Keep the privileged helper separate from the main Tauri process; the main app must not run as root.
- Do not store, log, or render raw packet payloads.
- Do not attempt TLS decryption or MITM behavior; SNI and DNS metadata are the intended boundary.
- Keep flow updates batched as Rust-owned metadata deltas, not raw packet streams into React.
- Use raw D3 for the topology graph; do not add a graph wrapper library.

## Codex App Usage

- Use Codex App Projects for repo-scoped implementation, debugging, and verification.
- Use Worktrees for capture, helper, ARP spoofing, database, D3 topology, Tauri capability, or security-sensitive changes.
- Use file search before editing because behavior spans Rust capture/database code, Tauri IPC/events, Zustand stores, and React views.
- Use app-window or browser evidence when conversation timeline, topology graph, device panel, or capture controls change.
- Use durable artifacts only for reusable traffic-analysis notes or handoffs that need to survive outside chat.

## Verification

Use `.codex/verify.commands` as the canonical local gate. Current session note: Rust tests pass, while JavaScript build requires Node dependencies to be installed first.

## Done Criteria

- The relevant verifier commands have been run, or the exact blocker is recorded.
- Capture/helper changes have explicit evidence that privileges did not broaden.
- UI graph/timeline changes have visual evidence when behavior matters.
