# Codec — Demo Checklist

A runnable walkthrough from a clean checkout to a working live-network-awareness demo.
Each step has a command, an expected result, and a quick "if it fails" pointer.

> **Audience:** anyone who wants to verify Codec works end-to-end on their own machine,
> demo it to someone else, or capture a baseline before changes.

---

## 0. Prerequisites

- macOS (Codec is macOS-only; libpcap + LaunchDaemon dependencies)
- Rust toolchain (`rustc`, `cargo`), Node 20+, pnpm, Xcode CLI tools
- Admin (sudo) password — required to install the privileged helper

```bash
rustc --version          # 1.80+ expected
node --version           # v20+ expected
pnpm --version           # 9+ expected
xcode-select -p          # /Applications/Xcode.app/... or /Library/Developer/CommandLineTools
```

**If it fails:** install missing toolchain via `mise install`, `brew install pnpm`,
or `xcode-select --install`.

---

## 1. Build the Rust workspace

```bash
cd /Users/d/Projects/Codec/src-tauri
cargo check --workspace
```

**Expected:** zero errors. Warnings are OK if they are not new (compare against the
last green commit).

**If it fails:**
- Check `Cargo.lock` is current (the v1.0.0 bump at commit `ee130cb`).
- `cargo clean && cargo check` if dependency resolution looks stale.

---

## 2. Run baseline Rust tests

```bash
cd /Users/d/Projects/Codec/src-tauri
cargo test --workspace
```

**Expected:** the baseline tests added in commit `f5c69e4` pass (db queries, device
registry, schema).

**If it fails:** look at the test name. DB tests use a temp file under `/tmp`; if a
prior crashed run left junk, `rm -rf /tmp/codec-test-*`.

---

## 3. Build the React frontend

```bash
cd /Users/d/Projects/Codec
npm install              # one-time per clean checkout
npm run build
```

**Expected:** Vite output in `dist/` with no TypeScript errors. Bundle includes the
topology graph, conversation view, device panel, and history panel.

**If it fails:**
- `npm install` should match the canonical `.codex/verify.commands` gate.
- `pnpm install --frozen-lockfile` to verify lockfile parity.
- If types fail, `pnpm run dev` shows live errors with file:line citations.

---

## 4. Install the privileged helper

The helper is a separate binary that runs as root via a LaunchDaemon. The main
Tauri app does NOT run as root — that's the security boundary.

```bash
cd /Users/d/Projects/Codec/src-tauri
cargo build -p codec-helper

cd /Users/d/Projects/Codec
# Run the installer from an administrator shell.
./scripts/install-helper.sh
```

**Expected:** `launchctl list | grep com.codec.helper` shows the daemon as running
(PID, not status code 0 alone).

**If it fails:**
- Run `scripts/uninstall-helper.sh` from an administrator shell, then re-run
  `scripts/install-helper.sh` to reset state.
- Check `Console.app` for `codec-helper` log lines — common errors are missing
  pcap permission or wrong interface name.

---

## 5. Confirm the helper socket

```bash
ls -la /tmp/codec-helper.sock
nc -U /tmp/codec-helper.sock < /dev/null | head -1
```

**Expected:** Unix domain socket exists; reading it yields newline-delimited JSON
`FlowBatch` messages (or nothing if no traffic yet).

**If it fails:** helper isn't running or the socket path differs. Re-check Step 4.

---

## 6. Start the Tauri app in dev mode

```bash
cd /Users/d/Projects/Codec
pnpm tauri dev
```

**Expected:**
- Webview window opens
- Frontend connects to `/tmp/codec-helper.sock` within ~2 seconds
- Console shows `helper_client: connected` log
- Devices begin appearing in the **Device Panel** within ~10 seconds of normal home
  traffic (DHCP, mDNS, DNS)

**If it fails:**
- Check `~/.codec/codec.db` exists and is writable.
- If the webview shows blank, check Content Security Policy (commit `b31edd0`); some
  dev-mode HMR can violate the strict policy.

---

## 7. Walk the four primary views

### 7a. Device Panel
- Visible devices list themselves with OUI-resolved vendor name (e.g., "Apple,
  Inc.", "Google LLC")
- Devices identified via mDNS show a friendly hostname (`Living-Room-TV.local`)
- Devices identified via DHCP option 12 show the DHCP-supplied hostname
- Rename / icon / visibility controls work and persist after app restart

### 7b. Conversation View
- Each device shows a thread of `device ↔ service` conversations
- TLS conversations show the SNI (e.g., `api.openai.com`), NOT decrypted payload
- DNS conversations show resolved hostnames
- HTTP conversations show method + path (e.g., `GET /api/v1/health`)

### 7c. Topology View
- D3 force-directed graph
- Devices are nodes; conversations are edges
- Edges thicken with sustained traffic; idle edges fade
- Pan + zoom work; no graph-wrapper library was used (raw D3 per project rule)

### 7d. History Panel
- Queries past flows via Tauri `invoke()`
- Time-range filter applied at the SQLite layer
- Empty state shows when no history is available

**If any view fails:** open DevTools (View menu in Tauri dev), check the relevant
Zustand store value, then check whether the corresponding Rust command emits the
event.

---

## 8. Verify the security boundary

```bash
# 1. Codec app process should NOT be root
ps aux | grep -i codec.app | grep -v grep | awk '{print $1}'
# Expected: your username, NOT 'root'

# 2. Helper IS root
ps aux | grep codec-helper | grep -v grep | awk '{print $1}'
# Expected: 'root'

# 3. No raw payloads in the database
sqlite3 ~/.codec/codec.db "SELECT name FROM sqlite_master WHERE type='table';"
# Expected: flow_summaries, devices, settings — NOT a 'packets' or 'payloads' table

# 4. Content Security Policy is strict
grep -i csp /Users/d/Projects/Codec/src-tauri/tauri.conf.json
# Expected: a Content-Security-Policy field (added in commit b31edd0)
```

---

## 9. Clean shutdown

```bash
# Quit the Tauri app (Cmd-Q)
./scripts/uninstall-helper.sh
ls /tmp/codec-helper.sock     # should be gone
```

**Expected:** socket removed, helper stopped, main app exited cleanly. Database is
preserved.

---

## 10. Demo screencap (optional)

A 60-second screencap of the running app makes a portfolio artifact. Suggested
sequence: open with Device Panel populated → switch to Conversation View → click into
one device's thread → switch to Topology View → demonstrate pan/zoom → end on
History Panel showing a 1-hour window.

Save to `docs/media/codec-demo.mp4` and reference it from `README.md`.

---

## Build-proof source of truth

This checklist mirrors the build proof captured at commits:

- `f5c69e4` — baseline Rust tests
- `ee130cb` — Cargo.lock v1.0.0
- `b31edd0` — CSP for Tauri webview
- `7d91b77` — frontend: topology + device panel + history panel

If a step regresses, bisect against these commits.

## Fresh proof log

Use this section for the latest handoff-ready evidence.

- Local baseline gate: run `.codex/verify.commands` from the repo root and record
  the date plus result.
- Privileged helper gate: run Steps 4-6 on the demo Mac with admin approval and
  record whether `com.codec.helper`, `/tmp/codec-helper.sock`, and the Tauri
  `helper_client: connected` log were observed.
- Live subnet gate: leave capture running for at least 60 seconds, then record
  whether Device Panel, Conversation View, Topology View, and History Panel all
  received fresh data.
- Boundary check: record the Step 8 result before calling the demo ready.

Latest Codex pass: local build/test baseline can be verified without elevation;
privileged helper install and live subnet capture still require an operator-run
administrator session on the target Mac.
