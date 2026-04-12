#!/bin/bash
set -euo pipefail

# Install codec-helper as a macOS LaunchDaemon (runs as root)
# Usage: sudo ./scripts/install-helper.sh

HELPER_SRC="${1:-src-tauri/target/debug/codec-helper}"
HELPER_DST="/Library/PrivilegedHelperTools/com.codec.helper"
PLIST_DST="/Library/LaunchDaemons/com.codec.helper.plist"
SOCKET_PATH="/tmp/codec-helper.sock"
LOG_DIR="/Library/Logs/com.codec.helper"
LOG_PATH="${LOG_DIR}/codec-helper.log"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

if [ ! -f "$HELPER_SRC" ]; then
    echo "Error: Helper binary not found at $HELPER_SRC"
    echo "Build it first: cd src-tauri && cargo build -p codec-helper"
    exit 1
fi

# Stop existing service if running
if launchctl list | grep -q com.codec.helper; then
    echo "Stopping existing helper service..."
    launchctl unload "$PLIST_DST" 2>/dev/null || true
fi

# Create log directory with restricted permissions (root-only, not world-readable)
echo "Creating log directory at $LOG_DIR..."
mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR"
chown root:wheel "$LOG_DIR"

# Install binary
echo "Installing helper binary to $HELPER_DST..."
mkdir -p "$(dirname "$HELPER_DST")"
cp "$HELPER_SRC" "$HELPER_DST"
chmod 755 "$HELPER_DST"
chown root:wheel "$HELPER_DST"

# Write LaunchDaemon plist
echo "Writing LaunchDaemon plist..."
cat > "$PLIST_DST" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.codec.helper</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/PrivilegedHelperTools/com.codec.helper</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/com.codec.helper/codec-helper.log</string>
    <key>StandardOutPath</key>
    <string>/Library/Logs/com.codec.helper/codec-helper.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
</dict>
</plist>
PLIST

chmod 644 "$PLIST_DST"
chown root:wheel "$PLIST_DST"

# Load the service
echo "Loading LaunchDaemon..."
launchctl load -w "$PLIST_DST"

echo "Done. Helper service is running."
echo "Check status: sudo launchctl list | grep codec"
echo "Check logs: sudo tail -f $LOG_PATH"
echo "Test socket: nc -U $SOCKET_PATH"
