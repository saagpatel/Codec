#!/bin/bash
set -euo pipefail

# Remove the codec-helper LaunchDaemon and binary.
# Usage: sudo ./scripts/uninstall-helper.sh

HELPER_DST="/Library/PrivilegedHelperTools/com.codec.helper"
PLIST_DST="/Library/LaunchDaemons/com.codec.helper.plist"
SOCKET_PATH="/tmp/codec-helper.sock"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

echo "Unloading LaunchDaemon..."
launchctl unload "$PLIST_DST" 2>/dev/null || true

echo "Removing files..."
rm -f "$HELPER_DST"
rm -f "$PLIST_DST"
rm -f "$SOCKET_PATH"
rm -f /tmp/codec-helper.log

echo "Done. Helper service removed."
