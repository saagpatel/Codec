#!/bin/bash
set -euo pipefail

# Grant read access to BPF devices for packet capture without root.
# Note: This resets on reboot. For persistent access, use the LaunchDaemon.
# Usage: sudo ./scripts/grant-bpf.sh

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

echo "Opening BPF devices for read access..."
chmod 644 /dev/bpf*
echo "Done. BPF devices are now readable by all users."
echo "Note: This resets on reboot. Use install-helper.sh for persistent access."
