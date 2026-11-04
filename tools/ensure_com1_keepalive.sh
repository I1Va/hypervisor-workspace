#!/usr/bin/env bash
# Ensure the COM1 keepalive is running on the DTB.
#
# Windows power-gates the legacy serial port when idle. Once that happens every
# COM1 register reads 0xFF and the hypervisor's debug log goes silent. Holding a
# handle open keeps the device in D0, which restores the log within a heartbeat.
#
# The scheduled task registered on the guest never fired (AutoAdminLogon is
# disabled, and the boot trigger did not run either), so this is driven from the
# harness instead: call it after every boot, before running anything that might
# wedge the machine. That makes it deterministic and independent of Task
# Scheduler.
#
# Usage: tools/ensure_com1_keepalive.sh
set -u

HOST="192.168.3.67"
USER_NAME="Арсений"
PASS="user"
SSH_OPTS=(-p 22 -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Push the latest copies: the guest keeps its own, and they must match.
sshpass -p "$PASS" scp "${SSH_OPTS[@]}" \
    "$HERE/com1_keepalive.ps1" "$HERE/com1_launch.ps1" \
    "$USER_NAME@$HOST:C:/Users/$USER_NAME/" >/dev/null 2>&1

# Start it, then report whether the port is actually held.
sshpass -p "$PASS" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" \
    "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\$USER_NAME\\com1_launch.ps1" 2>/dev/null
