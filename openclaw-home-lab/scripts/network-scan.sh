#!/usr/bin/env bash
#
# network-scan.sh — Verify firewall state and report open/listening ports
#
# Safe, read-only audit script. No packets sent to external hosts.
#
# Usage:
#   bash network-scan.sh
#
# Author: Vincent Phan
# License: MIT

set -euo pipefail

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

echo "========================================"
echo "OpenClaw Home Lab — Network Audit"
echo "========================================"
echo

# 1. Firewall status
log "Checking macOS Application Firewall..."
if sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q "enabled"; then
    log "  Firewall: ENABLED"
else
    log "  Firewall: DISABLED (WARNING)"
fi

if sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | grep -q "enabled"; then
    log "  Stealth Mode: ENABLED"
else
    log "  Stealth Mode: DISABLED (WARNING)"
fi

# 2. Listening ports
log "Checking listening ports..."
if command -v lsof >/dev/null 2>&1; then
    # List only IPv4/IPv6 listening ports
    lsof -iTCP -sTCP:LISTEN -P -n | grep -E "^(COMMAND|[0-9])" || true
else
    log "  lsof not found — skipping port scan"
fi

# 3. Loopback-only verification for OpenClaw
log "Verifying OpenClaw gateway binding..."
if lsof -i :18789 | grep -q "LISTEN"; then
    bind_addr=$(lsof -i :18789 | grep LISTEN | awk '{print $9}' | head -1)
    if echo "$bind_addr" | grep -q "127.0.0.1"; then
        log "  Gateway: LISTENING on 127.0.0.1:18789 (GOOD)"
    else
        log "  Gateway: LISTENING on $bind_addr (WARNING — not loopback-only)"
    fi
else
    log "  Gateway: NOT LISTENING (expected if not running)"
fi

# 4. Active connections (outbound summary)
log "Outbound connection summary..."
if command -v netstat >/dev/null 2>&1; then
    # macOS netstat: count established connections by foreign port
    netstat -an -p tcp 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | cut -d. -f5 | sort | uniq -c | sort -rn | head -10 || true
else
    log "  netstat not available"
fi

# 5. Wi-Fi / physical interface
log "Primary network interface..."
iface=$(route -n get default 2>/dev/null | grep interface | awk '{print $2}' || echo "unknown")
if [[ "$iface" != "unknown" ]]; then
    ip_addr=$(ipconfig getifaddr "$iface" 2>/dev/null || echo "unavailable")
    log "  Interface: $iface"
    log "  IP Address: $ip_addr"
else
    log "  Unable to determine primary interface"
fi

# 6. DNS servers
log "DNS configuration..."
if command -v scutil >/dev/null 2>&1; then
    scutil --dns | grep nameserver | head -5 || true
else
    log "  scutil not available"
fi

echo
log "Audit complete."
