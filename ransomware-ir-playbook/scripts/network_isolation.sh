#!/usr/bin/env bash
# network_isolation.sh
# Rapid network segmentation for small business router/firewall during ransomware incident.
#
# Purpose:
#   Designed for pharmacy/small healthcare IT environments using common router platforms:
#   - pfSense / OPNsense (FreeBSD-based, pfctl)
#   - UniFi (USG/UDM, unifi-os shell / SSH)
#   - Generic Linux firewall (iptables / nftables)
#
#   Disables VPN interfaces, blocks outbound C2 ports, isolates IoT VLAN (pharmacy
#   temperature sensors), and preserves evidence VLAN access. Includes pre-flight
#   checks, rollback commands, and audit logging.
#
#   NOTE: This script detects the platform and runs the appropriate commands. If no
#   supported platform is detected, it falls back to iptables/nftables on Linux.
#
# Author: Vincent Phan (CPhT, Entry-level IT/Cybersecurity student)
# License: MIT
# Platform: Linux / BSD / macOS (with limitations)
# Requires: bash, standard POSIX utilities (ip, iptables, nft, pfctl, ssh, logger, date)

set -euo pipefail
IFS=$'\n\t'

# ──────────────────────────────────────────────────────────────────────────────
# Configuration & Constants
# ──────────────────────────────────────────────────────────────────────────────
readonly SCRIPT_NAME="network_isolation.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly AUTHOR="Vincent Phan (CPhT, CSUSB-bound IT/Cybersecurity student)"
readonly DISCLAIMER="SYNTHETIC / PORTFOLIO SCRIPT. Review and customize before production use."

# C2 / suspicious outbound ports to block immediately
readonly C2_PORTS=(
    443    # HTTPS (C2 often uses this — block selectively, whitelist known)
    8443   # Alt-HTTPS (common C2)
    8080   # HTTP proxy / C2
    4444   # Metasploit default
    5555   # Android ADB / common C2
    6666   # IRC / common C2
    6667   # IRC
    9999   # Common C2
    31337  # Classic backdoor
    12345  # NetBus
    12346  # NetBus
    23456  # EvilOSX
    47808  # Bacnet (IoT, sometimes abused)
)

# Known safe IPs / ranges to NEVER block (pharmacy-critical infrastructure)
# MODIFY THESE FOR YOUR ENVIRONMENT
readonly SAFE_IPS=(
    "127.0.0.0/8"       # Loopback
    "10.0.10.0/24"      # Corporate VLAN (pharmacy workstations)
    "10.0.20.0/24"      # Server VLAN (domain controller, EHR)
    "10.0.99.0/24"      # Evidence VLAN (forensic collector, isolated)
)

# VLAN / interface mapping (adjust for your router)
readonly VLAN_CORP="10.0.10.0/24"   # Pharmacy workstations
readonly VLAN_SERVERS="10.0.20.0/24" # Domain controller, EHR, billing
readonly VLAN_IOT="10.0.30.0/24"    # IoT: temperature sensors, humidity monitors
readonly VLAN_EVIDENCE="10.0.99.0/24" # Forensic evidence collection (preserve access)

# Log file
readonly LOGFILE="/var/log/ransomware_ir_isolation.log"
readonly ROLLBACK_SCRIPT="/tmp/network_isolation_rollback.sh"

# ──────────────────────────────────────────────────────────────────────────────
# Platform Detection
# ──────────────────────────────────────────────────────────────────────────────
detect_platform() {
    if [[ -f /etc/pfSense-rc ]] || [[ -f /etc/pfSense ]]; then
        echo "pfsense"
        return
    fi
    if [[ -f /etc/opnsense-rc ]] || [[ -f /etc/opnsense ]]; then
        echo "opnsense"
        return
    fi
    if [[ -f /usr/bin/ubnt-device-info ]] || [[ -f /usr/bin/ubnt-systool ]]; then
        echo "unifi"
        return
    fi
    if command -v iptables &>/dev/null; then
        echo "iptables"
        return
    fi
    if command -v nft &>/dev/null; then
        echo "nftables"
        return
    fi
    if command -v pfctl &>/dev/null; then
        echo "pfctl"
        return
    fi
    echo "unknown"
}

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
log_action() {
    local msg="$1"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "[$timestamp] $msg" | tee -a "$LOGFILE" 2>/dev/null || echo "[$timestamp] $msg"
    logger -t "$SCRIPT_NAME" "$msg" 2>/dev/null || true
}

# ──────────────────────────────────────────────────────────────────────────────
# Pre-flight Checks
# ──────────────────────────────────────────────────────────────────────────────
run_preflight() {
    log_action "=== PRE-FLIGHT CHECKS ==="

    # Check root / sudo
    if [[ $EUID -ne 0 ]]; then
        log_action "WARNING: Not running as root. Firewall changes may fail."
    fi

    # Check for internet connectivity (to verify we can still reach HHS/authorities if needed)
    if ping -c 1 -W 3 1.1.1.1 &>/dev/null; then
        log_action "PASS: Internet connectivity detected (1.1.1.1)."
    else
        log_action "WARNING: No internet connectivity. May already be isolated."
    fi

    # Check existing firewall state
    local platform
    platform=$(detect_platform)
    log_action "Detected platform: $platform"

    case "$platform" in
        pfsense|opnsense)
            if pfctl -sr &>/dev/null; then
                log_action "PASS: pfctl is responsive."
            else
                log_action "ERROR: pfctl not responsive. Aborting."
                exit 1
            fi
            ;;
        iptables)
            if iptables -L -n &>/dev/null; then
                log_action "PASS: iptables is responsive."
            else
                log_action "ERROR: iptables not responsive. Aborting."
                exit 1
            fi
            ;;
        nftables)
            if nft list ruleset &>/dev/null; then
                log_action "PASS: nftables is responsive."
            else
                log_action "ERROR: nftables not responsive. Aborting."
                exit 1
            fi
            ;;
        unifi)
            log_action "WARNING: UniFi platform detected. SSH to USG/UDM required."
            log_action "This script will generate UniFi CLI commands for manual execution."
            ;;
        pfctl)
            if pfctl -sr &>/dev/null; then
                log_action "PASS: pfctl (macOS/BSD) is responsive."
            else
                log_action "ERROR: pfctl not responsive. Aborting."
                exit 1
            fi
            ;;
        *)
            log_action "ERROR: No supported firewall platform detected. Cannot proceed safely."
            exit 1
            ;;
    esac

    # Backup current firewall state
    log_action "Backing up current firewall state..."
    case "$platform" in
        pfsense|opnsense|pfctl)
            pfctl -sr > "/tmp/pf_rules_backup_$(date +%Y%m%d_%H%M%S).txt" 2>/dev/null || true
            ;;
        iptables)
            iptables-save > "/tmp/iptables_backup_$(date +%Y%m%d_%H%M%S).txt" 2>/dev/null || true
            ;;
        nftables)
            nft list ruleset > "/tmp/nftables_backup_$(date +%Y%m%d_%H%M%S).txt" 2>/dev/null || true
            ;;
        unifi)
            log_action "UniFi: Generate rollback via UniFi Controller GUI or CLI."
            ;;
    esac
    log_action "PASS: Pre-flight complete."
}

# ──────────────────────────────────────────────────────────────────────────────
# Generate Rollback Script
# ──────────────────────────────────────────────────────────────────────────────
generate_rollback() {
    local platform
    platform=$(detect_platform)

    log_action "Generating rollback script: $ROLLBACK_SCRIPT"

    cat > "$ROLLBACK_SCRIPT" <<EOF
#!/usr/bin/env bash
# Auto-generated rollback script for $SCRIPT_NAME
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Platform: $platform
# WARNING: Review before execution. This restores pre-isolation firewall state.

set -euo pipefail

EOF

    case "$platform" in
        pfsense|opnsense)
            echo '# Rollback for pfSense/OPNsense' >> "$ROLLBACK_SCRIPT"
            echo '# Restore from backup: pfctl -f /tmp/pf_rules_backup_*.txt' >> "$ROLLBACK_SCRIPT"
            echo '# Or use pfSense GUI: Diagnostics > Backup & Restore' >> "$ROLLBACK_SCRIPT"
            ;;
        iptables)
            echo '# Rollback for iptables' >> "$ROLLBACK_SCRIPT"
            echo 'iptables -F' >> "$ROLLBACK_SCRIPT"
            echo 'iptables -X' >> "$ROLLBACK_SCRIPT"
            echo 'iptables -P INPUT ACCEPT' >> "$ROLLBACK_SCRIPT"
            echo 'iptables -P FORWARD ACCEPT' >> "$ROLLBACK_SCRIPT"
            echo 'iptables -P OUTPUT ACCEPT' >> "$ROLLBACK_SCRIPT"
            echo '# Restore from backup: iptables-restore < /tmp/iptables_backup_*.txt' >> "$ROLLBACK_SCRIPT"
            ;;
        nftables)
            echo '# Rollback for nftables' >> "$ROLLBACK_SCRIPT"
            echo 'nft flush ruleset' >> "$ROLLBACK_SCRIPT"
            echo '# Restore from backup: nft -f /tmp/nftables_backup_*.txt' >> "$ROLLBACK_SCRIPT"
            ;;
        unifi)
            echo '# UniFi rollback: Use controller GUI or SSH into USG/UDM' >> "$ROLLBACK_SCRIPT"
            ;;
        pfctl)
            echo '# Rollback for macOS/BSD pfctl' >> "$ROLLBACK_SCRIPT"
            echo 'sudo pfctl -d' >> "$ROLLBACK_SCRIPT"
            echo 'sudo pfctl -F all' >> "$ROLLBACK_SCRIPT"
            ;;
    esac

    chmod +x "$ROLLBACK_SCRIPT"
    log_action "PASS: Rollback script generated."
}

# ──────────────────────────────────────────────────────────────────────────────
# Isolation Actions
# ──────────────────────────────────────────────────────────────────────────────

isolate_iptables() {
    log_action "=== APPLYING iptables ISOLATION ==="

    # Create custom chain for IR isolation
    iptables -N RANSOMWARE_IR 2>/dev/null || iptables -F RANSOMWARE_IR

    # Block outbound C2 ports (TCP)
    for port in "${C2_PORTS[@]}"; do
        iptables -A RANSOMWARE_IR -p tcp --dport "$port" -j LOG --log-prefix "IR_BLOCK_C2:" 2>/dev/null || true
        iptables -A RANSOMWARE_IR -p tcp --dport "$port" -j DROP
        log_action "  Blocked outbound TCP port $port"
    done

    # Block UDP C2 ports (common: 53 DNS tunneling, 123 NTP amplification, 47808 Bacnet)
    iptables -A RANSOMWARE_IR -p udp --dport 53 -m limit --limit 10/min -j LOG --log-prefix "IR_DNS_TUNNEL:" 2>/dev/null || true
    iptables -A RANSOMWARE_IR -p udp --dport 53 -j DROP
    iptables -A RANSOMWARE_IR -p udp --dport 123 -j DROP
    iptables -A RANSOMWARE_IR -p udp --dport 47808 -j DROP
    log_action "  Blocked suspicious UDP ports (53, 123, 47808)"

    # Isolate IoT VLAN (VLAN 30) — block all outbound except to evidence VLAN
    iptables -A RANSOMWARE_IR -s "$VLAN_IOT" -d "$VLAN_EVIDENCE" -j ACCEPT
    iptables -A RANSOMWARE_IR -s "$VLAN_IOT" -d "$VLAN_SERVERS" -j DROP
    iptables -A RANSOMWARE_IR -s "$VLAN_IOT" -d "$VLAN_CORP" -j DROP
    iptables -A RANSOMWARE_IR -s "$VLAN_IOT" -j LOG --log-prefix "IR_IOT_ISOLATE:" 2>/dev/null || true
    iptables -A RANSOMWARE_IR -s "$VLAN_IOT" -j DROP
    log_action "  Isolated IoT VLAN ($VLAN_IOT) — no outbound except evidence VLAN"

    # Allow evidence VLAN to communicate everywhere (for forensics)
    iptables -A RANSOMWARE_IR -s "$VLAN_EVIDENCE" -j ACCEPT
    log_action "  Preserved evidence VLAN access ($VLAN_EVIDENCE)"

    # Block inbound from external to IoT VLAN
    iptables -A RANSOMWARE_IR -d "$VLAN_IOT" -m state --state NEW -j DROP
    log_action "  Blocked inbound new connections to IoT VLAN"

    # Disable VPN interfaces (if tun0, tun1, wg0, etc. exist)
    for iface in tun0 tun1 tun2 wg0 wg1 ppp0; do
        if ip link show "$iface" &>/dev/null; then
            iptables -A RANSOMWARE_IR -o "$iface" -j DROP
            log_action "  Blocked outbound via VPN interface: $iface"
        fi
    done

    # Insert RANSOMWARE_IR chain into OUTPUT and FORWARD
    iptables -I OUTPUT 1 -j RANSOMWARE_IR
    iptables -I FORWARD 1 -j RANSOMWARE_IR

    log_action "PASS: iptables isolation applied."
}

isolate_nftables() {
    log_action "=== APPLYING nftables ISOLATION ==="

    # Create a table for IR isolation
    nft add table inet ransomware_ir 2>/dev/null || true
    nft flush table inet ransomware_ir 2>/dev/null || true

    # Add chain
    nft add chain inet ransomware_ir isolate { type filter hook forward priority 0 \; }
    nft add chain inet ransomware_ir isolate_output { type filter hook output priority 0 \; }

    # Block C2 ports
    for port in "${C2_PORTS[@]}"; do
        nft add rule inet ransomware_ir isolate tcp dport "$port" drop
        nft add rule inet ransomware_ir isolate_output tcp dport "$port" drop
    done
    nft add rule inet ransomware_ir isolate udp dport 53 drop
    nft add rule inet ransomware_ir isolate udp dport 123 drop
    nft add rule inet ransomware_ir isolate udp dport 47808 drop
    log_action "  Blocked C2 ports via nftables"

    # Isolate IoT VLAN
    nft add rule inet ransomware_ir isolate ip saddr "$VLAN_IOT" ip daddr "$VLAN_SERVERS" drop
    nft add rule inet ransomware_ir isolate ip saddr "$VLAN_IOT" ip daddr "$VLAN_CORP" drop
    nft add rule inet ransomware_ir isolate ip saddr "$VLAN_IOT" drop
    log_action "  Isolated IoT VLAN via nftables"

    # Preserve evidence VLAN
    nft add rule inet ransomware_ir isolate ip saddr "$VLAN_EVIDENCE" accept
    log_action "  Preserved evidence VLAN via nftables"

    log_action "PASS: nftables isolation applied."
}

isolate_pfsense() {
    log_action "=== APPLYING pfSense/OPNsense ISOLATION ==="
    log_action "WARNING: pfSense/OPNsense CLI changes are complex. Generating commands for manual execution."

    # Generate pfSense command list for admin to run via GUI or SSH
    local cmdfile="/tmp/pfsense_isolation_commands.txt"
    cat > "$cmdfile" <<EOF
# pfSense / OPNsense Isolation Commands
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Run these via pfSense GUI (Firewall > Rules) or SSH

# 1. Disable all VPN interfaces (Interfaces > Assignments, check disabled)
#    Interfaces: WAN, LAN, CORP, SERVERS, IOT, EVIDENCE, VPN_*

# 2. Add firewall rules on IOT interface (VLAN 30):
#    Action: Block
#    Protocol: Any
#    Source: $VLAN_IOT
#    Destination: $VLAN_SERVERS
#    Description: IR_ISOLATE_IOT_TO_SERVERS

#    Action: Block
#    Protocol: Any
#    Source: $VLAN_IOT
#    Destination: $VLAN_CORP
#    Description: IR_ISOLATE_IOT_TO_CORP

#    Action: Block
#    Protocol: Any
#    Source: $VLAN_IOT
#    Destination: any
#    Description: IR_ISOLATE_IOT_OUTBOUND

#    Action: Pass
#    Protocol: Any
#    Source: $VLAN_EVIDENCE
#    Destination: any
#    Description: IR_PRESERVE_EVIDENCE

# 3. Add outbound block rules on WAN:
#    Action: Block
#    Protocol: TCP
#    Source: any
#    Destination: any
#    Destination Port Range: 4444, 5555, 6666, 6667, 9999, 31337, 12345, 12346, 23456, 8443
#    Description: IR_BLOCK_C2_PORTS

# 4. Apply changes and reload filter
EOF
    log_action "PASS: pfSense commands written to $cmdfile"
}

isolate_unifi() {
    log_action "=== APPLYING UniFi ISOLATION ==="
    log_action "WARNING: UniFi isolation requires SSH into USG/UDM or controller CLI."

    local cmdfile="/tmp/unifi_isolation_commands.txt"
    cat > "$cmdfile" <<EOF
# UniFi Isolation Commands
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Run via SSH to USG/UDM or UniFi Controller (Settings > Routing & Firewall)

# 1. Disable VPN interfaces (if any):
#    configure
#    delete interfaces wireguard wg0
#    commit
#    save
#    exit

# 2. Add firewall rules on IoT network (VLAN 30):
#    configure
#    set firewall name IOT_IN default-action drop
#    set firewall name IOT_IN rule 10 action drop
#    set firewall name IOT_IN rule 10 description "IR_BLOCK_IOT_TO_SERVERS"
#    set firewall name IOT_IN rule 10 destination address $VLAN_SERVERS
#    set firewall name IOT_IN rule 20 action drop
#    set firewall name IOT_IN rule 20 description "IR_BLOCK_IOT_TO_CORP"
#    set firewall name IOT_IN rule 20 destination address $VLAN_CORP
#    commit
#    save
#    exit

# 3. Add firewall rules on EVIDENCE network (VLAN 99):
#    configure
#    set firewall name EVIDENCE_IN default-action accept
#    commit
#    save
#    exit

# 4. Block outbound C2 ports on WAN_IN:
#    configure
#    set firewall name WAN_IN rule 100 action drop
#    set firewall name WAN_IN rule 100 description "IR_BLOCK_C2_PORTS"
#    set firewall name WAN_IN rule 100 protocol tcp
#    set firewall name WAN_IN rule 100 destination port 4444,5555,6666,6667,9999,31337,12345,12346,23456,8443
#    commit
#    save
#    exit
EOF
    log_action "PASS: UniFi commands written to $cmdfile"
}

isolate_pfctl_macos() {
    log_action "=== APPLYING macOS pfctl ISOLATION ==="
    log_action "WARNING: macOS pfctl is limited. This blocks outbound C2 ports only."

    # Enable pf
    sudo pfctl -e 2>/dev/null || true

    # Create anchor file
    local anchor="/tmp/ransomware_ir_anchor"
    cat > "$anchor" <<EOF
# Ransomware IR Anchor — macOS pfctl
# Block outbound C2 ports
$(for port in "${C2_PORTS[@]}"; do echo "block drop out proto tcp to any port $port"; done)
EOF

    sudo pfctl -a ransomware_ir -f "$anchor" 2>/dev/null || {
        log_action "WARNING: Could not load pf anchor. macOS SIP may prevent this."
    }

    log_action "PASS: macOS pfctl isolation applied (limited)."
}

# ──────────────────────────────────────────────────────────────────────────────
# Main Execution
# ──────────────────────────────────────────────────────────────────────────────
main() {
    echo "========================================"
    echo "  RANSOMWARE NETWORK ISOLATION SCRIPT"
    echo "  $SCRIPT_NAME v$SCRIPT_VERSION"
    echo "  $AUTHOR"
    echo "========================================"
    echo ""
    echo "DISCLAIMER: $DISCLAIMER"
    echo ""
    echo "This script will:"
    echo "  1. Run pre-flight checks"
    echo "  2. Backup current firewall rules"
    echo "  3. Generate a rollback script"
    echo "  4. Apply isolation rules:"
    echo "     - Block suspicious outbound C2 ports"
    echo "     - Isolate IoT VLAN (temperature sensors)"
    echo "     - Preserve evidence VLAN access"
    echo "     - Disable VPN interfaces"
    echo ""

    if [[ "${1:-}" == "--rollback" ]]; then
        if [[ -f "$ROLLBACK_SCRIPT" ]]; then
            log_action "Executing rollback script..."
            bash "$ROLLBACK_SCRIPT"
            log_action "Rollback complete."
        else
            echo "[-] Rollback script not found: $ROLLBACK_SCRIPT"
            exit 1
        fi
        return
    fi

    if [[ "${1:-}" != "--yes" ]]; then
        read -r -p "Continue? Type 'yes' to proceed: " confirm
        if [[ "$confirm" != "yes" ]]; then
            echo "[-] Aborted by user."
            exit 0
        fi
    fi

    # Ensure log directory exists
    mkdir -p "$(dirname "$LOGFILE")"

    log_action "=== RANSOMWARE IR ISOLATION STARTED ==="
    log_action "Author: $AUTHOR"
    log_action "Version: $SCRIPT_VERSION"
    log_action "Platform: $(detect_platform)"

    run_preflight
    generate_rollback

    local platform
    platform=$(detect_platform)

    case "$platform" in
        iptables)
            isolate_iptables
            ;;
        nftables)
            isolate_nftables
            ;;
        pfsense|opnsense)
            isolate_pfsense
            ;;
        unifi)
            isolate_unifi
            ;;
        pfctl)
            isolate_pfctl_macos
            ;;
        *)
            log_action "ERROR: Cannot isolate — unsupported platform."
            exit 1
            ;;
    esac

    log_action "=== ISOLATION COMPLETE ==="
    log_action "Rollback script: $ROLLBACK_SCRIPT"
    log_action "Log file: $LOGFILE"
    log_action ""
    log_action "NEXT STEPS:"
    log_action "  1. Verify evidence VLAN ($VLAN_EVIDENCE) is accessible."
    log_action "  2. Check that IoT VLAN ($VLAN_IOT) is fully isolated."
    log_action "  3. Run analyze_logs.py and check_iocs.py on evidence systems."
    log_action "  4. Run hipaa_notification_calculator.py for notification deadlines."
    log_action "  5. To rollback: $0 --rollback"
    log_action ""

    echo ""
    echo "[+] Isolation complete."
    echo "    Log: $LOGFILE"
    echo "    Rollback: $ROLLBACK_SCRIPT"
    echo "    Run '$0 --rollback' to revert."
}

# ──────────────────────────────────────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────────────────────────────────────
main "$@"
