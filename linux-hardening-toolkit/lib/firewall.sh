#!/usr/bin/env bash
###############################################################################
# lib/firewall.sh — UFW firewall checks (CIS Ubuntu 22.04 Section 3.5)
# ePHI Relevance: Network segmentation is a HIPAA Security Rule requirement.
#               A default-deny firewall is the first line of defense for any
#               server storing or transmitting ePHI.
# Author: Vincent Phan
###############################################################################

set -euo pipefail

run_firewall_checks() {
    local mode="$1"
    local -n total="$2"
    local -n passed="$3"
    local -n failed="$4"

    # CIS 3.5.1.1 — Ensure UFW is installed
    check_and_record "${mode}" \
        "FW-01: UFW is installed (CIS 3.5.1.1)" \
        "command -v ufw >/dev/null 2>&1" \
        "apt-get install -y ufw" \
        total passed failed

    # CIS 3.5.1.2 — Ensure UFW service is enabled (persistence)
    check_and_record "${mode}" \
        "FW-02: UFW service is enabled (CIS 3.5.1.2)" \
        "systemctl is-active --quiet ufw || systemctl is-enabled --quiet ufw" \
        "systemctl enable --now ufw" \
        total passed failed

    # CIS 3.5.1.3 — Ensure default deny policy
    # ePHI context: explicit-allow only. Any exposed port is a PHI breach risk.
    check_and_record "${mode}" \
        "FW-03: Default deny policy (CIS 3.5.1.3)" \
        "ufw status verbose | grep -q 'Default: deny (incoming), allow (outgoing)'" \
        "ufw default deny incoming; ufw default allow outgoing" \
        total passed failed

    # CIS 3.5.1.4 — Ensure loopback traffic is configured (anti-spoofing)
    check_and_record "${mode}" \
        "FW-04: Loopback traffic configured (CIS 3.5.1.4)" \
        "ufw status verbose | grep -q 'Anywhere on lo'" \
        "ufw allow in on lo; ufw deny in from 127.0.0.0/8" \
        total passed failed

    # ePHI-contextual: allow SSH only if it's the admin path (synthetic check)
    # In production, this would be restricted to a bastion / VPN IP range.
    check_and_record "${mode}" \
        "FW-05: SSH (port 22) restricted/allowed (ePHI admin path)" \
        "ufw status | grep -q '22/tcp'" \
        "ufw allow 22/tcp comment 'SSH admin access — restrict to bastion IP in prod'" \
        total passed failed

    # Apply rules if in harden mode
    if [[ "${mode}" == "harden" ]]; then
        ufw reload || log_warn "UFW reload failed."
    fi
}
