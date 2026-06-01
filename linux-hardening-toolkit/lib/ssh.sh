#!/usr/bin/env bash
###############################################################################
# lib/ssh.sh — SSH hardening checks (CIS Ubuntu 22.04 Section 5.2)
# ePHI Relevance: SSH is the primary administrative path to ePHI servers.
#               Compromised SSH = full ePHI access. Every control here
#               maps to a real breach vector seen in healthcare ransomware.
# Author: Vincent Phan
###############################################################################

set -euo pipefail

SSH_CONFIG="/etc/ssh/sshd_config"

run_ssh_checks() {
    local mode="$1"
    local -n total="$2"
    local -n passed="$3"
    local -n failed="$4"

    # CIS 5.2.1 — Ensure SSH Protocol is 2 (prevents protocol downgrade)
    check_and_record "${mode}" \
        "SSH-01: SSH Protocol is 2 (CIS 5.2.1)" \
        "grep -qE '^Protocol\s+2' ${SSH_CONFIG}" \
        "set_config_value ${SSH_CONFIG} Protocol 2" \
        total passed failed

    # CIS 5.2.2 — Ensure SSH LogLevel is VERBOSE (forensic audit trail)
    check_and_record "${mode}" \
        "SSH-02: SSH LogLevel is VERBOSE (CIS 5.2.2)" \
        "grep -qE '^LogLevel\s+VERBOSE' ${SSH_CONFIG}" \
        "set_config_value ${SSH_CONFIG} LogLevel VERBOSE" \
        total passed failed

    # CIS 5.2.3 — Ensure MaxAuthTries <= 4 (brute-force throttling)
    check_and_record "${mode}" \
        "SSH-03: MaxAuthTries <= 4 (CIS 5.2.3)" \
        "grep -qE '^MaxAuthTries\s+[0-4]$' ${SSH_CONFIG}" \
        "set_config_value ${SSH_CONFIG} MaxAuthTries 4" \
        total passed failed

    # CIS 5.2.4 — Ensure PermitRootLogin is disabled (blast-radius reduction)
    check_and_record "${mode}" \
        "SSH-04: PermitRootLogin is disabled (CIS 5.2.4)" \
        "grep -qE '^PermitRootLogin\s+no' ${SSH_CONFIG}" \
        "set_config_value ${SSH_CONFIG} PermitRootLogin no" \
        total passed failed

    # CIS 5.2.5 — Ensure PasswordAuthentication is disabled (key-based auth)
    # ePHI context: Passwords are the #1 stolen credential type in healthcare breaches.
    check_and_record "${mode}" \
        "SSH-05: PasswordAuthentication disabled (CIS 5.2.5)" \
        "grep -qE '^PasswordAuthentication\s+no' ${SSH_CONFIG}" \
        "set_config_value ${SSH_CONFIG} PasswordAuthentication no" \
        total passed failed

    # CIS 5.2.12 — Ensure idle timeout (ClientAliveInterval/ClientAliveCountMax)
    # ePHI context: unattended admin sessions = opportunity for insider misuse
    check_and_record "${mode}" \
        "SSH-06: ClientAliveInterval set to 300 (CIS 5.2.12)" \
        "grep -qE '^ClientAliveInterval\s+300' ${SSH_CONFIG}" \
        "set_config_value ${SSH_CONFIG} ClientAliveInterval 300" \
        total passed failed

    # Restart SSH only if in harden mode and we changed something
    if [[ "${mode}" == "harden" ]]; then
        systemctl restart sshd || log_warn "Failed to restart sshd. Verify manually."
    fi
}
