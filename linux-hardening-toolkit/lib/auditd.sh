#!/usr/bin/env bash
###############################################################################
# lib/auditd.sh — Audit daemon checks (CIS Ubuntu 22.04 Section 4.1)
# ePHI Relevance: HIPAA requires audit trails of ePHI access (164.312(b)).
#               auditd is the canonical Linux mechanism for capturing who
#               accessed what file, when, and from where.
# Author: Vincent Phan
###############################################################################

set -euo pipefail

AUDITD_CONF="/etc/audit/auditd.conf"
AUDIT_RULES_DIR="/etc/audit/rules.d"
EPHI_AUDIT_RULES="${AUDIT_RULES_DIR}/ePHI-access.rules"

run_auditd_checks() {
    local mode="$1"
    local -n total="$2"
    local -n passed="$3"
    local -n failed="$4"

    # CIS 4.1.1.1 — Ensure auditd is installed
    check_and_record "${mode}" \
        "AUDIT-01: auditd is installed (CIS 4.1.1.1)" \
        "command -v auditd >/dev/null 2>&1" \
        "apt-get install -y auditd audispd-plugins" \
        total passed failed

    # CIS 4.1.1.2 — Ensure auditd service is enabled
    check_and_record "${mode}" \
        "AUDIT-02: auditd service is enabled (CIS 4.1.1.2)" \
        "systemctl is-enabled --quiet auditd" \
        "systemctl enable --now auditd" \
        total passed failed

    # CIS 4.1.1.3 — Ensure audit log storage is large enough (ePHI = high volume)
    # Using max_log_file = 50MB as a reasonable healthcare default.
    check_and_record "${mode}" \
        "AUDIT-03: Max audit log file size configured (CIS 4.1.1.3)" \
        "grep -qE '^max_log_file\s*=\s*50' ${AUDITD_CONF}" \
        "sed -i 's/^max_log_file.*/max_log_file = 50/' ${AUDITD_CONF}" \
        total passed failed

    # CIS 4.1.1.4 — Ensure audit logs are not automatically deleted (retention)
    # ePHI: HIPAA requires 6-year retention. We keep logs until admin action.
    check_and_record "${mode}" \
        "AUDIT-04: Audit log retention = keep_logs (CIS 4.1.1.4)" \
        "grep -qE '^max_log_file_action\s*=\s*keep_logs' ${AUDITD_CONF}" \
        "sed -i 's/^max_log_file_action.*/max_log_file_action = keep_logs/' ${AUDITD_CONF}" \
        total passed failed

    # CIS 4.1.3 — Audit sudoers / privilege escalation (critical for ePHI)
    check_and_record "${mode}" \
        "AUDIT-05: sudoers changes are audited (CIS 4.1.3)" \
        "auditctl -l | grep -q '/etc/sudoers'" \
        "echo '-w /etc/sudoers -p wa -k identity' >> ${AUDIT_RULES_DIR}/privilege.rules; echo '-w /etc/sudoers.d/ -p wa -k identity' >> ${AUDIT_RULES_DIR}/privilege.rules" \
        total passed failed

    # ePHI-specific: Synthetic audit rules for a fake ePHI directory
    # In production, this would target /var/healthcare/ePHI or similar.
    check_and_record "${mode}" \
        "AUDIT-06: ePHI directory access auditing (HIPAA 164.312(b))" \
        "test -f ${EPHI_AUDIT_RULES}" \
        "cat > ${EPHI_AUDIT_RULES} <<'EOF'
# ePHI audit rules — synthetic example for portfolio demo
# In production: replace /srv/ePHI with actual ePHI mount point
-w /srv/ePHI -p rwxa -k ePHI_access
-a always,exit -F arch=b64 -S open -S openat -F dir=/srv/ePHI -F success=1 -k ePHI_file_open
EOF" \
        total passed failed

    # Reload audit rules if hardening
    if [[ "${mode}" == "harden" ]]; then
        augenrules --load || log_warn "augenrules --load failed."
        systemctl restart auditd || log_warn "auditd restart failed."
    fi
}
