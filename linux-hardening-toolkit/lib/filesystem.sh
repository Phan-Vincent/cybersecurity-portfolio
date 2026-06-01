#!/usr/bin/env bash
###############################################################################
# lib/filesystem.sh — File permissions & world-writable checks (CIS 6.1.x)
# ePHI Relevance: World-writable files/directories allow any user (including
#               compromised web/app service accounts) to modify or delete ePHI.
#               Sticky bits prevent deletion by non-owners in shared directories.
# Author: Vincent Phan
###############################################################################

set -euo pipefail

run_filesystem_checks() {
    local mode="$1"
    local -n total="$2"
    local -n passed="$3"
    local -n failed="$4"

    # CIS 6.1.1 — Audit system file permissions (SUID/SGID)
    # ePHI: SUID abuse is a classic privilege escalation path. If a compromised
    #       service account can exploit a SUID binary, they may reach ePHI.
    local suid_count
    suid_count=$(find / -perm -4000 -type f 2>/dev/null | wc -l)
    # Synthetic check: ensure SUID binaries are a known, reasonable count.
    # In a real hardening run, we'd whitelist expected SUID binaries.
    if [[ ${suid_count} -le 50 ]]; then
        log_pass "FS-01: SUID binary count is reasonable (${suid_count}) (CIS 6.1.1)"
        passed=$((passed + 1))
    else
        log_fail "FS-01: SUID binary count is high (${suid_count}) — review manually (CIS 6.1.1)"
        failed=$((failed + 1))
    fi
    total=$((total + 1))

    # CIS 6.1.2 — Ensure no world-writable files exist (critical for ePHI dirs)
    # ePHI: A world-writable file in /var/healthcare/ = any local user can alter PHI.
    local ww_count
    ww_count=$(find / -xdev -type f -perm -002 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | wc -l)
    if [[ ${ww_count} -eq 0 ]]; then
        log_pass "FS-02: No world-writable files found (CIS 6.1.2)"
        passed=$((passed + 1))
    else
        log_fail "FS-02: ${ww_count} world-writable files found (CIS 6.1.2)"
        failed=$((failed + 1))
        if [[ "${mode}" == "harden" ]]; then
            log_warn "  -> Manual review required. Automated removal of world-writable files is dangerous."
        fi
    fi
    total=$((total + 1))

    # CIS 6.1.3 — Ensure sticky bit on all world-writable directories
    # ePHI: Prevents user A from deleting user B's files in shared temp dirs.
    local no_sticky
    no_sticky=$(find / -xdev -type d -perm -002 ! -perm -1000 2>/dev/null | grep -v '^/proc\|^/sys' | wc -l)
    if [[ ${no_sticky} -eq 0 ]]; then
        log_pass "FS-03: Sticky bit set on all world-writable directories (CIS 6.1.3)"
        passed=$((passed + 1))
    else
        log_fail "FS-03: ${no_sticky} world-writable dirs lack sticky bit (CIS 6.1.3)"
        failed=$((failed + 1))
        if [[ "${mode}" == "harden" ]]; then
            find / -xdev -type d -perm -002 ! -perm -1000 2>/dev/null | grep -v '^/proc\|^/sys' | while read -r dir; do
                chmod +t "${dir}" && log_info "  -> Set sticky bit on ${dir}"
            done
        fi
    fi
    total=$((total + 1))

    # ePHI-specific: Ensure /srv/ePHI (synthetic directory) is not world-readable
    if [[ -d /srv/ePHI ]]; then
        local perms
        perms=$(stat -c "%a" /srv/ePHI)
        if [[ ${perms} -le 750 ]]; then
            log_pass "FS-04: /srv/ePHI permissions are restricted (${perms}) (ePHI best practice)"
            passed=$((passed + 1))
        else
            log_fail "FS-04: /srv/ePHI permissions are too permissive (${perms}) (ePHI best practice)"
            failed=$((failed + 1))
            if [[ "${mode}" == "harden" ]]; then
                chmod 750 /srv/ePHI && log_info "  -> Set /srv/ePHI to 750"
            fi
        fi
        total=$((total + 1))
    else
        log_warn "FS-04: /srv/ePHI does not exist (skipping — create this dir for production ePHI)"
    fi
}
