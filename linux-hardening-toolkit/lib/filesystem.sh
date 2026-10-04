#!/usr/bin/env bash
###############################################################################
# lib/filesystem.sh — File permissions & world-writable checks (CIS 6.1.x)
# ePHI Relevance: World-writable files/directories allow any user (including
#               compromised web/app service accounts) to modify or delete ePHI.
#               Sticky bits prevent deletion by non-owners in shared directories.
# Author: Vincent Phan
###############################################################################

set -euo pipefail

FS_ROOT="${FS_ROOT:-/}"   # overridable so tests can scan a sandbox tree

run_filesystem_checks() {
    local mode="$1"

    # CIS 6.1.1 — SUID binaries: a high count suggests unreviewed privilege paths
    local suid_count
    suid_count=$(find "${FS_ROOT}" -xdev -perm -4000 -type f 2>/dev/null | wc -l)
    if [[ ${suid_count} -le 50 ]]; then
        record_result PASS "FS-01: SUID binary count is reasonable (${suid_count}) (CIS 6.1.1)"
    else
        record_result FAIL "FS-01: SUID binary count is high (${suid_count}) — review manually (CIS 6.1.1)"
    fi

    # CIS 6.1.2 — No world-writable files (any user could tamper with them)
    local ww_count
    ww_count=$(find "${FS_ROOT}" -xdev -type f -perm -002 2>/dev/null | wc -l)
    if [[ ${ww_count} -eq 0 ]]; then
        record_result PASS "FS-02: No world-writable files found (CIS 6.1.2)"
    else
        record_result FAIL "FS-02: ${ww_count} world-writable files found — manual review required (CIS 6.1.2)"
        # Automated removal of world-writable files is dangerous; report only.
    fi

    # CIS 6.1.3 — Sticky bit on world-writable directories (prevents cross-user deletion)
    local no_sticky
    no_sticky=$(find "${FS_ROOT}" -xdev -type d -perm -002 ! -perm -1000 2>/dev/null | wc -l)
    if [[ ${no_sticky} -eq 0 ]]; then
        record_result PASS "FS-03: Sticky bit set on all world-writable directories (CIS 6.1.3)"
    elif [[ "${mode}" == "harden" ]] && confirm_change "set sticky bit on ${no_sticky} world-writable dir(s)"; then
        find "${FS_ROOT}" -xdev -type d -perm -002 ! -perm -1000 -exec chmod +t {} + 2>/dev/null
        CHANGES_MADE=$((CHANGES_MADE + 1))
        record_result FIXED "FS-03: Sticky bit set on ${no_sticky} world-writable dir(s) (CIS 6.1.3)"
    else
        record_result FAIL "FS-03: ${no_sticky} world-writable dirs lack sticky bit (CIS 6.1.3)"
    fi

    # ePHI directory: no group-write and no access at all for "other" (mask 027)
    if [[ -d "${EPHI_DIR}" ]]; then
        local perms
        perms=$(stat -c "%a" "${EPHI_DIR}")
        if (( (8#${perms} & 8#027) == 0 )); then
            record_result PASS "FS-04: ${EPHI_DIR} permissions are restricted (${perms}) (HIPAA 164.312(a)(1))"
        elif [[ "${mode}" == "harden" ]] && confirm_change "chmod 750 ${EPHI_DIR}"; then
            chmod 750 "${EPHI_DIR}"
            CHANGES_MADE=$((CHANGES_MADE + 1))
            record_result FIXED "FS-04: ${EPHI_DIR} permissions set to 750 (was ${perms}) (HIPAA 164.312(a)(1))"
        else
            record_result FAIL "FS-04: ${EPHI_DIR} permissions are too permissive (${perms}) (HIPAA 164.312(a)(1))"
        fi
    else
        record_result WARN "FS-04: ${EPHI_DIR} does not exist (skipping — pass --ephi-dir for production ePHI)"
    fi
}
