#!/usr/bin/env bash
###############################################################################
# tests/validate.sh — Smoke + behaviour tests for the hardening toolkit
#
# Runs entirely in a sandbox: every check is pointed at temporary copies of
# config files, and systemctl/sshd are stubbed, so it never touches the host.
# No root required.  Usage: bash tests/validate.sh
###############################################################################

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANDBOX="$(mktemp -d)"
trap 'rm -rf "${SANDBOX}"' EXIT

PASSES=0
FAILURES=0
ok()   { PASSES=$((PASSES + 1)); echo "  ok   - $*"; }
bad()  { FAILURES=$((FAILURES + 1)); echo "  FAIL - $*"; }
expect() { local desc="$1"; shift; if "$@"; then ok "$desc"; else bad "$desc"; fi; }

# Run a snippet with the toolkit sourced, in an isolated subshell.
# Output: one "STATUS|MODULE|DESCRIPTION" line per recorded result.
run_toolkit() {
    (
        export REPORT_DIR="${SANDBOX}/reports"
        # shellcheck source=/dev/null
        source "${ROOT}/harden.sh"
        # Stub every command that could change the host. Fixes may only touch
        # the sandbox files that each scenario points the module at.
        systemctl() { return 0; }
        sshd() { return 0; }
        apt-get() { return 0; }
        ufw() { return 0; }
        augenrules() { return 0; }
        auditctl() { return 0; }
        # Belt and braces: point every remaining config path into the sandbox
        SSH_CONFIG="${SANDBOX}/unused/sshd_config"
        LOGIN_DEFS="${SANDBOX}/unused/login.defs"
        PAM_COMMON_PASSWORD="${SANDBOX}/unused/common-password"
        PAM_COMMON_AUTH="${SANDBOX}/unused/common-auth"
        AUDITD_CONF="${SANDBOX}/unused/auditd.conf"
        AUDIT_RULES_DIR="${SANDBOX}/unused/rules.d"
        EPHI_AUDIT_RULES="${AUDIT_RULES_DIR}/ePHI-access.rules"
        UNATTENDED_CONF="${SANDBOX}/unused/50unattended-upgrades"
        AUTO_UPGRADES_CONF="${SANDBOX}/unused/20auto-upgrades"
        FS_ROOT="${SANDBOX}/unused/fs"
        EPHI_DIR="${SANDBOX}/unused/ephi"
        mkdir -p "${SANDBOX}/unused/rules.d" "${SANDBOX}/unused/fs"
        init_logging
        eval "$1" >/dev/null 2>&1
        printf '%s\n' "${RESULTS[@]}"
    )
}

status_of() {  # status_of <results> <id-prefix>
    grep -E "\|[^|]*\|$2:" <<< "$1" | head -1 | cut -d'|' -f1
}

echo "# Syntax"
for f in "${ROOT}"/harden.sh "${ROOT}"/audit.sh "${ROOT}"/lib/*.sh "${ROOT}"/tests/*.sh; do
    expect "bash -n $(basename "$f")" bash -n "$f"
done
if command -v shellcheck >/dev/null 2>&1; then
    expect "shellcheck (errors only)" shellcheck -S error -x "${ROOT}"/harden.sh "${ROOT}"/audit.sh "${ROOT}"/lib/*.sh
else
    echo "  skip - shellcheck not installed"
fi

echo "# Entrypoints"
for fn in check_root init_logging print_banner check_and_record record_result set_config_value generate_report \
          run_ssh_checks run_firewall_checks run_auth_checks run_auditd_checks run_filesystem_checks run_updates_checks; do
    expect "function ${fn} is defined" bash -c "source '${ROOT}/harden.sh'; declare -F ${fn} >/dev/null"
done
expect "harden.sh --help exits 0" bash -c "'${ROOT}/harden.sh' --help >/dev/null"
expect "audit.sh refuses --harden" bash -c "! '${ROOT}/audit.sh' --harden 2>/dev/null"

echo "# SSH audit / harden"
cat > "${SANDBOX}/sshd_config" <<'CFG'
#Protocol 2
LogLevel INFO
MaxAuthTries 6
PermitRootLogin yes
PasswordAuthentication yes
CFG
cp "${SANDBOX}/sshd_config" "${SANDBOX}/sshd_config.orig"
r=$(run_toolkit "SSH_CONFIG='${SANDBOX}/sshd_config'; run_ssh_checks audit")
expect "audit flags all 6 weak SSH settings" test "$(grep -c '^FAIL' <<< "$r")" -eq 6
expect "audit mode leaves sshd_config untouched" cmp -s "${SANDBOX}/sshd_config" "${SANDBOX}/sshd_config.orig"

r=$(run_toolkit "SSH_CONFIG='${SANDBOX}/sshd_config'; AUTO_MODE=true; run_ssh_checks harden")
expect "harden remediates SSH-01..04 and SSH-06" test "$(grep -c '^FIXED' <<< "$r")" -eq 5
expect "SSH-05 not touched without --key-auth (lockout guard)" test "$(status_of "$r" SSH-05)" = "FAIL"
expect "PasswordAuthentication still yes" grep -q '^PasswordAuthentication yes' "${SANDBOX}/sshd_config"
expect "harden backed up sshd_config" bash -c "compgen -G '${SANDBOX}/sshd_config.bak.*' >/dev/null"

r=$(run_toolkit "SSH_CONFIG='${SANDBOX}/sshd_config'; AUTO_MODE=true; KEY_AUTH=true; run_ssh_checks harden")
expect "--key-auth remediates SSH-05" test "$(status_of "$r" SSH-05)" = "FIXED"

cp "${ROOT}/configs/sshd_config.hardening" "${SANDBOX}/sshd_template"
r=$(run_toolkit "SSH_CONFIG='${SANDBOX}/sshd_template'; run_ssh_checks audit")
expect "configs/sshd_config.hardening passes every SSH check" test "$(grep -c '^PASS' <<< "$r")" -eq 6

echo "# Password aging"
printf 'PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\nPASS_WARN_AGE 7\n' > "${SANDBOX}/login.defs"
r=$(run_toolkit "LOGIN_DEFS='${SANDBOX}/login.defs'; AUTO_MODE=true; run_auth_checks harden")
expect "AUTH-03 remediated" test "$(status_of "$r" AUTH-03)" = "FIXED"
expect "login.defs now PASS_MAX_DAYS 365" grep -q '^PASS_MAX_DAYS 365' "${SANDBOX}/login.defs"
cp "${ROOT}/configs/login.defs.hardening" "${SANDBOX}/login.defs.tpl"
r=$(run_toolkit "LOGIN_DEFS='${SANDBOX}/login.defs.tpl'; run_auth_checks audit")
for id in AUTH-03 AUTH-04 AUTH-05; do
    expect "configs/login.defs.hardening passes ${id}" test "$(status_of "$r" "${id}")" = "PASS"
done

echo "# Auditd config"
cp "${ROOT}/configs/auditd.conf.hardening" "${SANDBOX}/auditd.conf"
r=$(run_toolkit "AUDITD_CONF='${SANDBOX}/auditd.conf'; run_auditd_checks audit")
expect "configs/auditd.conf.hardening passes AUDIT-03" test "$(status_of "$r" AUDIT-03)" = "PASS"
expect "configs/auditd.conf.hardening passes AUDIT-04" test "$(status_of "$r" AUDIT-04)" = "PASS"

echo "# Unattended upgrades (literal \${distro_codename} placeholders)"
printf 'Unattended-Upgrade::Allowed-Origins {\n        "${distro_id}:${distro_codename}";\n//      "${distro_id}:${distro_codename}-security";\n};\n' > "${SANDBOX}/50uu"
r=$(run_toolkit "UNATTENDED_CONF='${SANDBOX}/50uu'; run_updates_checks audit")
expect "UPD-03 fails while security origin is commented out" test "$(status_of "$r" UPD-03)" = "FAIL"
r=$(run_toolkit "UNATTENDED_CONF='${SANDBOX}/50uu'; AUTO_MODE=true; run_updates_checks harden")
expect "UPD-02 fix wrote only the sandbox 20auto-upgrades" grep -q 'Unattended-Upgrade "1"' "${SANDBOX}/unused/20auto-upgrades"
expect "UPD-03 remediated" test "$(status_of "$r" UPD-03)" = "FIXED"
expect "security origin uncommented, placeholders kept literal" grep -qE '^[[:space:]]*"\$\{distro_id\}:\$\{distro_codename\}-security";' "${SANDBOX}/50uu"

echo "# Filesystem + ePHI directory"
mkdir -p "${SANDBOX}/fs/ephi" "${SANDBOX}/fs/shared"
touch "${SANDBOX}/fs/loose.txt"; chmod 666 "${SANDBOX}/fs/loose.txt"
chmod 777 "${SANDBOX}/fs/shared"
chmod 707 "${SANDBOX}/fs/ephi"
r=$(run_toolkit "FS_ROOT='${SANDBOX}/fs'; EPHI_DIR='${SANDBOX}/fs/ephi'; run_filesystem_checks audit")
expect "FS-02 flags world-writable file" test "$(status_of "$r" FS-02)" = "FAIL"
expect "FS-03 flags dir without sticky bit" test "$(status_of "$r" FS-03)" = "FAIL"
expect "FS-04 flags ePHI dir mode 707 (octal check)" test "$(status_of "$r" FS-04)" = "FAIL"
r=$(run_toolkit "FS_ROOT='${SANDBOX}/fs'; EPHI_DIR='${SANDBOX}/fs/ephi'; AUTO_MODE=true; run_filesystem_checks harden")
expect "FS-03 remediated" test "$(status_of "$r" FS-03)" = "FIXED"
expect "FS-04 remediated" test "$(stat -c %a "${SANDBOX}/fs/ephi")" = "750"
expect "world-writable file reported, never auto-changed" test "$(stat -c %a "${SANDBOX}/fs/loose.txt")" = "666"

echo "# Report"
r=$(run_toolkit "CURRENT_MODULE=SSH; SSH_CONFIG='${SANDBOX}/sshd_template'; run_ssh_checks audit; generate_report audit")
report=$(ls "${SANDBOX}"/reports/*-audit-report.md 2>/dev/null | head -1)
expect "markdown report written" test -s "${report}"
expect "report has executive summary" grep -q '^## Executive Summary' "${report}"
expect "report lists SSH findings" grep -q '| SSH | PASS | SSH-04' "${report}"

echo
echo "${PASSES} passed, ${FAILURES} failed"
[[ ${FAILURES} -eq 0 ]]
