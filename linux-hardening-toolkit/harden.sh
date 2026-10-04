#!/usr/bin/env bash
###############################################################################
# harden.sh — Linux Hardening Toolkit Entrypoint
# CIS-Aligned hardening & audit for healthcare ePHI environments
# Author: Vincent Phan | CSUSB Cybersecurity student | Former CVS CPhT
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"

# Source modules
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/ssh.sh"
source "${LIB_DIR}/firewall.sh"
source "${LIB_DIR}/auth.sh"
source "${LIB_DIR}/auditd.sh"
source "${LIB_DIR}/filesystem.sh"
source "${LIB_DIR}/updates.sh"

# CLI flags
MODE="audit"    # default: safe, read-only
VERBOSE=false

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

OPTIONS:
    --audit          Read-only audit mode (default). Safe to run anytime.
    --harden         Apply hardening changes. Backs up configs first and
                     asks before each change.
    --auto           With --harden: apply every change without prompting.
    --key-auth       With --harden: allow disabling SSH password auth.
                     Only use once key-based login is confirmed working.
    --ephi-dir DIR   Directory treated as ePHI storage (default: ${EPHI_DIR}).
    --verbose        Show the check command behind each control.
    --help           Show this help.

EXAMPLES:
    sudo $0 --audit              # Audit without changing anything
    sudo $0 --harden             # Harden interactively
    sudo $0 --harden --auto      # Harden without prompts (lab / CI)
EOF
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --audit)    MODE="audit"; shift ;;
            --harden)   MODE="harden"; shift ;;
            --auto)     AUTO_MODE=true; shift ;;
            --key-auth) KEY_AUTH=true; shift ;;
            --ephi-dir) EPHI_DIR="${2:?--ephi-dir needs a path}"; shift 2 ;;
            --verbose)  VERBOSE=true; shift ;;
            --help|-h)  usage ;;
            *) log_error "Unknown option: $1"; usage ;;
        esac
    done
}

main() {
    parse_args "$@"

    check_root
    init_logging
    print_banner

    log_info "Mode: ${MODE} | $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    log_info "CIS Benchmark: Ubuntu 22.04 LTS (applicable to 24.04)"
    log_info "ePHI directory: ${EPHI_DIR}"
    echo

    run_module "SSH"        run_ssh_checks
    run_module "Firewall"   run_firewall_checks
    run_module "Auth"       run_auth_checks
    run_module "Auditd"     run_auditd_checks
    run_module "Filesystem" run_filesystem_checks
    run_module "Updates"    run_updates_checks

    echo
    log_info "=========================================="
    log_info "Results: ${PASS_COUNT} passed / ${FAIL_COUNT} failed / ${TOTAL_CHECKS} total (${WARN_COUNT} warnings)"
    if [[ ${FAIL_COUNT} -eq 0 ]]; then
        log_pass "All checks passed."
    elif [[ "${MODE}" == "audit" ]]; then
        log_warn "Some checks failed. Review above and re-run with --harden to remediate."
    else
        log_warn "Some checks still fail. See the report for manual remediation steps."
    fi
    log_info "=========================================="
    generate_report "${MODE}"

    # Non-zero exit lets CI or cron treat an audit with failures as an alert
    [[ ${FAIL_COUNT} -eq 0 ]]
}

run_module() {
    local name="$1" func="$2"
    CURRENT_MODULE="${name}"
    log_info "--- Module: ${name} ---"
    ${func} "${MODE}" || log_warn "Module ${name} exited early"
    echo
}

# Allow tests to source this file for its functions without running main
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
