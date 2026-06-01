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
    --audit      Read-only audit mode (default). Safe to run anytime.
    --harden     Apply hardening changes. Backs up configs first.
    --verbose    Show detailed per-check output.
    --help       Show this help.

EXAMPLES:
    sudo $0 --audit          # Audit without changing anything
    sudo $0 --harden         # Harden the system
    sudo $0 --audit --verbose # Verbose audit
EOF
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --audit)   MODE="audit"; shift ;;
            --harden)  MODE="harden"; shift ;;
            --verbose) VERBOSE=true; shift ;;
            --help)    usage ;;
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
    log_info "ePHI context: Healthcare server hardening for HIPAA-aligned environments"
    echo

    local total=0 passed=0 failed=0

    # Run each module; every module returns 0 on pass, 1 on fail
    run_module "SSH"        run_ssh_checks        total passed failed
    run_module "Firewall"   run_firewall_checks   total passed failed
    run_module "Auth"       run_auth_checks       total passed failed
    run_module "Auditd"     run_auditd_checks     total passed failed
    run_module "Filesystem" run_filesystem_checks total passed failed
    run_module "Updates"    run_updates_checks    total passed failed

    echo
    log_info "=========================================="
    log_info "Results: ${passed} passed / ${failed} failed / ${total} total"
    if [[ ${failed} -eq 0 ]]; then
        log_pass "All checks passed."
    else
        log_warn "Some checks failed. Review above and re-run with --harden to remediate."
    fi
    log_info "=========================================="
}

run_module() {
    local name="$1"
    local func="$2"
    local -n t="$3"
    local -n p="$4"
    local -n f="$5"

    log_info "--- Module: ${name} ---"
    if ${VERBOSE}; then
        ${func} "${MODE}" t p f
    else
        ${func} "${MODE}" t p f 2>/dev/null || true
    fi
    echo
}

main "$@"
