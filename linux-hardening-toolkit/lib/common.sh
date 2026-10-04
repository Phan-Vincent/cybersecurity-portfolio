#!/usr/bin/env bash
#
# lib/common.sh — Shared functions for harden.sh and audit.sh
# Check engine, scoring, backup helpers, report generation, color output.
# This file is sourced, not executed directly.
#

set -uo pipefail

# ─── Colors (safe for non-TTY) ───
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; NC=''
fi

# ─── State ───
declare -a RESULTS=()    # "STATUS|MODULE|DESCRIPTION" in execution order
declare -a BACKUPS=()    # list of backup files created
TOTAL_CHECKS=0
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
FIXED_COUNT=0
CHANGES_MADE=0
CURRENT_MODULE=""
REPORT_FILE=""
REPORT_DIR="${REPORT_DIR:-./reports}"
AUTO_MODE=false
KEY_AUTH=false
EPHI_DIR="${EPHI_DIR:-/var/ephisynth}"   # Synthetic ePHI path — no real PHI ever

# ─── Helpers ───
log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC} $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

check_root() {
  if [[ $EUID -ne 0 ]]; then
    log_error "This script must run as root (or via sudo)."
    exit 1
  fi
}

print_banner() {
  echo "================================================================"
  echo " Linux Hardening Toolkit — CIS-aligned audit for ePHI servers"
  echo "================================================================"
}

init_logging() {
  RESULTS=(); BACKUPS=()
  TOTAL_CHECKS=0; PASS_COUNT=0; FAIL_COUNT=0; WARN_COUNT=0; FIXED_COUNT=0; CHANGES_MADE=0
}

# ─── Scoring ───
# Usage: record_result <PASS|FAIL|WARN|FIXED> <description>
# FIXED counts as a pass: the control failed, was remediated, and re-verified.
record_result() {
  local status="$1" desc="$2"
  RESULTS+=("${status}|${CURRENT_MODULE}|${desc}")
  case "$status" in
    PASS)  TOTAL_CHECKS=$((TOTAL_CHECKS + 1)); PASS_COUNT=$((PASS_COUNT + 1)); log_pass "$desc" ;;
    FIXED) TOTAL_CHECKS=$((TOTAL_CHECKS + 1)); PASS_COUNT=$((PASS_COUNT + 1)); FIXED_COUNT=$((FIXED_COUNT + 1))
           log_pass "$desc (remediated)" ;;
    FAIL)  TOTAL_CHECKS=$((TOTAL_CHECKS + 1)); FAIL_COUNT=$((FAIL_COUNT + 1)); log_fail "$desc" ;;
    WARN)  WARN_COUNT=$((WARN_COUNT + 1)); log_warn "$desc" ;;
  esac
}

# ─── Check engine ───
# Usage: check_and_record <mode> <description> <check_cmd> <fix_cmd>
#   check_cmd  shell snippet; exit 0 means the control is satisfied
#   fix_cmd    shell snippet applied in harden mode (after confirmation) when
#              the check fails; empty string means "manual remediation only"
# Counts are kept in the global TOTAL_CHECKS / PASS_COUNT / FAIL_COUNT.
check_and_record() {
  local mode="$1" desc="$2" check_cmd="$3" fix_cmd="$4"

  [[ "${VERBOSE:-false}" == true ]] && log_info "  check: ${check_cmd}"
  if (eval "$check_cmd") >/dev/null 2>&1; then
    record_result PASS "$desc"
    return 0
  fi

  if [[ "$mode" != "harden" ]]; then
    record_result FAIL "$desc"
    return 0
  fi

  if [[ -z "$fix_cmd" ]]; then
    record_result FAIL "$desc — manual remediation required"
    return 0
  fi

  if ! confirm_change "$desc"; then
    record_result FAIL "$desc — remediation declined"
    return 0
  fi

  # Not in a subshell: backup_file must be able to record into BACKUPS
  if eval "$fix_cmd" && (eval "$check_cmd") >/dev/null 2>&1; then
    CHANGES_MADE=$((CHANGES_MADE + 1))
    record_result FIXED "$desc"
  else
    record_result FAIL "$desc — remediation did not verify"
  fi
  return 0
}

# ─── Backup ───
backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    local bak
    bak="${f}.bak.$(date +%Y%m%d_%H%M%S)"
    [[ -e "$bak" ]] && return 0   # already backed up this second
    cp -p "$f" "$bak"
    BACKUPS+=("$bak")
    log_info "Backed up $f -> $bak"
  fi
}

# ─── Safe replace ───
# Only if AUTO_MODE or interactive confirm
confirm_change() {
  local desc="$1"
  if [[ "$AUTO_MODE" == true ]]; then
    return 0
  fi
  local ans=""
  read -rp "Apply change: $desc? [y/N] " ans || return 1
  [[ "$ans" =~ ^[Yy]$ ]]
}

# ─── Config manipulation ───
# Usage: set_config_value <file> <key> <value>
# Replaces an existing (optionally commented-out) "key value" line, or appends one.
set_config_value() {
  local file="$1" key="$2" value="$3"
  backup_file "$file"
  if grep -qE "^\s*#?\s*${key}\s+" "$file"; then
    sed -i -E "0,/^\s*#?\s*${key}\s+.*/s//${key} ${value}/" "$file"
  else
    echo "${key} ${value}" >> "$file"
  fi
}

# ─── Report generation ───
generate_report() {
  local mode="$1"   # "audit" or "harden"
  mkdir -p "$REPORT_DIR"
  REPORT_FILE="${REPORT_DIR}/$(date +%Y%m%d_%H%M%S)-${mode}-report.md"

  local pct=0
  if (( TOTAL_CHECKS > 0 )); then
    pct=$(( PASS_COUNT * 100 / TOTAL_CHECKS ))
  fi

  local risk="LOW"
  if (( FAIL_COUNT >= 8 )); then risk="CRITICAL"
  elif (( FAIL_COUNT >= 5 )); then risk="HIGH"
  elif (( FAIL_COUNT >= 2 )); then risk="MEDIUM"
  fi

  local os
  os="$( (. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}") || echo unknown)"

  {
    echo "# Linux Hardening Toolkit — ${mode^} Report"
    echo
    echo "**Generated:** $(date '+%Y-%m-%d %H:%M:%S %Z')  "
    echo "**Mode:** ${mode}  "
    echo "**Host:** $(hostname)  "
    echo "**OS:** ${os}  "
    echo "**Kernel:** $(uname -r)  "
    echo "**ePHI directory:** \`${EPHI_DIR}\`"
    echo
    echo "## Executive Summary"
    echo
    echo "| Metric | Value |"
    echo "|--------|-------|"
    echo "| Scored controls | $TOTAL_CHECKS |"
    echo "| Passed | $PASS_COUNT |"
    echo "| Remediated this run | $FIXED_COUNT |"
    echo "| Failed | $FAIL_COUNT |"
    echo "| Warnings (not scored) | $WARN_COUNT |"
    echo "| **Compliance** | **${pct}%** |"
    echo "| **Risk Rating** | **$risk** |"
    echo
    echo "## Detailed Findings"
    echo
    echo "| Module | Result | Control |"
    echo "|--------|--------|---------|"
    local entry status module desc
    for entry in "${RESULTS[@]}"; do
      IFS='|' read -r status module desc <<< "$entry"
      printf "| %s | %s | %s |\n" "$module" "$status" "${desc//|/\\|}"
    done
    echo
    echo "## Remediation Required"
    echo
    if (( FAIL_COUNT == 0 )); then
      echo "No failed controls."
    else
      for entry in "${RESULTS[@]}"; do
        IFS='|' read -r status module desc <<< "$entry"
        if [[ "$status" == "FAIL" ]]; then echo "- [ ] **${module}** — ${desc}"; fi
      done
    fi
    if (( ${#BACKUPS[@]} > 0 )); then
      echo
      echo "## Backups Created"
      echo
      local b
      for b in "${BACKUPS[@]}"; do echo "- \`$b\`"; done
    fi
    echo
    echo "---"
    echo
    echo "*Student-built assessment aligned with the CIS Ubuntu Linux Benchmark. Not a substitute for"
    echo "CIS-CAT, OpenSCAP, or a professional audit. ePHI paths are synthetic.*"
  } > "$REPORT_FILE"

  echo -e "\n${CYAN}Report written to: ${REPORT_FILE}${NC}"
}
