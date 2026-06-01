#!/usr/bin/env bash
#
# lib/common.sh — Shared functions for harden.sh and audit.sh
# Scoring engine, backup helpers, report generation, color output.
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
declare -A SCORES        # cis_id -> PASS/FAIL/WARN/MANUAL
declare -A MESSAGES      # cis_id -> human-readable detail
declare -A SEVERITY      # cis_id -> LOW/MEDIUM/HIGH/CRITICAL
declare -a BACKUPS=()    # list of backup files created
TOTAL_CHECKS=0
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
MANUAL_COUNT=0
REPORT_FILE=""
AUTO_MODE=false
KEY_AUTH=false
EPHI_DIR="/var/ephisynth"   # Synthetic ePHI path — no real PHI ever

# ─── Helpers ───
log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC} $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
log_crit()  { echo -e "${RED}[CRIT]${NC} $*"; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "This script must run as root (or via sudo)." >&2
    exit 1
  fi
}

# ─── Scoring ───
# Usage: score <cis_id> <PASS|FAIL|WARN|MANUAL> <severity> <message>
score() {
  local id="$1" result="$2" sev="$3" msg="$4"
  SCORES["$id"]="$result"
  SEVERITY["$id"]="$sev"
  MESSAGES["$id"]="$msg"
  ((TOTAL_CHECKS++))
  case "$result" in
    PASS)   ((PASS_COUNT++)); log_pass  "[$id] $msg" ;;
    FAIL)   ((FAIL_COUNT++)); log_fail  "[$id] $msg" ;;
    WARN)   ((WARN_COUNT++)); log_warn  "[$id] $msg" ;;
    MANUAL) ((MANUAL_COUNT++)); log_info "[$id] $msg" ;;
  esac
}

# ─── Backup ───
backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    local bak="${f}.bak.$(date +%Y%m%d_%H%M%S)"
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
  read -rp "Apply change: $desc? [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

# ─── Config manipulation ───
set_ssh_config() {
  local key="$1" value="$2"
  local file="/etc/ssh/sshd_config"
  backup_file "$file"
  if grep -qE "^\s*#?\s*${key}\s+" "$file"; then
    sed -i -E "s/^\s*#?\s*(${key})\s+.*/\1 ${value}/" "$file"
  else
    echo "$key $value" >> "$file"
  fi
}

set_pam_pwquality() {
  local key="$1" value="$2"
  local file="/etc/security/pwquality.conf"
  backup_file "$file"
  if grep -qE "^\s*#?\s*${key}\s*=" "$file" 2>/dev/null; then
    sed -i -E "s/^\s*#?\s*(${key})\s*=.*/\1 = ${value}/" "$file"
  else
    echo "$key = $value" >> "$file"
  fi
}

# ─── Report generation ───
generate_report() {
  local mode="$1"   # "audit" or "harden"
  mkdir -p "./reports"
  REPORT_FILE="./reports/$(date +%Y%m%d_%H%M%S)-${mode}-report.md"

  local pct=0
  if (( TOTAL_CHECKS > 0 )); then
    pct=$(( PASS_COUNT * 100 / TOTAL_CHECKS ))
  fi

  # Risk rating
  local risk="LOW"
  if (( FAIL_COUNT > 0 )); then
    if (( FAIL_COUNT >= 5 )); then risk="HIGH"
    elif (( FAIL_COUNT >= 2 )); then risk="MEDIUM"
    fi
  fi
  # Critical overrides
  for id in "${!SCORES[@]}"; do
    if [[ "${SCORES[$id]}" == "FAIL" && "${SEVERITY[$id]}" == "CRITICAL" ]]; then
      risk="CRITICAL"
    fi
  done

  cat > "$REPORT_FILE" <<EOF
# Linux Hardening Toolkit — ${mode^} Report

**Generated:** $(date '+%Y-%m-%d %H:%M:%S %Z')  
**Mode:** ${mode}  
**Host:** $(hostname)  
**OS:** $(lsb_release -d -s 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')  
**Kernel:** $(uname -r)

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Controls | $TOTAL_CHECKS |
| Passed | $PASS_COUNT |
| Failed | $FAIL_COUNT |
| Warnings | $WARN_COUNT |
| Manual | $MANUAL_COUNT |
| **Compliance** | **${pct}%** |
| **Risk Rating** | **$risk** |

---

## Detailed Findings

| CIS ID | Severity | Result | Detail |
|--------|----------|--------|--------|
EOF

  # Sort by severity order
  for sev in CRITICAL HIGH MEDIUM LOW; do
    for id in $(echo "${!SEVERITY[@]}" | tr ' ' '\n' | sort); do
      if [[ "${SEVERITY[$id]}" == "$sev" ]]; then
        local r="${SCORES[$id]}"
        local m="${MESSAGES[$id]}"
        # Escape pipe for markdown
        m="${m//|/\\|}"
        printf "| %s | %s | %s | %s |\n" "$id" "$sev" "$r" "$m" >> "$REPORT_FILE"
      fi
    done
  done

  cat >> "$REPORT_FILE" <<EOF

---

## Remediation Priority (Failed Controls)

EOF

  if (( FAIL_COUNT == 0 )); then
    echo "No failed controls." >> "$REPORT_FILE"
  else
    for id in $(echo "${!SCORES[@]}" | tr ' ' '\n' | sort); do
      if [[ "${SCORES[$id]}" == "FAIL" ]]; then
        printf "- **%s** (%s): %s\n" "$id" "${SEVERITY[$id]}" "${MESSAGES[$id]}" >> "$REPORT_FILE"
      fi
    done
  fi

  if [[ "$mode" == "harden" && ${#BACKUPS[@]} -gt 0 ]]; then
    cat >> "$REPORT_FILE" <<EOF

---

## Backups Created

EOF
    for b in "${BACKUPS[@]}"; do
      echo "- \`$b\`" >> "$REPORT_FILE"
    done
  fi

  cat >> "$REPORT_FILE" <<EOF

---

## Honest Scope Note

This is a student-built assessment toolkit aligned with CIS Ubuntu Linux Benchmark v2.0.1. 
It is not a substitute for CIS-CAT, OpenSCAP, or a professional security audit. 
All ePHI references use synthetic paths (e.g., \`/var/ephisynth/\`).
EOF

  echo -e "\n${CYAN}Report written to: ${REPORT_FILE}${NC}"
}

print_summary() {
  echo ""
  echo "╔══════════════════════════════════════════╗"
  echo "║         AUDIT SUMMARY                    ║"
  echo "╠══════════════════════════════════════════╣"
  printf  "║  Total:  %-3d    Passed:  %-3d            ║\n" "$TOTAL_CHECKS" "$PASS_COUNT"
  printf  "║  Failed: %-3d    Warnings: %-3d            ║\n" "$FAIL_COUNT" "$WARN_COUNT"
  printf  "║  Manual: %-3d                             ║\n" "$MANUAL_COUNT"
  echo "╚══════════════════════════════════════════╝"
}
