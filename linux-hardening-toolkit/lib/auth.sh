#!/usr/bin/env bash
###############################################################################
# lib/auth.sh — Password policy & PAM checks (CIS Ubuntu 22.04 Section 5.3 / 5.4)
# ePHI Relevance: Credential compromise is the #1 initial access vector in
#               healthcare breaches (Verizon DBIR). Weak passwords + no lockout
#               = stolen ePHI via brute-force or credential stuffing.
# Author: Vincent Phan
###############################################################################

set -euo pipefail

PAM_COMMON_PASSWORD="${PAM_COMMON_PASSWORD:-/etc/pam.d/common-password}"
PAM_COMMON_AUTH="${PAM_COMMON_AUTH:-/etc/pam.d/common-auth}"
LOGIN_DEFS="${LOGIN_DEFS:-/etc/login.defs}"

run_auth_checks() {
    local mode="$1"

    # CIS 5.3.1 — Ensure password creation requirements (pam_pwquality)
    # ePHI: Prevents "Password123" from being the key to patient records.
    check_and_record "${mode}" \
        "AUTH-01: pam_pwquality enforces strong passwords (CIS 5.3.1)" \
        "grep -q 'pam_pwquality.so' ${PAM_COMMON_PASSWORD}" \
        "apt-get install -y libpam-pwquality; sed -i '/pam_pwquality.so/d' ${PAM_COMMON_PASSWORD}; echo 'password requisite pam_pwquality.so try_first_pass retry=3 minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' >> ${PAM_COMMON_PASSWORD}"

    # CIS 5.3.2 — Ensure lockout for failed password attempts (pam_faillock)
    # ePHI: Rate-limits credential stuffing against ePHI admin accounts.
    check_and_record "${mode}" \
        "AUTH-02: pam_faillock locks accounts after failed attempts (CIS 5.3.2)" \
        "grep -q 'pam_faillock.so' ${PAM_COMMON_AUTH}" \
        "apt-get install -y libpam-modules; sed -i '/pam_faillock.so/d' ${PAM_COMMON_AUTH}; echo 'auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900' >> ${PAM_COMMON_AUTH}; echo 'auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900' >> ${PAM_COMMON_AUTH}"

    # CIS 5.4.1.1 — Ensure password expiration <= 365 days
    # ePHI: Limits the window a stolen credential remains valid.
    check_and_record "${mode}" \
        "AUTH-03: Password max age <= 365 days (CIS 5.4.1.1)" \
        "grep -qE '^PASS_MAX_DAYS\s+365' ${LOGIN_DEFS}" \
        "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' ${LOGIN_DEFS}"

    # CIS 5.4.1.2 — Ensure minimum password age >= 1 day
    # Prevents rapid password cycling to bypass history checks.
    check_and_record "${mode}" \
        "AUTH-04: Password min age >= 1 day (CIS 5.4.1.2)" \
        "grep -qE '^PASS_MIN_DAYS\s+1' ${LOGIN_DEFS}" \
        "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' ${LOGIN_DEFS}"

    # CIS 5.4.1.3 — Ensure password warning >= 7 days
    # ePHI: Prevents accidental lockouts that could block emergency access.
    check_and_record "${mode}" \
        "AUTH-05: Password warning >= 7 days (CIS 5.4.1.3)" \
        "grep -qE '^PASS_WARN_AGE\s+7' ${LOGIN_DEFS}" \
        "sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' ${LOGIN_DEFS}"
}
