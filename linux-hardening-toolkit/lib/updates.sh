#!/usr/bin/env bash
###############################################################################
# lib/updates.sh — Unattended-upgrades & auto-reboot (CIS 1.8 / 1.9)
# ePHI Relevance: Unpatched vulnerabilities are the #1 exploited flaw in
#               healthcare breaches (HHS breach reports cite "unpatched
#               systems" repeatedly). Auto-reboot ensures kernel patches
#               are actually live, not just installed.
# Author: Vincent Phan
###############################################################################

set -euo pipefail

UNATTENDED_CONF="${UNATTENDED_CONF:-/etc/apt/apt.conf.d/50unattended-upgrades}"
AUTO_UPGRADES_CONF="${AUTO_UPGRADES_CONF:-/etc/apt/apt.conf.d/20auto-upgrades}"

run_updates_checks() {
    local mode="$1"

    # CIS 1.8 — Ensure automatic updates are enabled
    check_and_record "${mode}" \
        "UPD-01: Unattended-upgrades installed (CIS 1.8)" \
        "dpkg -l unattended-upgrades | grep -q '^ii'" \
        "apt-get install -y unattended-upgrades"

    # Ensure unattended-upgrades is actually enabled in APT
    check_and_record "${mode}" \
        "UPD-02: Unattended-upgrades enabled in APT (CIS 1.8)" \
        "grep -q '^APT::Periodic::Unattended-Upgrade \"1\";' ${AUTO_UPGRADES_CONF}" \
        "echo 'APT::Periodic::Update-Package-Lists \"1\";' > ${AUTO_UPGRADES_CONF}; echo 'APT::Periodic::Unattended-Upgrade \"1\";' >> ${AUTO_UPGRADES_CONF}"

    # ePHI: Ensure security updates are applied (not just any updates)
    # Single quotes keep ${distro_id}/${distro_codename} literal: they are
    # unattended-upgrades placeholders, not shell variables.
    check_and_record "${mode}" \
        "UPD-03: Security origin enabled in unattended-upgrades (CIS 1.8)" \
        "grep -qE '^[[:space:]]*\"\\\$\\{distro_id\\}:\\\$\\{distro_codename\\}-security\";' ${UNATTENDED_CONF}" \
        "sed -i -E 's|^([[:space:]]*)//[[:space:]]*(\"\\\$\\{distro_id\\}:\\\$\\{distro_codename\\}-security\";)|\\1\\2|' ${UNATTENDED_CONF}"

    check_and_record "${mode}" \
        "UPD-04: Auto-reboot enabled for security updates (CIS 1.9)" \
        "grep -q '^Unattended-Upgrade::Automatic-Reboot \"true\";' ${UNATTENDED_CONF}" \
        "cat >> ${UNATTENDED_CONF} <<'EOF'

// ePHI server: reboot after security updates during maintenance window
Unattended-Upgrade::Automatic-Reboot \"true\";
Unattended-Upgrade::Automatic-Reboot-Time \"02:00\";
EOF"

    # ePHI: Mail notification to admin on auto-update (awareness = response time)
    check_and_record "${mode}" \
        "UPD-05: Unattended-upgrades mail notification configured (ePHI best practice)" \
        "grep -q '^Unattended-Upgrade::Mail ' ${UNATTENDED_CONF}" \
        "echo 'Unattended-Upgrade::Mail \"security@example-healthcare.local\";' >> ${UNATTENDED_CONF}; echo 'Unattended-Upgrade::MailOnlyOnError \"false\";' >> ${UNATTENDED_CONF}"
}
