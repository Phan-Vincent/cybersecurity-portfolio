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

UNATTENDED_CONF="/etc/apt/apt.conf.d/50unattended-upgrades"
AUTO_REBOOT_CONF="/etc/apt/apt.conf.d/99auto-reboot"

run_updates_checks() {
    local mode="$1"
    local -n total="$2"
    local -n passed="$3"
    local -n failed="$4"

    # CIS 1.8 — Ensure automatic updates are enabled
    check_and_record "${mode}" \
        "UPD-01: Unattended-upgrades installed (CIS 1.8)" \
        "dpkg -l unattended-upgrades | grep -q '^ii'" \
        "apt-get install -y unattended-upgrades" \
        total passed failed

    # Ensure unattended-upgrades is actually enabled in APT
    check_and_record "${mode}" \
        "UPD-02: Unattended-upgrades enabled in APT (CIS 1.8)" \
        "grep -q '^APT::Periodic::Unattended-Upgrade \"1\";' /etc/apt/apt.conf.d/20auto-upgrades" \
        "echo 'APT::Periodic::Update-Package-Lists \"1\";' > /etc/apt/apt.conf.d/20auto-upgrades; echo 'APT::Periodic::Unattended-Upgrade \"1\";' >> /etc/apt/apt.conf.d/20auto-upgrades" \
        total passed failed

    # ePHI: Ensure security updates are applied (not just any updates)
    check_and_record "${mode}" \
        "UPD-03: Security origin enabled in unattended-upgrades (CIS 1.8)" \
        "grep -q 'security' ${UNATTENDED_CONF}" \
        "sed -i 's|//\s*\"origin=Debian,codename=${distro_codename}-updates\"|\"origin=Debian,codename=${distro_codename}-updates\"|' ${UNATTENDED_CONF}; sed -i 's|//\s*\"origin=Debian,codename=${distro_codename}-security\"|\"origin=Debian,codename=${distro_codename}-security\"|' ${UNATTENDED_CONF}" \
        total passed failed

    # CIS 1.9 — Ensure automatic reboot is configured (kernel patches need reboot)
    # ePHI: A patched but un-rebooted kernel is still vulnerable. Auto-reboot
    #       with a time window limits exposure during known quiet hours.
    check_and_record "${mode}" \
        "UPD-04: Auto-reboot enabled for security updates (CIS 1.9)" \
        "grep -q '^Unattended-Upgrade::Automatic-Reboot \"true\";' ${UNATTENDED_CONF}" \
        "cat >> ${UNATTENDED_CONF} <<'EOF'

// ePHI server: reboot after security updates during maintenance window
Unattended-Upgrade::Automatic-Reboot \"true\";
Unattended-Upgrade::Automatic-Reboot-Time \"02:00\";
EOF" \
        total passed failed

    # ePHI: Mail notification to admin on auto-update (awareness = response time)
    check_and_record "${mode}" \
        "UPD-05: Unattended-upgrades mail notification configured (ePHI best practice)" \
        "grep -q '^Unattended-Upgrade::Mail ' ${UNATTENDED_CONF}" \
        "echo 'Unattended-Upgrade::Mail \"security@example-healthcare.local\";' >> ${UNATTENDED_CONF}; echo 'Unattended-Upgrade::MailOnlyOnError \"false\";' >> ${UNATTENDED_CONF}" \
        total passed failed
}
