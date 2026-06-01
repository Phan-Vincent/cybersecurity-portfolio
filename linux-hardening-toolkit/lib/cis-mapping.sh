#!/usr/bin/env bash
#
# lib/cis-mapping.sh — CIS Ubuntu Linux 22.04 LTS v2.0.1 control descriptions
# Sourced by harden.sh / audit.sh for reporting.
#

declare -A CIS_DESC

# SSH (Section 5.2)
CIS_DESC["5.2.2"]="Ensure SSH Protocol is set to 2"
CIS_DESC["5.2.7"]="Ensure SSH MaxAuthTries is set to 4 or less"
CIS_DESC["5.2.8"]="Ensure SSH root login is disabled"
CIS_DESC["5.2.12"]="Ensure SSH password authentication is disabled (key-auth)"
CIS_DESC["5.2.13"]="Ensure SSH idle timeout is configured"
CIS_DESC["5.2.14"]="Ensure SSH empty passwords are not permitted"

# Firewall (Section 3.5)
CIS_DESC["3.5.1.1"]="Ensure UFW is installed and enabled"
CIS_DESC["3.5.1.2"]="Ensure default deny firewall policy"
CIS_DESC["3.5.1.3"]="Ensure UFW loopback traffic is configured"

# Password policy (Section 5.4)
CIS_DESC["5.4.1"]="Ensure password creation requirements are configured"
CIS_DESC["5.4.1.1"]="Ensure password complexity (minlen 14, 3/4 classes)"
CIS_DESC["5.4.1.2"]="Ensure password expiration is 90 days or less"
CIS_DESC["5.4.1.4"]="Ensure inactive password lock is 30 days or less"

# Auditd (Section 4.1)
CIS_DESC["4.1.1.2"]="Ensure auditd service is enabled"
CIS_DESC["4.1.14"]="Ensure changes to sudoers are collected"
CIS_DESC["4.1.4"]="Ensure events that modify date/time are collected"
CIS_DESC["4.1.7"]="Ensure events affecting user/group info are collected"
CIS_DESC["CUSTOM-AUDIT-EPHI"]="Custom: audit ePHI directory access (HIPAA 164.312(b))"

# File permissions (Section 6.1)
CIS_DESC["6.1.2"]="Ensure permissions on /etc/passwd are 644"
CIS_DESC["6.1.3"]="Ensure permissions on /etc/shadow are 640"
CIS_DESC["6.1.9"]="Ensure no world-writable files exist (flagged)"
CIS_DESC["6.1.11"]="Audit SUID special permissions"
CIS_DESC["6.1.12"]="Audit SGID special permissions"

# Updates (Section 1.8)
CIS_DESC["1.8"]="Ensure automatic updates are configured"
CIS_DESC["1.8.1"]="Ensure unattended-upgrades package is installed"
CIS_DESC["1.8.2"]="Ensure security patches are applied automatically"
CIS_DESC["CUSTOM-REBOOT"]="Custom: auto-reboot disabled for lab safety"

# Helper
cis_lookup() {
  local id="$1"
  echo "${CIS_DESC[$id]:-$id}"
}
