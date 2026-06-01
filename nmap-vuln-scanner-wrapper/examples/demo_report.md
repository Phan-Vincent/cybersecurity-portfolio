# Network Reconnaissance Report

> **Generated:** 2024-01-15 14:33:21  
> **Tool:** nmap-vuln-scanner-wrapper v1.0.0  
> **Demo Mode:** Yes

## ⚠️ Ethical Notice

This scan was conducted with explicit authorization. Unauthorized scanning is illegal and unethical.

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Hosts | 3 |
| Total Open Ports | 7 |
| 🔴 High Risk | 3 |
| ⚠️ Medium Risk | 2 |
| 🟢 Low Risk | 2 |

## Detailed Findings

### Host: 192.168.1.10 (web-server-01)

- **Status:** up
- **OS:** None

| Port | Protocol | Service | Product | Version | Risk | CVEs |
|------|----------|---------|---------|---------|------|------|
| 22 | tcp | ssh | OpenSSH | 8.2p1 | 🟢 LOW | None |
| 80 | tcp | http | Apache httpd | 2.4.41 | ⚠️ MEDIUM | CVE-2021-41773 |
| 443 | tcp | https | Apache httpd | 2.4.41 | ⚠️ MEDIUM | CVE-2021-41773 |
| 3306 | tcp | mysql | MySQL | 5.7.33 | 🔴 HIGH | CVE-2021-2154 |

### Host: 192.168.1.20 (file-server-01)

- **Status:** up
- **OS:** None

| Port | Protocol | Service | Product | Version | Risk | CVEs |
|------|----------|---------|---------|---------|------|------|
| 445 | tcp | microsoft-ds | Samba | 4.11.6 | 🔴 HIGH | CVE-2020-1472 |
| 3389 | tcp | ms-wbt-server | xrdp | 0.9.12 | 🔴 HIGH | None |

### Host: 192.168.1.30 (backup-server-01)

- **Status:** up
- **OS:** None

| Port | Protocol | Service | Product | Version | Risk | CVEs |
|------|----------|---------|---------|---------|------|------|
| 22 | tcp | ssh | OpenSSH | 7.4p1 | 🟢 LOW | CVE-2018-15473 |
| 8080 | tcp | http | nginx | 1.14.0 | 🟢 LOW | CVE-2019-9511 |

---

**Recommendations:**

1. **Immediate:** Review all HIGH risk findings. Exposed RDP/SMB should be firewalled or VPN-restricted.
2. **Short-term:** Patch services with known CVE matches. Prioritize internet-facing services.
3. **Ongoing:** Implement continuous scanning with authorized scope boundaries.
