# Firewall Rules

> **Platform:** pfSense CE 2.7 (or OPNsense)  
> **Philosophy:** Default deny, explicit allow, log all denied traffic, stateful inspection.

---

## Rule Numbering Convention

| Range | Purpose |
|-------|---------|
| 1000–1999 | Emergency / block rules (malware, C2, geoblock) |
| 2000–2999 | Management (VLAN 10) access rules |
| 3000–3999 | Clinical (VLAN 20) rules |
| 4000–4999 | Medical IoT (VLAN 30) rules |
| 5000–5999 | Guest (VLAN 40) rules |
| 6000–6999 | Admin / Billing (VLAN 50) rules |
| 9000–9999 | Global / catch-all rules |

---

## Interface Overview

| Interface | Description | VLAN ID | Network |
|-----------|-------------|-----------|---------|
| WAN | ISP uplink | — | DHCP from ISP |
| MGMT | Management | 10 | 10.10.10.0/24 |
| CLINICAL | Clinical | 20 | 10.10.20.0/24 |
| IOT | Medical IoT | 30 | 10.10.30.0/24 |
| GUEST | Guest / BYOD | 40 | 10.10.40.0/24 |
| ADMIN | Admin / Billing | 50 | 10.10.50.0/24 |

---

## Global Anti-Malware / Geoblock (Floating Rules)

| # | Action | Source | Destination | Protocol | Port | Description | Log |
|---|--------|--------|-------------|----------|------|-------------|-----|
| 1001 | Block | Any | *Known C2 IPs* | Any | Any | Emerging Threats C2 blocklist (daily update) | ✅ |
| 1002 | Block | Any | *Country block: CN, RU, KP, IR* | Any | Any | GeoIP deny — no legitimate clinic traffic | ✅ |
| 1003 | Block | Any | Any | TCP/UDP | 53 (DNS) | Force DNS to pfSense resolver (prevent DNS hijack) | ✅ |
| 1004 | Block | Any | RFC1918 (reverse path) | Any | Any | Block spoofed private IP ingress on WAN | ✅ |

---

## Management (VLAN 10) Rules

> **Default posture:** No inbound access from any user VLAN. Physical switchport or VPN required.

| # | Action | Source | Destination | Protocol | Port | Description | Log |
|---|--------|--------|-------------|----------|------|-------------|-----|
| 2001 | Allow | MGMT net | Any | ICMP | — | Ping for troubleshooting | ❌ |
| 2002 | Allow | MGMT net | Any | TCP/UDP | 53 | DNS queries | ❌ |
| 2003 | Allow | MGMT net | Any | UDP | 123 | NTP time sync | ❌ |
| 2004 | Allow | MGMT net | Any | TCP/UDP | 443 | HTTPS updates (pfSense, packages, SIEM) | ❌ |
| 2005 | Block | MGMT net | Any | TCP/UDP | 80 | HTTP denied — TLS only | ✅ |
| 2006 | Allow | MGMT net | *Vendor update IPs* | TCP/UDP | 443 | IoT vendor update whitelisting (explicit IP list) | ❌ |
| 2099 | Block | MGMT net | Any | Any | Any | Default deny outbound | ✅ |
| 2999 | Block | Any | MGMT net | Any | Any | Default deny inbound from all zones | ✅ |

**Key notes:**
- pfSense web UI (tcp/443 on 10.10.10.1) is bound to MGMT interface only.
- SSH access (tcp/22) is disabled by default; enabled only via console for emergency recovery.
- Anti-lockout rule (console-only) ensures admin access if rule table is corrupted.

---

## Clinical (VLAN 20) Rules

| # | Action | Source | Destination | Protocol | Port | Description | Log |
|---|--------|--------|-------------|----------|------|-------------|-----|
| 3001 | Allow | CLINICAL net | CLINICAL net | Any | Any | Intra-VLAN traffic (EHR, file shares, print) | ❌ |
| 3002 | Allow | CLINICAL net | IOT net | TCP | 443 | Access IoT Gateway (device data review) | ✅ |
| 3003 | Block | CLINICAL net | IOT net | Any | Any | Deny all other IoT access | ✅ |
| 3004 | Block | CLINICAL net | GUEST net | Any | Any | No cross-talk to untrusted zone | ✅ |
| 3005 | Block | CLINICAL net | ADMIN net | Any | Any | No direct access to billing/payroll | ✅ |
| 3006 | Allow | CLINICAL net | Any | ICMP | — | Ping for troubleshooting | ❌ |
| 3007 | Allow | CLINICAL net | Any | TCP/UDP | 53 | DNS (via pfSense resolver) | ❌ |
| 3008 | Allow | CLINICAL net | Any | UDP | 123 | NTP | ❌ |
| 3009 | Allow | CLINICAL net | Any | TCP | 443 | HTTPS to Internet (EHR cloud portal, telehealth) | ❌ |
| 3010 | Block | CLINICAL net | Any | TCP | 80 | HTTP denied — TLS only | ✅ |
| 3011 | Block | CLINICAL net | Any | TCP | 445 | SMB blocked — prevents ransomware lateral spread | ✅ |
| 3012 | Block | CLINICAL net | Any | TCP | 3389 | RDP blocked — no remote desktop to Internet | ✅ |
| 3013 | Block | CLINICAL net | Any | TCP | 22 | SSH outbound blocked | ✅ |
| 3014 | Block | CLINICAL net | Any | TCP | 23 | Telnet blocked (legacy protocol) | ✅ |
| 3015 | Allow | CLINICAL net | *EHR vendor cloud IPs* | TCP | 443 | Explicit allow: EHR SaaS provider (IP whitelist) | ❌ |
| 3016 | Allow | CLINICAL net | *Telehealth platform IPs* | TCP | 443 | Explicit allow: Doxy.me / Zoom Healthcare (IP whitelist) | ❌ |
| 3099 | Block | CLINICAL net | Any | Any | Any | Default deny outbound | ✅ |
| 3999 | Block | Any | CLINICAL net | Any | Any | Default deny inbound from all zones | ✅ |

---

## Medical IoT (VLAN 30) Rules

> **Philosophy:** IoT devices are **data producers only**. They may push to the IoT Gateway. They may not initiate to any other internal zone. Egress is allow-list only.

| # | Action | Source | Destination | Protocol | Port | Description | Log |
|---|--------|--------|-------------|----------|------|-------------|-----|
| 4001 | Allow | IOT net | IOT net | Any | Any | Intra-VLAN (device-to-gateway) | ❌ |
| 4002 | Allow | IOT net | IOT_GW (10.10.30.1) | TCP | 443 | Send normalized HL7/FHIR data to gateway | ✅ |
| 4003 | Allow | IOT net | IOT_GW (10.10.30.1) | TCP | 11112 | DICOM imaging to gateway (if applicable) | ✅ |
| 4004 | Block | IOT net | CLINICAL net | Any | Any | Devices cannot initiate to clinical workstations | ✅ |
| 4005 | Block | IOT net | ADMIN net | Any | Any | Devices cannot reach billing/payroll | ✅ |
| 4006 | Block | IOT net | GUEST net | Any | Any | Devices cannot reach guest network | ✅ |
| 4007 | Block | IOT net | MGMT net | Any | Any | Devices cannot reach management | ✅ |
| 4008 | Allow | IOT net | Any | UDP | 123 | NTP time sync (required for accurate timestamps) | ❌ |
| 4009 | Allow | IOT net | Any | TCP/UDP | 53 | DNS (via pfSense resolver) | ❌ |
| 4010 | Allow | IOT net | *Vendor update IP list* | TCP | 443 | Firmware / software updates (explicit IP whitelist) | ✅ |
| 4011 | Block | IOT net | Any | TCP | 80 | HTTP denied — TLS only for updates | ✅ |
| 4012 | Block | IOT net | Any | Any | Any | Default deny all other Internet access | ✅ |
| 4099 | Block | IOT net | Any | Any | Any | Default deny outbound | ✅ |
| 4999 | Block | Any | IOT net | Any | Any | Default deny inbound from all zones | ✅ |

**IoT Gateway (10.10.30.1) — Special Rules:**

The gateway is a Linux VM running on a VLAN 30 access port. It has a secondary virtual interface on VLAN 20 (via firewall policy, not a physical trunk) to forward data to the EHR server.

| # | Action | Source | Destination | Protocol | Port | Description | Log |
|---|--------|--------|-------------|----------|------|-------------|-----|
| 4050 | Allow | IOT_GW (10.10.30.1) | EHR_SRV (10.10.20.100) | TCP | 443 | Gateway pushes aggregated data to EHR | ✅ |
| 4051 | Block | IOT_GW | Any | Any | Any | Gateway may not access anything else | ✅ |

---

## Guest (VLAN 40) Rules

> **Philosophy:** Internet-only. No access to any RFC1918 network. Aggressive rate limiting and short DHCP leases.

| # | Action | Source | Destination | Protocol | Port | Description | Log |
|---|--------|--------|-------------|----------|------|-------------|-----|
| 5001 | Allow | GUEST net | Any | ICMP | — | Ping (limited to 10 pps per IP) | ❌ |
| 5002 | Allow | GUEST net | Any | TCP/UDP | 53 | DNS (via pfSense resolver) | ❌ |
| 5003 | Allow | GUEST net | Any | UDP | 123 | NTP | ❌ |
| 5004 | Allow | GUEST net | Any | TCP | 80 | HTTP to Internet (captive portal before auth) | ❌ |
| 5005 | Allow | GUEST net | Any | TCP | 443 | HTTPS to Internet | ❌ |
| 5006 | Block | GUEST net | RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) | Any | Any | No access to any internal network | ✅ |
| 5007 | Block | GUEST net | Any | TCP | 445 | SMB blocked (ransomware protection) | ✅ |
| 5008 | Block | GUEST net | Any | TCP | 3389 | RDP blocked | ✅ |
| 5009 | Block | GUEST net | Any | TCP | 22 | SSH blocked | ✅ |
| 5010 | Block | GUEST net | Any | TCP | 25 | SMTP blocked (prevent spam relay) | ✅ |
| 5099 | Block | GUEST net | Any | Any | Any | Default deny outbound | ✅ |
| 5999 | Block | Any | GUEST net | Any | Any | Default deny inbound from all zones | ✅ |

---

## Admin / Billing (VLAN 50) Rules

| # | Action | Source | Destination | Protocol | Port | Description | Log |
|---|--------|--------|-------------|----------|------|-------------|-----|
| 6001 | Allow | ADMIN net | ADMIN net | Any | Any | Intra-VLAN (billing, payroll, print) | ❌ |
| 6002 | Allow | ADMIN net | CLINICAL net | TCP | 443 | Access EHR (read-only billing module) via jump host | ✅ |
| 6003 | Block | ADMIN net | CLINICAL net | Any | Any | Deny all other clinical access | ✅ |
| 6004 | Block | ADMIN net | IOT net | Any | Any | No IoT access | ✅ |
| 6005 | Block | ADMIN net | GUEST net | Any | Any | No guest network access | ✅ |
| 6006 | Allow | ADMIN net | Any | ICMP | — | Ping | ❌ |
| 6007 | Allow | ADMIN net | Any | TCP/UDP | 53 | DNS | ❌ |
| 6008 | Allow | ADMIN net | Any | UDP | 123 | NTP | ❌ |
| 6009 | Allow | ADMIN net | Any | TCP | 443 | HTTPS (insurance portals, ADP, bank) | ❌ |
| 6010 | Block | ADMIN net | Any | TCP | 80 | HTTP denied — TLS only | ✅ |
| 6011 | Block | ADMIN net | Any | TCP | 445 | SMB blocked | ✅ |
| 6012 | Block | ADMIN net | Any | TCP | 3389 | RDP blocked | ✅ |
| 6013 | Allow | ADMIN net | *Insurance clearinghouse IPs* | TCP | 443 | Explicit allow: clearinghouse connections | ❌ |
| 6014 | Allow | ADMIN net | *Payroll SaaS IPs* | TCP | 443 | Explicit allow: ADP / Gusto / etc. | ❌ |
| 6099 | Block | ADMIN net | Any | Any | Any | Default deny outbound | ✅ |
| 6999 | Block | Any | ADMIN net | Any | Any | Default deny inbound from all zones | ✅ |

---

## WAN Inbound Rules (Port Forwards / Rejections)

| # | Action | Source | Destination | Protocol | Port | Description | Log |
|---|--------|--------|-------------|----------|------|-------------|-----|
| 9001 | Block | Any | WAN address | Any | Any | Default deny all inbound — no port forwards | ✅ |
| 9002 | Reject | Any | WAN address | TCP | 22 | Explicit reject SSH (no brute-force noise in logs) | ✅ |
| 9003 | Reject | Any | WAN address | TCP | 3389 | Explicit reject RDP | ✅ |
| 9004 | Reject | Any | WAN address | TCP | 443 | Explicit reject HTTPS (no remote mgmt) | ✅ |
| 9005 | Block | Any | WAN address | ICMP | — | Block ICMP echo-request (smurf / recon) | ✅ |
| 9099 | Block | Any | WAN address | Any | Any | Final default deny | ✅ |

**Note:** There are zero port forwards. Remote access (if ever needed) requires VPN (WireGuard on alternative port, MFA required) — not implemented in this scope.

---

## NAT / Outbound Rules

| Interface | Source | Destination | Translation | Description |
|-----------|--------|-------------|-------------|-------------|
| WAN | MGMT net | Any | WAN IP | Management outbound (updates, NTP) |
| WAN | CLINICAL net | Any | WAN IP | Clinical outbound (HTTPS, telehealth) |
| WAN | IOT net | Any | WAN IP | IoT outbound (NTP, vendor updates) |
| WAN | GUEST net | Any | WAN IP | Guest outbound (HTTP/S only) |
| WAN | ADMIN net | Any | WAN IP | Admin outbound (HTTPS, insurance APIs) |

**Outbound NAT mode:** Automatic — pfSense generates NAT rules for each interface.

**No 1:1 NAT or port forwards.**

---

## Logging Strategy

| Log Destination | What | Retention |
|-----------------|------|-----------|
| pfSense local (tmp) | All blocked packets, 7 days | 7 days |
| Syslog → SIEM (10.10.10.10) | All firewall events, real-time | 90 days hot, 1 year cold |
| SIEM alerts | Any "deny" from VLAN 30 → any other VLAN; any port scan detected; any Guest → RFC1918 attempt | Immediate email to admin |

**Log format:** RFC 5424 syslog, sent via UDP/514 to SIEM VM. Encrypted syslog (TLS/6514) preferred if SIEM supports it.

---

## Rule Validation Checklist

- [ ] Every inter-VLAN flow is justified by a clinical or business requirement.
- [ ] No SMB (tcp/445) crosses VLAN boundaries.
- [ ] No RDP (tcp/3389) leaves any VLAN.
- [ ] HTTP (tcp/80) is blocked outbound for all zones except Guest (captive portal only).
- [ ] Management VLAN has zero inbound routed access.
- [ ] IoT has no outbound access except NTP, DNS, and explicit vendor IPs.
- [ ] Guest cannot reach any RFC1918 network.
- [ ] WAN has zero port forwards and zero inbound allow rules.
- [ ] All deny rules are logged.
- [ ] GeoIP and C2 blocklists are auto-updated daily.
