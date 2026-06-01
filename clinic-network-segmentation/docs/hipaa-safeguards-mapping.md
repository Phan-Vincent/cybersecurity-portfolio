# HIPAA Security Rule Technical Safeguards Mapping

## Introduction

The HIPAA Security Rule (45 CFR Part 160 and Subparts A and C of Part 164) establishes national standards to protect individuals' electronic personal health information (ePHI) that is created, received, used, or maintained by a covered entity.

This document maps **every network control** in this design to the relevant §164.312 technical safeguard. The goal is to make the compliance justification explicit and auditable.

**All patient data referenced in this project is synthetic.**

---

## §164.312(a)(1) — Access Control

> *"Implement technical policies and procedures for electronic information systems that maintain electronic protected health information to allow access only to those persons or software programs that have been granted access rights."*

### Implementation Specifications

| Spec | Network Control | Location in Project |
|------|----------------|-------------------|
| **Unique User Identification** (Required) | RADIUS authentication per user for VVFM-Clinical Wi-Fi. Each provider has a unique certificate + username. | `docs/vlan-segmentation.md` — Wi-Fi section |
| **Emergency Access Procedure** (Required) | Anti-lockout rule on pfSense (console-only). Break-glass local admin account with 20+ char password stored in clinic safe. | `docs/firewall-rules.md` — Management section |
| **Automatic Logoff** (Addressable) | EHR application enforces 15-minute idle timeout. Network layer: WPA3-Enterprise session rekey every 8 hours. | Acknowledged; app-layer control |
| **Encryption and Decryption** (Addressable) | TLS 1.3 enforced for all EHR access (tcp/443). mTLS between IoT devices and IoT Gateway. | `docs/firewall-rules.md` — rules 3009, 4002 |

### Network Segmentation as Access Control

| Zone | Access to EHR | Justification | HIPAA Principle |
|------|--------------|---------------|-----------------|
| Clinical (VLAN 20) | ✅ Direct (L2 + firewall) | Providers and nurses require real-time EHR access for patient care | Minimum Necessary |
| Medical IoT (VLAN 30) | ❌ Direct blocked | Devices push data to gateway; gateway forwards to EHR. Devices never initiate to EHR server. | Minimum Necessary |
| Guest (VLAN 40) | ❌ Denied | Patients and visitors have zero legitimate need for EHR access | Minimum Necessary |
| Admin (VLAN 50) | ✅ Via jump host, tcp/443 only | Billing staff need read-only billing module access. Firewall limits to EHR tcp/443 only. | Minimum Necessary |
| Management (VLAN 10) | ❌ Denied | IT infrastructure has no clinical role. Physical access only. | Minimum Necessary |

---

## §164.312(b) — Audit Controls

> *"Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information."*

### Network-Level Audit Controls

| Control | Implementation | Evidence Location |
|---------|---------------|-------------------|
| **Firewall Session Logging** | pfSense logs all denied packets and permitted cross-VLAN sessions to local disk + remote SIEM (10.10.10.10) | `docs/firewall-rules.md` — Logging Strategy |
| **DHCP Lease Logging** | All DHCP assignments logged with MAC, hostname, VLAN, timestamp. Enables device-to-IP traceability. | `docs/vlan-segmentation.md` — DHCP section |
| **DNS Query Logging** | Unbound resolver logs all queries (anonymized for Guest VLAN). Identifies C2 beaconing, rebinding attempts. | `docs/threat-model.md` — T-006 |
| **802.1x Authentication Logging** | FreeRADIUS logs every successful/failed authentication attempt to VVFM-Clinical SSID with username + AP location. | `docs/vlan-segmentation.md` — Wi-Fi section |
| **SIEM Retention** | Hot retention: 90 days. Cold/archive: 1 year. Meets HIPAA §164.316(b)(2)(i) 6-year record retention. | `docs/firewall-rules.md` — Logging Strategy |

### What Is Logged (Example)

```
<134>Jun  2 14:32:15 fw-vvw-pfsense filterlog: 3002,,,3002,em1,match,pass,in,4,0x0,,64,12345,0,DF,6,tcp,60,10.10.20.11,10.10.30.1,52341,443,0,S,9876543210:,8192,,mss;nop;wscale;nop;nop;TS:sackOK;eol
```
*Translation: Clinical workstation 10.10.20.11 initiated a new TCP session to IoT Gateway 10.10.30.1 on port 443. This is permitted by firewall rule 3002.*

---

## §164.312(c)(1) — Integrity

> *"Implement technical security measures to guard against unauthorized access to electronic protected health information that is being transmitted over an electronic communications network."*

### Integrity Controls

| Control | Implementation | Evidence Location |
|---------|---------------|-------------------|
| **TLS 1.3 for Data in Transit** | Firewall rules 3009, 6009, 4002 enforce TLS only. HTTP (tcp/80) is denied outbound for all zones except Guest captive portal. | `docs/firewall-rules.md` |
| **mTLS for IoT** | IoT devices present client certificates to IoT Gateway. Prevents rogue devices from injecting falsified vitals data. | `docs/network-diagram.md` — IoT Gateway description |
| **SMB/RDP Inter-VLAN Deny** | Rules 3011, 3012, 60011, 60012 block protocols commonly abused for file tampering and remote manipulation. | `docs/firewall-rules.md` |
| **NTP Time Sync** | All zones sync to pfSense (stratum 2). Accurate timestamps are required for forensic integrity of audit logs. | `docs/firewall-rules.md` — per-zone NTP rules |

---

## §164.312(d) — Person or Entity Authentication

> *"Implement procedures to verify that a person or entity seeking access to electronic protected health information is the one claimed."*

### Authentication at the Network Layer

| Control | Implementation | Evidence Location |
|---------|---------------|-------------------|
| **WPA3-Enterprise for Clinical Wi-Fi** | VVFM-Clinical uses RADIUS (FreeRADIUS on pfSense) with per-user certificates + username/password. | `docs/vlan-segmentation.md` — Wi-Fi table |
| **802.1x Dynamic VLAN Assignment** | Front-desk jack dynamically assigns VLAN based on device authentication. Domain-joined device → VLAN 20. Unknown device → VLAN 40. | `docs/network-diagram.md` — Front Desk note |
| **MAC-Based DHCP Reservations for IoT** | IoT devices receive IPs only if their MAC is pre-registered. Unknown MACs on VLAN 30 are blocked at switchport. | `docs/vlan-segmentation.md` — IoT DHCP |
| **Hidden SSID for IoT** | VVFM-IoT is not broadcast. Reduces casual discovery and connection attempts. | `docs/vlan-segmentation.md` — Wi-Fi table |

---

## §164.312(e)(1) — Transmission Security

> *"Implement technical security measures to guard against unauthorized access to electronic protected health information that is being transmitted over an electronic communications network."*

### Transmission Security Controls

| Control | Implementation | Evidence Location |
|---------|---------------|-------------------|
| **TLS 1.3 Enforcement** | Outbound HTTPS (tcp/443) is the only permitted web protocol for Clinical, Admin, and IoT zones. HTTP is denied. | `docs/firewall-rules.md` — rules 3010, 4011, 6010 |
| **Cipher Suite Hardening** | pfSense uses modern OpenSSL with TLS 1.3 only. Deprecated protocols (SSLv3, TLS 1.0/1.1) are disabled in Unbound + web UI. | Implied by TLS 1.3 requirement |
| **Inter-VLAN Traffic Inspection** | All cross-VLAN traffic passes through the stateful firewall — not just routed at L3. Enables session-level tracking. | `docs/network-diagram.md` — Logical Overview |
| **Guest Network Isolation** | VLAN 40 has no route to any RFC1918 network. Even if a patient runs a packet sniffer, they cannot see clinical traffic. | `docs/firewall-rules.md` — rule 5006 |
| **AP Client Isolation** | Guest Wi-Fi has L2 client isolation enabled — one guest device cannot communicate with another guest device. | `docs/vlan-segmentation.md` — Wi-Fi notes |

---

## §164.312(e)(2)(i) — Integrity Controls (Transmission)

> *"Implement security measures to ensure that electronically transmitted electronic protected health information is not improperly modified without detection until disposed of."*

| Control | Implementation | Evidence Location |
|---------|---------------|-------------------|
| **TLS 1.3 + AEAD Ciphers** | GCM-mode AEAD provides authenticated encryption — tampering is detected at the transport layer. | Implied by TLS 1.3 |
| **mTLS Client Certificates** | IoT device certificates are validated by the gateway. If a device certificate is revoked, the gateway refuses connection. | `docs/network-diagram.md` — IoT Gateway |
| **DICOM Integrity** | Imaging modality sends DICOM over TLS to IoT Gateway. DICOM has native data integrity checks (sequence numbers, checksums). | `docs/firewall-rules.md` — rule 4003 |

---

## §164.312(e)(2)(ii) — Encryption

> *"Encrypt electronic protected health information whenever deemed appropriate."*

| Control | Implementation | Evidence Location |
|---------|---------------|-------------------|
| **TLS 1.3 for All ePHI Transit** | Every ePHI-bearing connection crosses the network via TLS 1.3. | `docs/firewall-rules.md` — throughout |
| **Backup NAS Encryption at Rest** | Backup NAS uses LUKS full-disk encryption. Key escrowed in clinic safe. | `docs/threat-model.md` — T-007 |
| **Management VLAN Air-Gap** | Management interfaces are not exposed over the network. An attacker who compromises a clinical workstation cannot reach the firewall web UI. | `docs/firewall-rules.md` — rule 2999 |
| **WPA3 for All Wi-Fi** | All SSIDs use WPA3 (Enterprise or PSK). WPA2 is disabled on clinical and IoT SSIDs. | `docs/vlan-segmentation.md` — Wi-Fi table |

---

## Summary Crosswalk Table

| HIPAA § | Safeguard Title | Relevant Network Controls | Primary Document |
|---------|----------------|--------------------------|------------------|
| §164.312(a)(1) | Access Control | VLAN segmentation, 802.1x, RADIUS, dynamic VLAN, role-based firewall rules | `vlan-segmentation.md`, `firewall-rules.md` |
| §164.312(b) | Audit Controls | Firewall logging, DHCP logging, DNS logging, 802.1x auth logging, SIEM forwarding | `firewall-rules.md` |
| §164.312(c)(1) | Integrity | TLS 1.3, mTLS, SMB/RDP block, NTP sync | `firewall-rules.md`, `network-diagram.md` |
| §164.312(d) | Person/Entity Authentication | WPA3-Enterprise, 802.1x, MAC reservations, hidden SSID | `vlan-segmentation.md` |
| §164.312(e)(1) | Transmission Security | TLS 1.3 enforcement, inter-VLAN stateful inspection, guest isolation | `firewall-rules.md`, `network-diagram.md` |
| §164.312(e)(2)(i) | Integrity Controls (Transmission) | TLS 1.3 AEAD, mTLS certificate validation, DICOM integrity | `network-diagram.md`, `firewall-rules.md` |
| §164.312(e)(2)(ii) | Encryption | TLS 1.3, LUKS at-rest, WPA3, management air-gap | `firewall-rules.md`, `threat-model.md` |

---

## Compliance Audit Checklist

Use this checklist during a HIPAA security risk assessment or internal audit:

- [ ] Verify all VLAN boundaries exist and match the segmentation table.
- [ ] Confirm no guest device (VLAN 40) can reach any RFC1918 address.
- [ ] Verify IoT devices (VLAN 30) cannot initiate connections to Clinical (VLAN 20).
- [ ] Confirm EHR server (10.10.20.100) is only accessible from VLAN 20 and VLAN 50 (tcp/443 only).
- [ ] Verify Management VLAN (10) has no inbound routed access from user VLANs.
- [ ] Confirm all cross-VLAN sessions are logged to SIEM.
- [ ] Verify TLS 1.3 is the only permitted encryption protocol for ePHI-bearing traffic.
- [ ] Confirm 802.1x is enabled on all clinical access ports.
- [ ] Verify backup NAS is encrypted at-rest and has air-gapped snapshots.
- [ ] Confirm firewall change control requires 2-person review.
- [ ] Verify geoIP blocklist and C2 blocklist are updated at least daily.
- [ ] Confirm SIEM retention meets 6-year requirement (hot + cold storage).

---

## References

1. HIPAA Security Rule — 45 CFR §160, §164.302–318: [https://www.hhs.gov/hipaa/for-professionals/security/index.html](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
2. NIST SP 800-53 Rev. 5 — Security and Privacy Controls for Information Systems and Organizations
3. NIST SP 800-66 Rev. 2 — An Introductory Resource Guide for Implementing the HIPAA Security Rule
4. pfSense Documentation — Firewall Rule Best Practices: [https://docs.netgate.com/pfsense/en/latest/firewall/index.html](https://docs.netgate.com/pfsense/en/latest/firewall/index.html)
5. OWASP IoT Security Verification Standard (ISVS)

> **Disclaimer:** This design is a student/architectural exercise. A production HIPAA implementation requires a qualified security risk assessment, business associate agreements, workforce training, and ongoing monitoring by a qualified professional.
