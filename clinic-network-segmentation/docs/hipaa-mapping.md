# HIPAA Security Rule Crosswalk

This document maps every technical safeguard in the HIPAA Security Rule (45 CFR §164.312) to a specific control in the clinic network segmentation design. It also maps to corresponding NIST SP 800-53 Rev 5 controls for students learning federal security frameworks.

---

## §164.312(a)(1) — Access Control

| Implementation | Network Control | NIST Mapping |
|---------------|----------------|--------------|
| Role-based access | VLAN separation (Admin, Clinical, Devices, IoT, Guest) | AC-2, AC-3 |
| Minimum necessary | Firewall default-deny; explicit allow per service/port | AC-6 |
| Unique user identification | Active Directory + RADIUS per user; no shared credentials for EHR | IA-2 |
| Emergency access | Break-glass local admin; sealed envelope in safe; 48-hour audit | AC-2(11) |
| Automatic logoff | GPO: 15-minute idle lock on Clinical workstations | AC-11 |
| Encryption & decryption | BitLocker (Windows) / FileVault (Mac) on all Clinical & Admin workstations | SC-13, SC-28 |

**Rationale:** VLANs are the first line of access control. A clinician's workstation on VLAN 20 cannot reach a domain controller on VLAN 10 because the firewall enforces the "minimum necessary" network path. This is defense-in-depth: even if AD credentials are phished, the network topology limits lateral movement.

---

## §164.312(b) — Audit Controls

| Implementation | Network Control | NIST Mapping |
|---------------|----------------|--------------|
| Audit logs | OPNsense logs all inter-VLAN connections (pass/block) | AU-6 |
| Log integrity | Windows Event Forwarder → Graylog VM (VLAN 10). Logs are hashed at ingestion. | AU-9 |
| Log review | Weekly log review script (`scripts/audit-review.py`) flags: Admin→Clinical RDP, MedDevices outbound attempts, failed 802.1X auth | AU-6(1) |
| Retention | 6 years (CA state requirement + HIPAA). Graylog index rotation monthly. | AU-11 |

**Rationale:** A small clinic cannot afford a 24/7 SOC. Automated log review scripts + weekly manager review is a realistic baseline. The key is that logs exist and are protected from tampering (hashed, separate VLAN).

---

## §164.312(c)(1) — Integrity

| Implementation | Network Control | NIST Mapping |
|---------------|----------------|--------------|
| Data integrity | DICOM TLS (Part 15) ensures imaging data is not modified in transit | SC-8 |
| Firmware integrity | Medical device updates are staged on Admin jump host, SHA-256 verified before push | SI-7 |
| USB blocking | GPO denies removable storage on Clinical VLAN workstations | MP-7 |

**Rationale:** Integrity is often overlooked in network designs. By forcing all medical device updates through a single jump host (VLAN 10 → VLAN 30 only), we create a chokepoint for verification. USB blocking prevents the "sneakernet" bypass of network controls.

---

## §164.312(d) — Person or Entity Authentication

| Implementation | Network Control | NIST Mapping |
|---------------|----------------|--------------|
| User authentication | 802.1X on wired Clinical ports (EAP-TLS cert + AD password) | IA-2(1), IA-2(2) |
| Device authentication | MAC ACL for IoT devices (static DHCP reservations, no dynamic IoT) | IA-3 |
| Remote authentication | WireGuard VPN + TOTP 2FA for remote clinicians | IA-2(1), IA-2(2) |
| Jump host | Admin access to MedDevices requires 2FA hardware token (YubiKey) | IA-2(12) |

**Rationale:** 802.1X is "enterprise" but free with Windows Server NPS or FreeRADIUS. For a 25-staff clinic, the certificate deployment overhead is manageable (one GPO push). The alternative — MAC-based port security — is weaker but acceptable for the smallest offices.

---

## §164.312(e)(1) — Transmission Security

| Implementation | Network Control | NIST Mapping |
|---------------|----------------|--------------|
| Integrity controls | TLS 1.3 for all web traffic; DICOM TLS for imaging | SC-8 |
| Encryption | WireGuard (modern crypto, no legacy cipher suites) for remote access | SC-13 |
| No unencrypted protocols | Firewall blocks Telnet, FTP, HTTP (port 80), SMBv1 across all VLANs | SC-8(1) |

**Rationale:** Small clinics often rely on EHR SaaS (e.g., Athenahealth, eClinicalWorks). The transmission security control applies to the *clinic's* network path to that SaaS, not the vendor's internal infrastructure. TLS 1.3 inspection on OPNsense ensures no downgrade attacks.

---

## §164.312(e)(2)(ii) — Encryption (Addressable)

| Implementation | Network Control | NIST Mapping |
|---------------|----------------|--------------|
| Full-disk encryption | BitLocker on all Windows Clinical/Admin workstations; recovery keys in AD | SC-28 |
| Backup encryption | Cloud backup (Backblaze B2 / Wasabi) uses client-side AES-256 before upload | SC-28(1) |
| Mobile device encryption | Clinic iPads (patient intake) enrolled in MDM with enforced encryption | SC-28 |

**Rationale:** "Addressable" does not mean "optional." For a small clinic without 24/7 guards, physical theft of a workstation is a real risk. Full-disk encryption is the cheapest insurance policy.

---

## Summary Matrix

| Safeguard | VLAN 10 Admin | VLAN 20 Clinical | VLAN 30 MedDevices | VLAN 40 MedIoT | VLAN 50 Guest |
|-----------|--------------|-----------------|-------------------|---------------|--------------|
| Access Control | 802.1X + jump host | 802.1X + GPO lock | MAC ACL + no internet | MAC ACL + cloud only | Captive portal |
| Audit | Full syslog | Workstation + firewall | Firewall only | Firewall only | Firewall only |
| Integrity | GPO + manual verify | USB block + DLP | Firmware staging | Cloud dashboard | N/A |
| Authentication | YubiKey + AD cert | AD cert + password | Device cert (if supported) | Pre-shared key (isolated) | Open |
| Transmission | TLS 1.3 + WireGuard | TLS 1.3 + DICOM TLS | DICOM TLS | TLS 1.3 | TLS 1.3 |
| Encryption | BitLocker | BitLocker | N/A (embedded) | N/A | N/A |

---

## NIST SP 800-66 Rev. 2 Reference

> "For small organizations, the Security Rule is intended to be scalable and flexible. The covered entity must assess its own needs and capabilities to determine the most appropriate security measures."

This design follows the **NIST SP 800-66 "small organization" profile**: prioritize network segmentation (cheap, high impact) over expensive enterprise tools (SIEM, DLP, NAC). As the clinic grows, controls can be upgraded without re-architecting the network.
