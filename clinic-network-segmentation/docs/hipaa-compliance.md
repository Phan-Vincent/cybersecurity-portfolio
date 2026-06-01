# HIPAA Security Rule Compliance Mapping

## Scope

This document maps every network control in the Small Clinic Network Segmentation Design to the **HIPAA Security Rule** (45 CFR §164.312) technical safeguards. It is intended for use during a HIPAA Security Risk Assessment (SRA) or OCR audit.

**Disclaimer:** This is a student architecture project with synthetic data. It is not a substitute for a professional HIPAA compliance review. The mapping is based on NIST SP 800-66 Rev. 2 and HHS OCR guidance.

---

## §164.312(a)(1) — Access Control

**Requirement:** Implement technical policies and procedures for electronic information systems that maintain electronic protected health information (ePHI) to allow access only to those persons or software programs that have been granted access rights.

### Implementation Specifications

#### (i) Unique User Identification
| Control | Evidence in Design | Location |
|---------|-------------------|----------|
| 802.1X EAP-TLS on clinical workstations | Each user + device has a unique certificate | `config/vlan-segmentation.csv` — VLAN 20 |
| Active Directory / FreeRADIUS user accounts | Each employee has a unique username + MFA | `docs/architecture.md` — Onboarding Procedure |
| Switch port-to-user mapping | Port security logs associate MAC + VLAN + switch port | `config/firewall-rules.csv` — logging enabled on all denies |

**Rationale:** Unique user IDs prevent shared credentials (e.g., "nurse1/nurse1"). If an incident occurs, the SIEM can trace the action to a specific user and device.

#### (ii) Emergency Access Procedure
| Control | Evidence in Design | Location |
|---------|-------------------|----------|
| Break-glass account | A single local admin account on the EHR server is stored offline (encrypted USB) | `docs/architecture.md` — Offline Backup |
| Emergency firewall rule | A pre-staged "emergency open" rule is disabled by default; enabling it requires manager approval + SIEM alert | `config/firewall-rules.csv` — Rule 999 (commented out) |

**Rationale:** In a disaster (e.g., ransomware locks admin accounts), the clinic needs a way to regain access. The break-glass account is offline and known only to the clinic manager, not the IT contractor.

#### (iii) Automatic Logoff
| Control | Evidence in Design | Location |
|---------|-------------------|----------|
| EHR application session timeout | eClinicalWorks enforces 15-minute idle timeout | Vendor responsibility (documented in BAA) |
| Switch port inactivity | Unused switch ports are disabled; enabled ports have 802.1X re-auth every 8 hours | `config/vlan-segmentation.csv` — Port Security |
| Guest WiFi session timeout | Captive portal expires after 4 hours | `docs/architecture.md` — Guest VLAN |

**Rationale:** Automatic logoff prevents session hijacking if a clinician walks away from a workstation without locking it.

#### (iv) Encryption and Decryption
| Control | Evidence in Design | Location |
|---------|-------------------|----------|
| TLS 1.3 enforcement on EHR traffic | Firewall strips TLS 1.2 and below; only TLS 1.3 is allowed to VLAN 20 | `config/firewall-rules.csv` — Rule 120 (TLS 1.3 only) |
| DICOM over TLS | Medical imaging traffic is wrapped in TLS 1.3 via the IoT gateway | `docs/architecture.md` — IoT Gateway Protocol Whitelist |
| Management traffic encryption | SSH (port 22) and HTTPS (port 443) only; no Telnet, HTTP, or SNMPv1/v2c | `config/firewall-rules.csv` — Deny rules for plaintext mgmt |
| Syslog encryption | Wazuh agents use AES-encrypted transport to the SIEM | `docs/architecture.md` — Security VLAN |

**Rationale:** Encryption ensures that even if an attacker captures network traffic (e.g., via a span port misconfiguration or passive tap), they cannot read PHI.

---

## §164.312(b) — Audit Controls

**Requirement:** Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use ePHI.

| Control | Evidence in Design | Location |
|---------|-------------------|----------|
| Firewall deny logging | Every denied packet is logged to syslog (VLAN 50) | `config/firewall-rules.csv` — all deny rules have `log=true` |
| 802.1X authentication logs | RADIUS server logs every auth success/failure to VLAN 50 | `docs/architecture.md` — Admin VLAN |
| Wazuh endpoint logging | File integrity monitoring (FIM) on EHR server; registry monitoring on Windows workstations | `docs/architecture.md` — Security VLAN |
| NIDS packet capture | Suricata on VLAN 50 captures full packet payloads for 7 days (rolling) | `docs/architecture.md` — NIDS Sensor |
| SIEM correlation | Wazuh server correlates firewall logs + endpoint logs + NIDS alerts | `docs/architecture.md` — SIEM |
| Log retention | 6 years online (SIEM) + 6 years offline (encrypted USB backup) | `docs/architecture.md` — Offline Backup |

**Rationale:** Audit controls are required for forensic investigation and OCR compliance. If a breach occurs, the clinic must be able to determine what data was accessed, by whom, and when. The 6-year retention aligns with HIPAA documentation requirements (§164.530(j)).

---

## §164.312(c)(1) — Integrity

**Requirement:** Implement electronic mechanisms to corroborate that ePHI has not been altered or destroyed in an unauthorized manner.

| Control | Evidence in Design | Location |
|---------|-------------------|----------|
| Network segmentation prevents tampering | VLAN 20 (Clinical) is isolated. An attacker on another VLAN cannot reach the EHR server to modify records | `config/firewall-rules.csv` — Default deny between VLANs |
| Wazuh FIM on EHR server | SHA-256 file hashes monitored. Any change to the EHR database triggers an alert | `docs/architecture.md` — Security VLAN |
| IoT gateway checksum validation | Firmware updates are verified (SHA-256) before flashing | `docs/architecture.md` — IoT Gateway |
| DICOM integrity | DICOM protocol includes data element validation; the gateway drops malformed DICOM packets | `docs/architecture.md` — IoT Gateway Protocol Whitelist |
| Backup integrity | Offline backup is checksummed weekly. The checksum is stored in the SIEM | `docs/architecture.md` — Offline Backup |

**Rationale:** Integrity is about preventing unauthorized modification. Segmentation is a **network-layer integrity control** — it stops the attacker from reaching the data in the first place. FIM and checksums are **application-layer** controls that detect modification if it occurs.

---

## §164.312(d) — Person or Entity Authentication

**Requirement:** Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.

| Control | Evidence in Design | Location |
|---------|-------------------|----------|
| 802.1X EAP-TLS | Device certificate + user credentials required to join VLAN 10 or 20 | `config/vlan-segmentation.csv` — VLAN 10, 20 |
| RADIUS authentication | FreeRADIUS server validates credentials against AD or local user DB | `docs/architecture.md` — Admin VLAN |
| Firewall admin MFA | OPNsense admin login requires TOTP (Google Authenticator) | `docs/architecture.md` — Management VLAN |
| Jump host MFA | Any remote/vendor access to clinical systems requires MFA + session recording | `docs/architecture.md` — DMZ |
| MAC address filtering | IoT devices have static DHCP reservations by MAC. Unknown MACs are dropped | `config/ip-addressing.csv` — IoT static reservations |

**Rationale:** Authentication ensures that only authorized users and devices can access clinical systems. The combination of device certificates (something you have) + user credentials (something you know) + MFA (something you have) provides strong multi-factor authentication.

---

## §164.312(e)(1) — Transmission Security

**Requirement:** Implement technical security measures to guard against unauthorized access to ePHI that is being transmitted over an electronic communications network.

#### (i) Integrity Controls
| Control | Evidence in Design | Location |
|---------|-------------------|----------|
| TLS 1.3 with AEAD | All EHR traffic uses AES-GCM, which provides both confidentiality and integrity | `config/firewall-rules.csv` — TLS 1.3 enforcement |
| DICOM TLS | Medical imaging traffic is integrity-protected via TLS | `docs/architecture.md` — IoT Gateway |
| Firewall stateful inspection | Connection tracking ensures packets are part of a valid session; spoofed packets are dropped | `config/firewall-rules.csv` — Stateful rules |

#### (ii) Confidentiality Controls
| Control | Evidence in Design | Location |
|---------|-------------------|----------|
| VLAN segmentation | Clinical traffic never transits the Guest or Admin VLANs | `config/vlan-segmentation.csv` |
| Firewall inter-VLAN ACLs | Even if VLANs share a switch, the firewall enforces isolation at L3 | `config/firewall-rules.csv` |
| Guest WiFi isolation | Patients cannot sniff each other's traffic or internal traffic | `docs/architecture.md` — Guest VLAN |
| Management VLAN isolation | Switch/firewall management is on a separate VLAN with no user traffic | `config/vlan-segmentation.csv` — VLAN 100 |
| No plaintext protocols | Telnet, FTP, HTTP, SNMPv1/v2c are denied by firewall | `config/firewall-rules.csv` — Deny rules |

**Rationale:** Transmission security protects data in motion. Segmentation ensures that even if an attacker is on the network, they cannot see clinical traffic. TLS ensures that even if an attacker captures traffic, they cannot read it.

---

## Summary Table: All Controls → HIPAA Requirements

| Control | §164.312(a)(1) Access Control | §164.312(b) Audit | §164.312(c)(1) Integrity | §164.312(d) Auth | §164.312(e)(1) Transmission |
|---------|-------------------------------|---------------------|--------------------------|-------------------|------------------------------|
| VLAN Segmentation | ✓ Unique user ID (per VLAN) | ✓ | ✓ Prevents tampering | ✓ Per-VLAN auth | ✓ Isolates traffic |
| Firewall Default Deny | ✓ | ✓ Logging | ✓ | ✓ | ✓ |
| 802.1X + EAP-TLS | ✓ | ✓ Auth logs | | ✓ Strong auth | |
| TLS 1.3 Enforcement | ✓ Encryption | | ✓ AEAD integrity | | ✓ Confidentiality |
| IoT Gateway + Whitelist | ✓ | ✓ Gateway logs | ✓ Checksums | | ✓ DICOM TLS |
| Guest WiFi Isolation | ✓ | ✓ | | | ✓ |
| SIEM / Wazuh | ✓ | ✓ Central audit | ✓ FIM | ✓ Auth correlation | |
| NIDS / Suricata | ✓ | ✓ Packet capture | ✓ Anomaly detection | | ✓ |
| Offline Backup | | ✓ 6-year retention | ✓ Checksums | | |
| Port Security | ✓ | ✓ | | ✓ Device auth | |
| Management VLAN | ✓ | ✓ | ✓ | ✓ | ✓ |
| DMZ Proxy | ✓ | ✓ | ✓ | ✓ | ✓ TLS pinning |
| Jump Host + MFA | ✓ | ✓ Session recording | | ✓ MFA | ✓ |
| DNS Filtering (Quad9) | ✓ | | | | ✓ Blocks C2 |

---

## Compliance Checklist (Generated by Script)

Run the following to generate a printable checklist:

```bash
python3 scripts/generate-compliance-checklist.py
```

This produces `output/hipaa-checklist.md` with a checkbox for every control, organized by §164.312 requirement. Use it during your SRA or share it with your Business Associate.
