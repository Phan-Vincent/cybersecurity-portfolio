# Small Clinic Network Segmentation Design

> A defense-in-depth network architecture for a 3-provider primary care clinic, built around HIPAA Security Rule technical safeguards and zero-trust principles for clinical IoT. This is a student design project grounded in real healthcare workflow experience.

**Author:** Vincent Phan — [github.com/Phan-Vincent](https://github.com/Phan-Vincent)\
**Role:** CVS Pharmacy Technician (CPhT) | CSU San Bernardino BS-IS Cybersecurity (Fall 2026)\
**Date:** 2026-06-02  
**License:** MIT

---

## Problem Statement

Small medical clinics (3–10 providers, ~25 staff, 50+ connected devices) face a security paradox: they handle Protected Health Information (PHI) under HIPAA, but rarely have dedicated IT staff or enterprise budgets. A typical flat network leaves EHR workstations, guest Wi-Fi, and unpatched medical IoT on the same broadcast domain — one compromised thermostat or phishing click becomes a lateral-movement highway to every patient record.

This project designs a **segmented, defensible network** using open-source components (pfSense/OPNsense, managed switches, VLAN-aware APs) that a small clinic could realistically deploy and maintain.

---

## What This Demonstrates

1. **Defense-in-Depth Architecture** — Layered controls: network segmentation → host-based firewalls → access control → monitoring → physical separation.
2. **HIPAA Security Rule Mapping** — Every VLAN and firewall rule maps to a 164.312 technical safeguard (§164.312(a)(1) access control, §164.312(e)(1) transmission security, etc.).
3. **Clinical Workflow Awareness** — VLAN boundaries respect how a clinic actually works: clinicians roam between exam rooms, printers must accept jobs from multiple subnets, imaging DICOM traffic has strict latency needs, and the front desk needs internet + EHR access simultaneously.
4. **Zero-Trust for IoT** — Medical devices (imaging, infusion pumps, patient monitors) are treated as untrusted by default: no internet, no cross-VLAN access, managed via a jump host.
5. **Runbook & Automation** — Included Python scripts validate the segmentation model and generate firewall rule templates from a YAML policy file; not just a diagram.

---

## Network Overview

### Mermaid Diagram

```mermaid
graph TD
    subgraph Internet
        I[Internet / ISP]
    end

    subgraph Edge["Edge Router/Firewall (pfSense)"]
        FW[OPNsense<br/>192.168.255.1/24]
    end

    subgraph Core["Managed Core Switch (VLAN Trunk)"]
        SW[Cisco/Aruba/UniFi<br/>L3 Routing Off]
    end

    subgraph Admin["VLAN 10: Admin & IT (192.168.10.0/24)"]
        AD1[Domain Controller<br/>DC-CLINIC01<br/>10.10]
        AD2[Jump Host<br/>IT-ADMIN-01<br/>10.20]
        AD3[Management Workstation<br/>10.30]
    end

    subgraph Clinical["VLAN 20: Clinical Workstations (192.168.20.0/24)"]
        CW1[Provider Workstation A<br/>20.10]
        CW2[Nurse Station<br/>20.20]
        CW3[Front Desk<br/>20.30]
        CW4[Provider Workstation B<br/>20.40]
    end

    subgraph Devices["VLAN 30: Medical Devices (192.168.30.0/24)"]
        MD1[Ultrasound (DICOM)<br/>30.10]
        MD2[Patient Monitor<br/>30.20]
        MD3[Infusion Pump Controller<br/>30.30]
    end

    subgraph IoT["VLAN 40: Medical IoT / Building (192.168.40.0/24)"]
        IOT1[IP Security Camera<br/>40.10]
        IOT2[HVAC Controller<br/>40.20]
        IOT3[Smart Door Lock<br/>40.30]
        IOT4[UPS Network Card<br/>40.40]
    end

    subgraph Guest["VLAN 50: Guest Wi-Fi (10.50.0.0/24)"]
        GW1[Patient Phone #1]
        GW2[Patient Phone #2]
        GW3[Guest Laptop]
    end

    subgraph DMZ["VLAN 99: DMZ (192.168.99.0/24)"]
        DMZ1[Patient Portal Proxy<br/>99.10]
        DMZ2[VPN Terminator<br/>99.20]
    end

    I --> FW
    FW --> SW
    SW --> Admin
    SW --> Clinical
    SW --> Devices
    SW --> IoT
    SW --> Guest
    SW --> DMZ

    style Internet fill:#ffcccc
    style Edge fill:#ffeebb
    style Guest fill:#e6f3ff
    style Devices fill:#ffe6e6
    style IoT fill:#fff0e6
```

### ASCII Diagram (for terminals & quick reference)

```
                                 +-----------+
                                 |  Internet |
                                 +-----+-----+
                                       |
                                 +-----v-----+
                                 |  OPNsense |  <-- pfSense/OPNsense Firewall/Router
                                 | 192.168   |      All routing, NAT, ACLs, IDS
                                 | .255.1/24 |
                                 +-----+-----+
                                       | Trunk (tagged VLANs 10,20,30,40,50,99)
                                 +-----v-----+
                                 |  Managed  |
                                 |  Switch   |  <-- UniFi/Cisco/Aruba L2
                                 |  (Trunk)  |
                                 +--+--+--+--+
                                    |  |  |  |
              +---------------------+  |  |  +---------------------+
              |                        |  |                        |
       +------v------+          +------v--+------+          +------v------+
       |  VLAN 10    |          |   VLAN 20      |          |  VLAN 30    |
       |  Admin/IT   |          |  Clinical WS   |          |  Med Devices|
       | 192.168.10  |          | 192.168.20     |          | 192.168.30  |
       | .0/24       |          | .0/24          |          | .0/24       |
       +------+------+          +--------+-------+          +------+------+
              |                          |                           |
    +---------+---------+      +---------+---------+       +---------+---------+
    |         |         |      |         |         |       |         |         |
 +--v-+    +--v-+    +--v-+ +--v-+    +--v-+    +--v-+  +--v-+    +--v-+    +--v-+
 | DC |    |Jump|    |Mgmt| |Prov|    |Nurse |   |Front| |Ultras|   |Pat |    |Infu|
 |    |    |Host|    |WS  | | WS |    |Sta   |   |Desk | |ound |   |Mon |    |sion|
 |10.10|   |10.20|   |10.30|20.10|   |20.20 |   |20.30| |30.10|   |30.20|   |30.30|
 +----+    +----+    +----+ +----+    +-----+    +----+ +----+    +----+    +----+

       +------v------+          +------v------+
       |  VLAN 40    |          |  VLAN 50    |
       |  Medical IoT|          |  Guest WiFi |
       | 192.168.40  |          | 10.50.0.0   |
       | .0/24       |          | /24         |
       +------+------+          +------+------+
              |                        |
    +---------+---------+      +-------+-------+
    |         |         |      |       |       |
 +--v-+    +--v-+    +--v-+  +--v-+  +--v-+  +--v-+
 |Cam |    |HVAC|    |Lock|  |Phone|  |Phone|  |Lapt|
 |40.10|   |40.20|   |40.30| | #1  |  | #2  |  |op  |
 +----+    +----+    +----+  |50.10|  |50.20|  |50.30|
                             +----+   +----+   +----+
```

---

## VLAN & Segmentation Plan

| VLAN ID | Name | CIDR | Purpose | DHCP Pool | Gateway |
|---------|------|------|---------|-----------|---------|
| 10 | Admin | 192.168.10.0/24 | Domain controllers, RADIUS, jump hosts, switch/firewall management | .100–.199 | .1 |
| 20 | Clinical | 192.168.20.0/24 | Provider & nurse EHR workstations, front desk | .100–.199 | .1 |
| 30 | MedDevices | 192.168.30.0/24 | Imaging, monitors, infusion pumps (no internet) | .100–.149 | .1 |
| 40 | MedIoT | 192.168.40.0/24 | Cameras, HVAC, door locks, UPS, badge readers | .100–.199 | .1 |
| 50 | Guest | 10.50.0.0/24 | Patient & visitor Wi-Fi | .100–.250 | .1 |
| 99 | DMZ | 192.168.99.0/24 | VPN terminator, patient portal reverse proxy | .100–.149 | .1 |

### Segmentation Rationale (Defense-in-Depth)

1. **Clinical Workstations (VLAN 20)** are the primary PHI interface. They need EHR, printing, and limited internet (for EHR SaaS/cloud backup). They must NOT reach MedDevices management interfaces directly.
2. **Medical Devices (VLAN 30)** are the most vulnerable segment. Many run embedded Windows/Linux with 5–10 year support cycles and cannot be patched quickly. They are **denied all internet access** and only accept inbound from Admin jump hosts (for maintenance) and Clinical (for DICOM/HL7 pushes). This is the "crown jewels" ring-fence.
3. **Medical IoT (VLAN 40)** is separated from MedDevices because IoT vendors have poor security track records (default creds, cloud-backhaul). Cameras and HVAC get internet (for cloud dashboards) but are blocked from all RFC1918 except their own subnet — a breach here cannot pivot to EHR or imaging.
4. **Guest (VLAN 50)** is RFC1918-isolated with client isolation enabled on the access point. A malicious or compromised patient device cannot even see another guest device.
5. **Admin (VLAN 10)** is where identity lives (RADIUS/AD). Admin workstations can SSH to firewalls and switch management VLANs, but only via a jump host with 2FA. Admin is the only segment with outbound SMB/RDP to other VLANs (controlled).
6. **DMZ (VLAN 99)** hosts the single externally accessible service: a WireGuard VPN terminator for remote clinicians. No PHI lives here; traffic is tunneled directly to Clinical VLAN via firewall rules.

---

## Firewall Rules (OPNsense / pfSense Style)

Rules are organized by **interface/VLAN** (rules apply to traffic *entering* that interface). Default-deny is implied everywhere.

### WAN → Any (Inbound from Internet)

| Action | Proto | Source | Destination | Port | Description |
|--------|-------|--------|-------------|------|-------------|
| Block | * | * | * | * | Default deny all inbound |
| Pass | UDP | Any | DMZ_WAN (99.20) | 51820 | WireGuard VPN terminator |
| Pass | TCP | Any | DMZ_WAN (99.10) | 80, 443 | Patient portal reverse proxy (TLS 1.3 only) |

### Admin (VLAN 10) → Any (Outbound)

| Action | Proto | Source | Destination | Port | Description |
|--------|-------|--------|-------------|------|-------------|
| Pass | TCP | Admin_Net | Firewall_Mgmt | 22, 443 | Manage firewalls & switches |
| Pass | TCP | Admin_Net | Clinical (20.0/24) | 445, 3389 | RDP/SMB support tickets only (logged) |
| Pass | TCP | Admin_Net | MedDevices (30.0/24) | 22, 443, 11112 | DICOM SCP maintenance; jump host only |
| Pass | TCP | Admin_Net | MedIoT (40.0/24) | 22, 80, 443 | IoT management interfaces |
| Pass | TCP/UDP | Admin_Net | Any | 53 | DNS (forwarder) |
| Pass | TCP/UDP | Admin_Net | Any | 123 | NTP |
| Block | * | Admin_Net | Guest (50.0/24) | * | No admin → guest (prevent lateral) |
| Block | * | Admin_Net | DMZ (99.0/24) | * | No direct admin → DMZ |

### Clinical (VLAN 20) → Any (Outbound)

| Action | Proto | Source | Destination | Port | Description |
|--------|-------|--------|-------------|------|-------------|
| Pass | TCP | Clinical_Net | Internet | 443 | EHR cloud, HTTPS only (TLS inspection proxy) |
| Pass | TCP | Clinical_Net | Clinical_Net | * | Intra-VLAN allowed (printing, file shares) |
| Pass | TCP | Clinical_Net | MedDevices (30.0/24) | 104, 11112 | DICOM push to imaging; HL7 MLLP |
| Pass | TCP | Clinical_Net | Admin (10.0/24) | 53 | DNS queries to internal resolver |
| Block | * | Clinical_Net | Admin (10.0/24) | 22, 3389, 445 | No management protocol access |
| Block | * | Clinical_Net | MedIoT (40.0/24) | * | No clinical → IoT |
| Block | * | Clinical_Net | Guest (50.0/24) | * | No clinical → guest |
| Block | * | Clinical_Net | DMZ (99.0/24) | * | No direct clinical → DMZ |

### MedDevices (VLAN 30) → Any (Outbound)

| Action | Proto | Source | Destination | Port | Description |
|--------|-------|--------|-------------|------|-------------|
| Pass | TCP | MedDevices_Net | Admin (10.0/24) | 53 | DNS (internal resolver only) |
| Pass | TCP | MedDevices_Net | Clinical (20.0/24) | 104, 11112 | DICOM/HL7 responses |
| Block | * | MedDevices_Net | Any | * | **Explicit deny all other traffic** |

**Critical note:** MedDevices have **no internet access**. Patch downloads are staged on the Admin jump host and pushed via SCP/SMB after hash verification.

### MedIoT (VLAN 40) → Any (Outbound)

| Action | Proto | Source | Destination | Port | Description |
|--------|-------|--------|-------------|------|-------------|
| Pass | TCP/UDP | MedIoT_Net | Internet | 443, 123 | Cloud dashboards (TLS), NTP |
| Pass | TCP | MedIoT_Net | MedIoT_Net | * | Intra-VLAN |
| Block | * | MedIoT_Net | RFC1918 | * | **No access to any private subnet** |
| Block | * | MedIoT_Net | Internet | 22, 23, 80, 3389 | Block management protocols outbound |

### Guest (VLAN 50) → Any (Outbound)

| Action | Proto | Source | Destination | Port | Description |
|--------|-------|--------|-------------|------|-------------|
| Pass | TCP/UDP | Guest_Net | Internet | 53, 80, 443 | Web browsing only |
| Block | * | Guest_Net | RFC1918 | * | **No access to clinic networks** |
| Block | * | Guest_Net | Guest_Net | * | Client isolation (AP layer) |

### DMZ (VLAN 99) → Any (Outbound)

| Action | Proto | Source | Destination | Port | Description |
|--------|-------|--------|-------------|------|-------------|
| Pass | TCP | DMZ_Net | Internet | 80, 443 | Let's Encrypt, package updates |
| Pass | TCP/UDP | VPN_Tunnel_Net | Clinical (20.0/24) | * | WireGuard peer → clinical (tunnel interface) |
| Block | * | DMZ_Net | RFC1918 | * | No DMZ → other internal VLANs |

---

## Threat Model & Security Rationale

### STRIDE-Informed Threats

| Threat | Segment | Mitigation | HIPAA Safeguard |
|--------|---------|-----------|-----------------|
| **Spoofing** (rogue AP / evil twin) | Guest | WPA3-Enterprise on Admin/Clinical; captive portal + MAC ACL on Guest | §164.312(a)(2)(i) Unique User Identification |
| **Tampering** (DICOM man-in-the-middle) | MedDevices ↔ Clinical | VLAN isolation + DICOM TLS (DICOM Part 15); no cross-VLAN routing | §164.312(e)(1) Transmission Security |
| **Repudiation** (who accessed the EHR?) | Clinical | RADIUS accounting + local syslog → SIEM | §164.312(b) Audit Controls |
| **Information Disclosure** (IoT exfil) | MedIoT | Default-deny outbound; TLS-only cloud; no RFC1918 access | §164.312(a)(1) Access Control |
| **Denial of Service** (imaging flood) | MedDevices | Rate-limit DICOM ports; separate VLAN prevents broadcast storm impact on EHR | §164.312(a)(1) Access Control |
| **Elevation of Privilege** (phish → admin) | Admin | Jump host + 2FA; no direct internet from Admin workstations; split DNS | §164.312(d) Person or Entity Authentication |

### Why This Is "Small Clinic Realistic"

- **Hardware:** A used Dell OptiPlex ($200) runs OPNsense. A UniFi 24-port switch ($250) handles VLANs. UniFi APs ($100/ea) do guest isolation. Total < $1,000 — believable for a small practice.
- **Maintenance:** Rules are validated by `scripts/validate-segmentation.py` against `config/vlan-segmentation.csv` and `config/firewall-rules.csv`. A part-time IT contractor (or a motivated office manager) can update the CSV files and re-run the script rather than hand-editing OPNsense UI.
- **No false promises:** This design does NOT include an enterprise SIEM, NAC, or EDR. It recommends **syslog forwarding to a $5/mo VPS running Wazuh or Graylog** — a student-researcher stretch goal, not a vendor fantasy.

---

## HIPAA Security Rule Mapping

| Safeguard (§164.312) | Implementation in This Design |
|---------------------|------------------------------|
| **(a)(1) Access Control** | VLANs enforce role-based network access. Firewall rules are default-deny. Guest cannot reach Clinical. MedDevices cannot reach Internet. |
| **(a)(2)(i) Unique User ID** | RADIUS (FreeRADIUS on Admin VLAN) + Active Directory. Each clinician has unique creds; shared front-desk accounts are emergency-only and heavily logged. |
| **(a)(2)(ii) Emergency Access** | Break-glass local admin account on Clinical workstations (password in sealed envelope, tamper-evident bag, stored in clinic manager safe). |
| **(a)(2)(iii) Automatic Logoff** | GPO: 15-minute idle screen lock on Clinical workstations. |
| **(a)(2)(iv) Encryption** | WireGuard VPN for remote access. TLS 1.3 on all HTTPS. DICOM TLS (Part 15) for imaging. BitLocker/FileVault on workstations. |
| **(b) Audit Controls** | OPNsense logs all inter-VLAN traffic. Windows Event Forwarder to Graylog VM. Syslog retention: 6 years (CA state + HIPAA). |
| **(c)(1) Integrity** | SHA-256 verification of medical device firmware staged on jump host. GPO denies USB mass storage on Clinical. |
| **(d) Person/Entity Authentication** | 802.1X on wired Clinical ports (certificate + AD cred). WPA3-Enterprise on secure Wi-Fi. |
| **(e)(1) Transmission Security** | TLS 1.3 for all web. WireGuard for remote. DICOM TLS for imaging. No unencrypted protocols cross-VLAN. |
| **(e)(2)(ii) Encryption (addressable)** | Full-disk encryption on all Clinical and Admin workstations. |

---

## Repository Layout

```
clinic-network-segmentation/
├── README.md                     # This file
├── LICENSE                       # MIT
├── docs/
│   ├── architecture.md            # Per-VLAN design, onboarding, backup strategy
│   ├── vlan-segmentation.md       # VLAN plan narrative
│   ├── firewall-rules.md          # Rule-by-rule rationale
│   ├── network-diagram.md         # Diagram walkthrough
│   ├── threat-model.md            # Expanded STRIDE + DREAD analysis
│   ├── hipaa-compliance.md        # §164.312 control-by-control evidence map
│   ├── hipaa-mapping.md           # Full safeguard crosswalk with NIST references
│   └── hipaa-safeguards-mapping.md # Technical safeguards (§164.312) summary
├── diagrams/
│   ├── network-ascii.txt          # ASCII art for quick terminal viewing
│   ├── network-diagram.txt        # Detailed text diagram
│   └── network-mermaid.md         # Mermaid source (renders on GitHub)
├── config/
│   ├── vlan-segmentation.csv        # VLAN table + DHCP + addressing details (CSV)
│   ├── firewall-rules.csv           # Firewall rules in CSV format
│   └── ip-addressing.csv            # IP addressing plan
├── data/
│   └── sample-device-inventory.csv  # Synthetic clinic device list (no real PHI)
├── scripts/
│   ├── validate-segmentation.py     # Validates configs + inventory against design constraints
│   └── generate-compliance-checklist.py  # Generates HIPAA compliance checklist
├── tests/                           # pytest suite for both scripts
└── .gitignore
```

---

## How to Run

### 1. Validate the Segmentation Policy

```bash
cd scripts
python3 validate-segmentation.py
```

Checks:
- No overlapping IP subnets between VLANs
- No duplicate VLAN IDs
- Firewall rules reference valid VLANs only
- Default deny rule (999) is present
- Every inventoried device sits inside its VLAN subnet, outside the DHCP pool, and off the gateway address
- No duplicate IPs or hostnames; static counts match the addressing plan
- PHI-handling devices live only on the Clinical or Medical_IoT VLANs
- Reports high-level statistics

Exits non-zero on any FAIL, so it can gate a CI pipeline.

### 2. Generate Compliance Checklist

```bash
cd scripts
python3 generate-compliance-checklist.py --output ../output/hipaa-checklist.md
```

Produces a Markdown checklist mapping every VLAN and firewall rule to its HIPAA §164.312 safeguard.

### 3. Run Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Skills Demonstrated

| Skill | Evidence |
|-------|----------|
| Network Segmentation / VLAN Design | VLAN plan, trunk configuration, broadcast domain isolation |
| Firewall Rule Engineering | Default-deny, least-privilege, protocol-specific rules for DICOM/HL7 |
| HIPAA Security Rule Fluency | Crosswalk from every safeguard to a technical control |
| Threat Modeling | STRIDE-based analysis with DREAD severity ratings in `docs/threat-model.md` |
| Policy-as-Code | CSV-based network policy validated by Python scripts |
| Healthcare Workflow Context | Realistic DICOM/HL7 port rules, clinical roaming, imaging latency needs |
| Healthcare Workflow Context | Realistic DICOM/HL7 port rules, clinical roaming, imaging latency needs |
| Open-Source Infrastructure | pfSense/OPNsense, FreeRADIUS, UniFi, Graylog (no vendor lock-in) |
| Documentation for Non-Technical Auditors | Clear tables, ASCII diagrams, and "why this matters" rationales |

---

## Honest Scope Notes

- **This is a design, not a deployed production network.** No patient data was ever touched. All device names, IPs, and MAC addresses are synthetic.
- **I have not physically deployed this at a clinic.** I built this as a portfolio piece while working as a Pharmacy Technician and studying for my CSUSB cybersecurity degree. The network architecture is informed by my healthcare workflow experience (understanding PHI handling, clinical urgency, and why a nurse cannot wait 10 minutes for a firewall rule change during code-blue) and by my home lab running OPNsense on a repurposed PC.
- **The Python scripts are functional validators and generators, not hardened CI/CD pipelines.** They check logical consistency of the policy file; they do not audit a live network.
- **Next iteration:** Add Wazuh SIEM configuration, Suricata IDS rules for DICOM anomalies, and a Terraform module for AWS VPC equivalent segmentation (for clinics using cloud EHR backup).

---

## Contact

- **LinkedIn:** (link)  
- **GitHub:** [Phan-Vincent](https://github.com/Phan-Vincent)  

*Built with attention to detail because patient data deserves nothing less.*
