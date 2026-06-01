# Architecture Document

## Small Clinic Network Segmentation — Full Narrative

### Clinic Profile (Synthetic)

- **Name:** Westside Family Medical Clinic (fictional)
- **Size:** 2 physicians, 1 NP, 3 MAs, 2 front-desk staff, 1 billing, 1 office manager, 1 IT contractor (shared with 2 other clinics)
- **Location:** Suburban medical plaza, 2,800 sq ft
- **EHR:** Cloud-hosted eClinicalWorks instance (web-based)
- **Imaging:** Digital X-ray + DICOM workstation, connected to a local PACS mini-server
- **IoT:** 4 patient monitors, 2 infusion pumps, 1 digital scale, 1 blood-pressure kiosk, 1 WiFi thermostat (HVAC vendor-managed)
- **Network hardware budget:** ~$3,500 (one L3 switch, one firewall appliance, 3 APs, one small server for SIEM/logging)

This is a **realistic small-practice profile** — not a fantasy hospital with $50k of Cisco gear. Every design decision is chosen to be implementable on this budget.

---

## Design Philosophy

### 1. Defense in Depth

No single control is trusted. Segmentation is the *primary* control, but it is backed by:
- **Authentication:** 802.1X on clinical and admin ports
- **Encryption:** TLS 1.3 on all EHR traffic; no plaintext management protocols
- **Monitoring:** Full packet capture + IDS on SPAN ports; Wazuh agents on endpoints
- **Hardening:** Port security, BPDU guard, disabled unused switch ports

### 2. Least Privilege by Default

Every VLAN starts with **zero connectivity** to any other VLAN. Rules are added one by one with explicit justifications. This is the opposite of a "flat network with some restrictions" — it is a **zero-trust network** built on VLAN boundaries.

### 3. HIPAA by Design

The HIPAA Security Rule is not an afterthought. Every VLAN, firewall rule, and logging decision is traced to a §164.312 requirement. The design is built to make a HIPAA risk assessment *easier* — the assessor can read the mapping and verify each control.

---

## Segment-by-Segment Rationale

### VLAN 10 — Admin / IT (10.10.0.0/24)

**Why separate?** IT staff have high privilege. If their segment is compromised, the attacker gets domain admin, firewall credentials, or RDP access to everything. By isolating admin workstations, we limit the blast radius of a phishing attack on the office manager or IT contractor.

**Controls:**
- 802.1X with EAP-TLS (certificate-based) — no shared passwords
- Admin workstations are denied access to VLAN 20 (Clinical) by firewall rule — they cannot "accidentally" see patient records
- Management access to VLAN 100 (Switch/Firewall/AP) is via SSH/HTTPS only, with key-based auth
- Jump host (10.10.0.10) in the DMZ is used for any vendor remote access; sessions are recorded

**Budget fit:** 802.1X can be run with FreeRADIUS on the logging server (VLAN 50). No need for a commercial NAC.

### VLAN 20 — Clinical / PHI (10.20.0.0/24)

**Why separate?** This is the **crown jewel**. The EHR server, clinical workstations, and lab interface all contain PHI. This VLAN must be the most restrictive.

**Controls:**
- No direct internet access. Clinical workstations reach the EHR server (10.20.0.10) and the DMZ web proxy (10.254.0.10) only.
- The DMZ proxy handles e-prescribing (Surescripts), insurance eligibility checks, and EHR cloud sync.
- 802.1X with MAC + user auth — a stolen laptop cannot be plugged into a clinical port and join the VLAN.
- Printer is local to VLAN 20 (no cross-VLAN printing) to prevent print job interception.
- EHR server runs Wazuh agent + file integrity monitoring (FIM). Alert on any unauthorized config change.

**Budget fit:** The EHR server is a repurposed desktop PC with SSD + Linux + Docker (Wazuh + local PACS). The cloud EHR is the SaaS provider's responsibility; we only secure the local access path.

### VLAN 30 — Medical IoT (10.30.0.0/24)

**Why separate?** Medical IoT devices are **unpatchable** and **high-risk**. They run embedded Linux with default credentials, no antivirus, and no EDR agent. They cannot be trusted on the same segment as the EHR server.

**Controls:**
- **No internet access.** IoT devices talk only to the IoT gateway (10.30.0.1), a hardened Debian VM running on the logging server.
- The gateway runs a **protocol whitelist**: only DICOM (port 104, TLS-wrapped), HL7 FHIR (port 443), and MQTT (port 8883, TLS) are forwarded.
- Each device has a **static DHCP reservation** mapped to its MAC address. Unknown MACs are dropped by port security.
- The gateway enforces **rate limiting** — 100 packets/sec per device. DDoS from a compromised IoT device is contained.
- Firmware updates are pushed through the gateway, not directly from the internet. The gateway verifies checksums before flashing.

**Budget fit:** The gateway is a Linux VM or container. No commercial IoT security platform needed.

### VLAN 40 — Guest WiFi (10.40.0.0/24)

**Why separate?** Patients and visitors bring infected devices. A flat network would let a compromised phone scan for SMB shares on the EHR server.

**Controls:**
- **Complete isolation.** Guest clients cannot reach any RFC 1918 address. They get DNS + HTTP/HTTPS only.
- **Client isolation** at the AP level — guests cannot attack each other (ARP spoofing, etc.).
- **Captive portal** with 4-hour session timeout. Credentials are not required; a click-through AUP is logged for liability.
- **Rate limiting:** 10 Mbps down / 5 Mbps up per client. No impact on clinical bandwidth.
- **Separate SSID:** "Westside-Guest" vs "Westside-Clinical" (hidden). The AP does not broadcast the clinical SSID.

**Budget fit:** Standard UniFi or TP-Link Omada APs support all these features.

### VLAN 50 — Security / Logs (10.50.0.0/24)

**Why separate?** The SIEM and NIDS are the **sensors** of the network. If they are on the same VLAN as everything else, an attacker who compromises the EHR server can also disable logging or poison the SIEM.

**Controls:**
- **Ingest-only.** The SIEM receives logs, but it cannot initiate connections to any other VLAN. If an attacker compromises the SIEM, they are stuck.
- **SPAN / Mirror port** on the core switch copies all inter-VLAN traffic to the NIDS sensor (10.50.0.11). The NIDS runs Suricata with the ET Open ruleset.
- **Wazuh server** (10.50.0.10) collects endpoint logs from every VLAN via the Wazuh agent.
- **Syslog collector** (10.50.0.12) ingests firewall deny logs, switch authentication logs, and AP association logs.
- **Backup:** Logs are exported nightly to an encrypted USB drive stored in a safe (offline backup). The SIEM itself has no cloud sync — air-gapped backup.

**Budget fit:** Wazuh + Suricata + syslog-ng are open source. A small form factor PC with 16GB RAM and 2TB SSD handles this easily.

### VLAN 100 — Network Management (10.100.0.0/24)

**Why separate?** Switch, firewall, and AP management interfaces are high-value targets. If they are on VLAN 10 or 20, an attacker who compromises a user workstation gets a direct path to the network fabric.

**Controls:**
- **Out-of-band management.** No user traffic transits this VLAN. It is only for admin-to-device sessions.
- **SSH key auth only.** Password authentication is disabled on the switch and firewall.
- **HTTPS with self-signed cert** (or Let's Encrypt via ACME on the DMZ). No HTTP.
- **Source IP restriction:** Only 10.10.0.0/24 (Admin VLAN) can reach 10.100.0.0/24.
- **BPDU guard** on all access ports — prevents rogue switches from hijacking spanning tree.

**Budget fit:** Management VLAN is a free feature on any managed switch.

### DMZ — 10.254.0.0/24

**Why separate?** The DMZ hosts services that must touch both the internet and internal segments. It is the **controlled bridge**.

**Services:**
- **Web proxy (Squid/HAProxy):** Handles e-prescribing, EHR cloud sync, and software updates. Inspects TLS SNI (not content) to verify destination domains.
- **DNS resolver (Unbound):** Forwards to Quad9 (9.9.9.9) with DNS-over-TLS. Blocks known malware domains.
- **eRx gateway:** Bridges Surescripts API (internet) to EHR server (VLAN 20). Validates TLS certificate pinning.

**Controls:**
- DMZ services can initiate connections to VLAN 20 (Clinical) on specific ports only (443, 104).
- DMZ cannot initiate connections to VLAN 10 (Admin) or VLAN 30 (IoT) at all.
- All DMZ sessions are logged to VLAN 50.

---

## Hardware Bill of Materials (Synthetic Budget)

| Item | Model (Example) | Est. Cost | Role |
|------|-----------------|-----------|------|
| Firewall | Protectli Vault (4-port, Celeron) | $450 | OPNsense / pfSense |
| Core Switch | TP-Link TL-SG3428XMP (L3, 24-port) | $400 | Inter-VLAN routing, ACLs, PoE |
| APs (x3) | UniFi U6 Lite | $300 | Clinical + Guest + Management SSIDs |
| SIEM/NIDS Server | Lenovo ThinkCentre M70q (i5, 16GB, 2TB) | $700 | Wazuh + Suricata + syslog |
| EHR Server | Repurposed desktop (i5, 32GB, SSD) | $0 (existing) | Local PACS + Docker host |
| IoT Gateway | VM on SIEM server | $0 | Hardened Debian |
| Cabling / Patch | Cat 6a, patch panel, rack | $400 | Infrastructure |
| UPS | APC Smart-UPS 750VA | $300 | Power protection for core gear |
| **Total** | | **~$2,550** | |

This is a realistic budget for a small clinic that takes security seriously. The design is vendor-agnostic — substitute Protectli with any x86 box, TP-Link with any L3 switch, UniFi with Omada or Ruckus.

---

## Operational Procedures (Conceptual)

### Onboarding a New Employee
1. HR creates Active Directory account (if using AD) or FreeRADIUS user entry
2. IT provisions laptop with 802.1X certificate (EAP-TLS)
3. Switch port is configured for the correct VLAN based on role (Clinical = VLAN 20, Admin = VLAN 10)
4. Wazuh agent is installed on the laptop
5. Access is reviewed quarterly — if the employee moves from front desk to billing, the RADIUS profile is updated

### Onboarding a New IoT Device
1. Vendor provides MAC address and required ports/protocols
2. IT creates a static DHCP reservation in the IoT VLAN (10.30.0.x)
3. IoT gateway rule is updated to allow the specific protocol (e.g., DICOM TLS)
4. Switch port is configured with port security (1 MAC max, sticky MAC)
5. Device is monitored for 48 hours. If it sends unexpected traffic, the port is shut down

### Incident Response — Ransomware Detection
1. NIDS (Suricata) on VLAN 50 detects SMBv1 traffic or known ransomware C2 beacon
2. Wazuh correlates the alert with endpoint FIM changes (e.g., file extension changes on EHR server)
3. Firewall rule is automatically updated (via API) to **isolate the affected VLAN** (e.g., deny all VLAN 20 outbound)
4. IT investigates on the jump host in VLAN 10 (read-only access to VLAN 20 logs via SIEM)
5. If EHR server is compromised, the offline backup (USB) is used for recovery

---

## Future Enhancements (Roadmap)

These are **not** in scope for this student project, but they show the candidate understands the next level:

1. **Zero Trust Network Access (ZTNA):** Replace VPN for remote access with Cloudflare Tunnel or Tailscale, with device posture checks.
2. **Automated Compliance Scanning:** A weekly Python script that reads the firewall API, compares it to `config/firewall-rules.csv`, and alerts on drift.
3. **Network Digital Twin:** A GNS3 or EVE-NG lab that mirrors this design, used for incident-response drills and firewall rule testing.
4. **IoT Firmware SBOM:** A Python script that parses device firmware images and checks CVEs against the NVD API.
5. **Terraform for OPNsense:** Infrastructure-as-code for the firewall configuration, stored in Git with CI/CD validation.
