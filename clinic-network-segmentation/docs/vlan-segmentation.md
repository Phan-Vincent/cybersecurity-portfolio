# VLAN Segmentation Plan

## Design Principles

1. **Minimum Necessary** — A device should only reach the networks and ports required for its function.
2. **Default Deny** — All inter-VLAN traffic is blocked unless explicitly permitted by a firewall rule.
3. **IoT Isolation** — Medical IoT devices are data producers, not consumers. They should never initiate connections to clinical workstations.
4. **Management Air-Gap** — Administrative interfaces (firewall, switch, APs) are on a separate VLAN with no routed access from user zones.

---

## VLAN Allocation Table

| VLAN ID | Name | CIDR | Gateway | Usable Hosts | Purpose | DHCP Range |
|---------|------|------|---------|--------------|---------|------------|
| 10 | Management | 10.10.10.0/24 | 10.10.10.1 | 253 | Firewall, switch, AP, SIEM, backup | 10.10.10.100–10.10.10.200 (static reservations only) |
| 20 | Clinical | 10.10.20.0/24 | 10.10.20.1 | 253 | Provider workstations, tablets, EHR server, nurse stations | 10.10.20.11–10.10.20.99 (dynamic); 10.10.20.100–10.10.20.150 (static reservations) |
| 30 | Medical IoT | 10.10.30.0/24 | 10.10.30.1 | 253 | BP cuffs, pulse oximeters, EKG, imaging modalities, IoT gateway | 10.10.30.51–10.10.30.100 (dynamic MAC-based reservations) |
| 40 | Guest / BYOD | 10.10.40.0/24 | 10.10.40.1 | 253 | Patient Wi-Fi, personal phones, staff BYOD | 10.10.40.11–10.10.40.200 (dynamic, 4h lease) |
| 50 | Admin / Billing | 10.10.50.0/24 | 10.10.50.1 | 253 | Billing workstations, office manager, payroll server, insurance clearinghouse | 10.10.50.11–10.10.50.99 (dynamic); 10.10.50.100–10.10.50.150 (static) |

**Total address space:** 10.10.0.0/20 (4094 usable hosts across all VLANs) — leaves room for future expansion (e.g., VLAN 60 for telehealth, VLAN 70 for pharmacy integration).

---

## Device Inventory by VLAN

### VLAN 10 — Management (Static Reservations Only)

| Hostname | IP | Role | MAC (Synthetic) | Notes |
|----------|-----|------|----------------|-------|
| fw-vvw-pfsense | 10.10.10.1 | Firewall/Router/DHCP | a4:bb:cc:00:00:01 | WAN + 5 VLAN interfaces |
| sw-vvw-core | 10.10.10.2 | L2 Managed Switch | a4:bb:cc:00:00:02 | 24-port, 802.1q trunk to firewall |
| ap-vvw-guest | 10.10.10.3 | Guest AP | a4:bb:cc:00:00:03 | SSID: VVFM-Guest (WPA3-Enterprise, VLAN 40) |
| ap-vvw-clinical | 10.10.10.4 | Clinical AP | a4:bb:cc:00:00:04 | SSID: VVFM-Clinical (WPA3-Enterprise, VLAN 20) |
| ap-vvw-iot | 10.10.10.5 | IoT AP | a4:bb:cc:00:00:05 | SSID: VVFM-IoT (WPA3-PSK, VLAN 30, hidden) |
| siem-vvw | 10.10.10.10 | Syslog / SIEM VM | a4:bb:cc:00:00:10 | Graylog / Wazuh; receives all firewall + AP logs |
| backup-vvw | 10.10.10.11 | Backup NAS | a4:bb:cc:00:00:11 | Encrypted at rest; air-gapped snapshot weekly |

### VLAN 20 — Clinical

| Hostname | IP | Role | User / Owner | Notes |
|----------|-----|------|--------------|-------|
| ws-vvw-doc1 | 10.10.20.11 | Provider Workstation | Dr. Sarah Chen | EHR access, domain-joined |
| ws-vvw-doc2 | 10.10.20.12 | Provider Workstation | Dr. Marcus Johnson | EHR access, domain-joined |
| tablet-vvw-doc3 | 10.10.20.13 | Provider Tablet | Dr. Emily Park | Mobile EHR, MDM-enrolled |
| ws-vvw-nurse1 | 10.10.20.21 | Nurse Station PC | RN Lisa Torres | EHR read-only + vitals entry |
| ws-vvw-nurse2 | 10.10.20.22 | Nurse Station PC | RN James Wright | EHR read-only + vitals entry |
| ehr-srv-vvw | 10.10.20.100 | EHR Application Server | IT Admin | Ubuntu LTS, Hardened; SQL backend on same host (no exposed SQL port) |
| print-vvw-clinical | 10.10.20.101 | Clinical Printer | Shared | Locked tray; print-release required |

### VLAN 30 — Medical IoT

| Hostname | IP | Role | Device Type | Notes |
|----------|-----|------|-------------|-------|
| iot-gw-vvw | 10.10.30.1 | IoT Aggregation Gateway | Linux VM | mTLS proxy; normalizes device HL7/FHIR data |
| dev-vvw-bp-01 | 10.10.30.51 | BP Cuff (Exam 1) | Omron Wireless | Sends data to iot-gw-vvw:443 |
| dev-vvw-bp-02 | 10.10.30.52 | BP Cuff (Exam 2) | Omron Wireless | Sends data to iot-gw-vvw:443 |
| dev-vvw-bp-03 | 10.10.30.53 | BP Cuff (Exam 3) | Omron Wireless | Sends data to iot-gw-vvw:443 |
| dev-vvw-ox-01 | 10.10.30.54 | Pulse Oximeter (Exam 1) | Masimo | Sends data to iot-gw-vvw:443 |
| dev-vvw-ox-02 | 10.10.30.55 | Pulse Oximeter (Exam 2) | Masimo | Sends data to iot-gw-vvw:443 |
| dev-vvw-ox-03 | 10.10.30.56 | Pulse Oximeter (Exam 3) | Masimo | Sends data to iot-gw-vvw:443 |
| dev-vvw-ekg-01 | 10.10.30.57 | EKG Monitor | Welch Allyn | Sends to iot-gw-vvw:443; DICOM for imaging |
| dev-vvw-img-01 | 10.10.30.60 | Imaging Modality | GE X-ray | DICOM to iot-gw-vvw:11112; gateway forwards to PACS (future) |

### VLAN 40 — Guest / BYOD

| Hostname | IP | Role | Owner | Notes |
|----------|-----|------|-------|-------|
| dynamic | 10.10.40.11–200 | Patient / Visitor Devices | Unknown | Captive portal; 50 Mbps rate-limit; 4h DHCP lease |

### VLAN 50 — Admin / Billing

| Hostname | IP | Role | User / Owner | Notes |
|----------|-----|------|--------------|-------|
| ws-vvw-bill1 | 10.10.50.11 | Billing Workstation | Brenda, Front Desk | Billing software, insurance portals |
| ws-vvw-office-mgr | 10.10.50.12 | Office Manager PC | Roberta, Office Mgr | Payroll, HR, reporting |
| payroll-srv-vvw | 10.10.50.100 | Payroll Server | IT Admin | ADP / internal payroll app |
| insurance-srv-vvw | 10.10.50.101 | Insurance Clearinghouse | IT Admin | Connects to external clearinghouse APIs |
| print-vvw-admin | 10.10.50.102 | Admin Printer | Shared | General office printing |

---

## Traffic Matrix

| From \ To | Management (10) | Clinical (20) | Medical IoT (30) | Guest (40) | Admin (50) | Internet |
|-----------|-------------------|---------------|------------------|------------|------------|----------|
| **Management (10)** | Local | Deny* | Deny* | Deny* | Deny* | Allow (updates, NTP) |
| **Clinical (20)** | Deny | Local | Allow (to iot-gw:443 only) | Deny | Deny | Allow (filtered) |
| **Medical IoT (30)** | Deny | Deny | Local | Deny | Deny | Allow (NTP, vendor update IPs only) |
| **Guest (40)** | Deny | Deny | Deny | Local | Deny | Allow (HTTP/S only) |
| **Admin (50)** | Deny | Allow (to ehr-srv:443 via jump) | Deny | Deny | Local | Allow (filtered) |

\* Management VLAN has no routed inbound access. Physical switchport or VPN required.

---

## Switch Port Allocation (24-Port Managed Switch)

| Port | VLAN Mode | Allowed VLANs | Connected Device | Notes |
|------|-----------|---------------|------------------|-------|
| 1 | Trunk | 10,20,30,40,50 | fw-vvw-pfsense | Firewall LAN interface |
| 2 | Access | 10 | siem-vvw | Dedicated management |
| 3 | Access | 10 | backup-vvw | Dedicated management |
| 4 | Trunk | 20,50 | ws-vvw-frontdesk | 802.1x dynamic assignment |
| 5 | Access | 20 | ws-vvw-doc1 | Exam 1 |
| 6 | Access | 20 | ws-vvw-doc2 | Exam 2 |
| 7 | Access | 20 | ws-vvw-nurse1 | Nurse station |
| 8 | Access | 20 | ws-vvw-nurse2 | Nurse station |
| 9 | Access | 20 | ehr-srv-vvw | EHR server |
| 10 | Access | 20 | print-vvw-clinical | Clinical printer |
| 11 | Access | 30 | iot-gw-vvw | IoT aggregation gateway |
| 12 | Access | 30 | (spare) | Future IoT |
| 13 | Access | 30 | (spare) | Future IoT |
| 14 | Access | 50 | ws-vvw-bill1 | Billing |
| 15 | Access | 50 | ws-vvw-office-mgr | Office manager |
| 16 | Access | 50 | payroll-srv-vvw | Payroll server |
| 17 | Access | 50 | insurance-srv-vvw | Insurance server |
| 18 | Access | 50 | print-vvw-admin | Admin printer |
| 19 | Access | 40 | ap-vvw-guest | Guest AP (PoE) |
| 20 | Access | 20 | ap-vvw-clinical | Clinical AP (PoE) |
| 21 | Access | 30 | ap-vvw-iot | IoT AP (PoE) |
| 22 | Access | 10 | (spare mgmt) | IT laptop jack |
| 23 | Trunk | 10,20,30,40,50 | (uplink spare) | Future expansion |
| 24 | Trunk | 10,20,30,40,50 | (uplink spare) | Future expansion |

---

## DHCP Configuration Summary

| VLAN | Lease Time | DNS Servers | NTP Server | Options |
|------|-----------|-------------|------------|---------|
| 10 | 8 days | 10.10.10.1 (pfSense resolver) | 10.10.10.1 | Static reservations only |
| 20 | 1 day | 10.10.10.1 | 10.10.10.1 | Domain: vvw.local; WINS disabled |
| 30 | 30 days | 10.10.10.1 | 10.10.10.1 | MAC-based reservations; no dynamic pool |
| 40 | 4 hours | 10.10.10.1 | 10.10.10.1 | Captive portal redirect; rate-limit 50 Mbps |
| 50 | 1 day | 10.10.10.1 | 10.10.10.1 | Domain: vvw.local |

**Note:** DHCP is served by pfSense for all VLANs. DNS resolver is Unbound with DNSSEC validation enabled. DNS rebinding protection is active (prevents private IP responses from public domains).

---

## Wi-Fi Configuration Summary

| SSID | VLAN | Band | Security | Authentication | Hidden | Rate Limit |
|------|------|------|----------|----------------|--------|------------|
| VVFM-Clinical | 20 | 5 GHz only | WPA3-Enterprise | RADIUS (FreeRADIUS on 10.10.10.1) | No | None |
| VVFM-IoT | 30 | 2.4 GHz | WPA3-PSK | Pre-shared key (rotated quarterly) | Yes | 10 Mbps per device |
| VVFM-Guest | 40 | 2.4 + 5 GHz | WPA3-Enterprise / WPA2 fallback | Captive portal + SMS/email verification | No | 50 Mbps aggregate |

**Key Wi-Fi hardening:**
- PMF (Protected Management Frames) required on all SSIDs.
- 802.11w (management frame protection) enabled.
- Rogue AP detection enabled on clinical and IoT SSIDs.
- Minimum RSSI threshold (-75 dBm) to prevent distant associations.
