# Expanded Threat Model: Small Clinic Network

**Methodology:** STRIDE + DREAD  
**Scope:** 3-provider primary care clinic, ~25 staff, 50+ endpoints, single site, no dedicated security staff.  
**Assumption:** Attacker can be external (internet), internal (malicious employee), or adjacent (guest Wi-Fi, compromised vendor laptop).

---

## Threat Inventory

### 1. Spoofing: Rogue Access Point / Evil Twin

- **Description:** Attacker places a cloned "Clinic-Guest" AP in the parking lot. Staff or patients connect; credentials phished.
- **DREAD:** Damage=8, Reproducibility=7, Exploitability=6, Affected Users=7, Discoverability=8 → **Score: 7.2 (HIGH)**
- **Mitigation:** WPA3-Enterprise (cert+AD) on Clinical/Admin. Guest SSID uses captive portal + MAC ACL, but is NOT trusted for anything internal. 802.1X on all wired Clinical ports.

### 2. Tampering: DICOM Man-in-the-Middle

- **Description:** Attacker on the same VLAN (if flat network) modifies imaging metadata or injects fake studies. With segmentation, this requires compromising a Clinical workstation first.
- **DREAD:** Damage=9, Reproducibility=4, Exploitability=5, Affected Users=5, Discoverability=4 → **Score: 5.4 (MEDIUM)**
- **Mitigation:** VLAN 30 (MedDevices) does not share broadcast domain with Clinical. DICOM TLS (Part 15) encrypts C-STORE/C-FIND. Firewall rules only allow DICOM ports (104, 11112) from Clinical → MedDevices.

### 3. Repudiation: "Who Deleted That Record?"

- **Description:** Shared front-desk credentials allow a terminated employee to claim "it wasn't me."
- **DREAD:** Damage=7, Reproducibility=8, Exploitability=7, Affected Users=6, Discoverability=7 → **Score: 7.0 (HIGH)**
- **Mitigation:** Unique AD accounts per user. RADIUS accounting logs on Admin VLAN. Windows Event Forwarder to Graylog. Shared accounts require manager approval + 48-hour expiration.

### 4. Information Disclosure: IoT Cloud Exfiltration

- **Description:** HVAC vendor's cloud dashboard is compromised. Because IoT devices are on a flat network, attacker pivots to EHR.
- **DREAD:** Damage=8, Reproducibility=6, Exploitability=7, Affected Users=8, Discoverability=6 → **Score: 7.0 (HIGH)**
- **Mitigation:** MedIoT VLAN (40) is denied all RFC1918 access. Internet is TLS 443 only. Even if the HVAC cloud is breached, the attacker cannot touch VLAN 20 or 30.

### 5. Denial of Service: Imaging Flood / Broadcast Storm

- **Description:** Ultrasound malfunctions and floods the network with DICOM association requests. On a flat network, EHR workstations freeze.
- **DREAD:** Damage=6, Reproducibility=5, Exploitability=4, Affected Users=8, Discoverability=5 → **Score: 5.6 (MEDIUM)**
- **Mitigation:** VLAN 30 is rate-limited at the switch port (1 Gbps → 100 Mbps for imaging). Broadcast storms are contained to VLAN 30. Clinical VLAN 20 is unaffected.

### 6. Elevation of Privilege: Phish → Domain Admin

- **Description:** Clinician clicks phishing link. Malware beaconing out. If on flat network, laterally moves to Admin DC.
- **DREAD:** Damage=9, Reproducibility=7, Exploitability=5, Affected Users=9, Discoverability=5 → **Score: 7.0 (HIGH)**
- **Mitigation:** Clinical VLAN cannot reach Admin management ports (22, 3389, 445). DC is on VLAN 10 with 802.1X port security. Jump host requires hardware token. GPO blocks USB storage.

---

## Attack Scenarios (Narrative)

### Scenario A: Compromised Guest Laptop

1. Attacker connects to Guest Wi-Fi (VLAN 50).
2. Scans 192.168.x.x ranges.
3. **Result:** Firewall default-deny blocks all RFC1918. Attacker sees nothing.
4. Even with WPA2 crack, Guest AP has client isolation.

### Scenario B: Phished Nurse Station

1. Nurse on VLAN 20 clicks credential-phishing email.
2. Malware drops beacon to C2.
3. **Result:** Clinical VLAN has internet HTTPS only (via proxy). C2 on port 4444 is blocked.
4. If C2 uses 443, TLS inspection proxy (OPNsense with CA cert installed on workstations) can detect SNI mismatch.
5. Lateral movement to MedDevices (VLAN 30) is blocked — no Clinical → MedDevices except DICOM ports.

### Scenario C: Compromised Ultrasound (Supply Chain)

1. Ultrasound vendor's update server is breached. Firmware backdoored.
2. Device on VLAN 30 beacons to attacker CC.
3. **Result:** VLAN 30 has no internet. Beacon fails.
4. Attacker must control a Clinical workstation to reach the device via DICOM ports — and even then, only C-STORE operations, not shell access.

---

## Risk Acceptance

- **Guest Wi-Fi WPA2 (not WPA3):** Accepted because WPA3 client support is not universal on patient devices. Risk mitigated by VLAN isolation + captive portal disclaimer.
- **No NAC (Network Access Control):** Accepted for cost reasons. Replaced by 802.1X on wired Clinical ports and MAC ACLs on IoT. If budget allows, Aruba ClearPass or PacketFence is the next upgrade.
- **No Dedicated IDS/IPS (yet):** Suricata on OPNsense is enabled in alert-only mode initially. Tuning requires 2–4 weeks of baseline learning. Full block mode is a post-deployment milestone.

---

## References

- NIST SP 800-66 Rev. 2: Implementing the HIPAA Security Rule
- DICOM Part 15: Security and System Management
- HL7 FHIR Security (R4)
- CIS Controls v8, IG-1 (small org baseline)
