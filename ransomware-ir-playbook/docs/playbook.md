# Ransomware Incident Response Playbook
## For Small Healthcare Pharmacies & Clinics
### Based on NIST SP 800-61 Rev. 2

**Author:** Vincent Phan | CPhT — CVS Pharmacy Technician\
**Target Audience:** Small-to-midsize outpatient pharmacies, compounding labs, clinic dispensaries  
**Version:** 1.0  
**Classification:** Internal Use / Portfolio Project — All patient data is synthetic

---

## Document Control

| Field | Value |
|-------|-------|
| Effective Date | 2026-06-01 |
| Review Cycle | Annually, or after any incident, major system change, or regulatory update |
| Owner | Pharmacy Manager / Privacy Officer (designated) |
| Distribution | IT admin workstation (encrypted), pharmacy manager office (locked cabinet), cloud backup (encrypted, MFA) |

---

## 1. Preparation

### 1.1 Objectives
- Establish an incident response capability before an event occurs.
- Define roles, contact trees, and communication channels.
- Ensure technical readiness: backups, logging, network segmentation, inventory.
- Satisfy HIPAA Security Rule (§164.308(a)(1)) — administrative safeguards for security management process.

### 1.2 Key Actions

#### 1.2.1 Roles & Responsibilities (Small-Team Model)

A typical small pharmacy may have only 4–8 total staff. Roles below can overlap, but accountability must be clear.

| Role | Typical Assignee | Responsibilities During an IR Event |
|------|-----------------|--------------------------------------|
| **Incident Commander (IC)** | Pharmacy Manager or Senior Pharmacist on duty | Declares incident severity, approves containment actions, coordinates with external parties (BAs, law enforcement, HHS) |
| **IT / Systems Lead** | Contracted IT admin or tech-savvy staff member | Executes technical containment, preserves forensic evidence, manages backup restoration |
| **Privacy Officer** | Pharmacist-In-Charge (PIC) or designated HIPAA officer | Assesses PHI scope, drives breach notification analysis, coordinates with state board |
| **Patient Safety Lead** | Pharmacist on duty (rotating) | Ensures dispensing continuity, manages emergency paper workflows, monitors cold-chain integrity |
| **Business Associate Liaison** | Pharmacy Manager or PIC | Contacts EHR/PM vendor, claims processor, wholesale supplier IT contacts |
| **Communications Lead** | Pharmacy Manager or front-of-house lead | Manages staff messaging, patient call scripts, social media silence protocol |

#### 1.2.2 Communication Plan

Maintain a printed, laminated contact tree in the pharmacy manager’s office and at the IT admin’s workstation. Include:

- **Internal:** Cell numbers for all staff, including after-hours. Rotating on-call pharmacist schedule.
- **Business Associates:**
  - Primary/secondary EHR vendor support (24/7 number, account ID)
  - Claims processor (Surescripts, RelayHealth, or clearinghouse)
  - Wholesale supplier IT desk (for order portal outages)
  - Cold-chain IoT sensor vendor support line
- **External Authorities:**
  - FBI IC3 (ic3.gov) — for criminal reporting
  - HHS Office for Civil Rights (OCR) Breach Portal
  - State Board of Pharmacy (California: [916-574-7900](https://cdph.ca.gov))
  - Cyber insurance carrier hotline (policy number in sealed envelope)
  - External IR retainer firm (if contracted)

#### 1.2.3 Technical Readiness Checklist

| Control | Implementation Standard | Verification Method |
|---------|------------------------|--------------------|
| Offline backups | 3-2-1 rule: 3 copies, 2 media types, 1 offsite/air-gapped | Monthly restore drill (synthetic data environment) |
| Network segmentation | Pharmacy LAN isolated from guest WiFi; IoT sensors on separate VLAN | Quarterly firewall rule review |
| Endpoint detection | EDR on all workstations; RDP logging enabled | Weekly EDR health dashboard check |
| MFA | Required for all remote access, cloud EHR, billing portals | Monthly MFA enrollment audit |
| Inventory | Asset list maintained: hostname, OS version, function, owner | Quarterly update; after any hardware swap |
| Logging | Centralized logs (SIEM or syslog server); retained ≥ 6 months | Monthly log integrity spot-check |
| Encryption | Full-disk encryption (BitLocker/FileVault) on all workstations; encrypted backup drives | Boot-time verification on patch cycle |

#### 1.2.4 Legal & Regulatory Pre-Positioning

- **Cyber insurance policy** reviewed annually. Confirm ransomware coverage is not excluded. Know deductible and incident-response-fund limits.
- **Business Associate Agreements (BAAs)** on file for all vendors with system access. Verify each BAA contains breach-notification timing (ideally ≤ 24 hours per OCR guidance).
- **State breach law matrix:** Some states (e.g., California via Cal. Civ. Code § 1798.82) require notification to the Attorney General if >500 residents affected, regardless of the HHS 500-person threshold.
- **HIPAA breach assessment template** pre-drafted (see Appendix A) so the Privacy Officer can begin documenting immediately upon discovery.

#### 1.2.5 Patient Safety Continuity Planning

Small pharmacies do not have the redundancy of hospital pharmacies. A ransomware event that locks the dispensary workstation can halt all prescription fulfillment. Preparations:

1. **Paper backup workflow:**
   - Maintain a locked, fire-resistant cabinet with:
     - Blank paper prescription logs (state-compliant format)
     - Hard-copy insurance formulary reference (quarterly update)
     - Current drug-interaction reference (monthly print from Lexicomp or equivalent)
     - State-required auxiliary labels (tamper-evident, child-resistant)
   - Train all pharmacists annually on manual DUR (Drug Utilization Review) procedures.

2. **Critical medication list:**
   - Identify medications that cannot be delayed >24 hours for regular patients (e.g., antiretrovirals, anticoagulants, insulin, transplant immunosuppressants).
   - Pre-negotiate emergency transfer agreements with 2–3 nearby pharmacies.
   - Print a quarterly list of patients on these medications (first name + last initial only; no full identifiers on the paper backup). Store in locked cabinet.

3. **Cold-chain continuity:**
   - IoT temperature sensors must have **local audible alarms** independent of network/cloud dashboards.
   - Maintain calibrated standalone digital min/max thermometers in every refrigerator/freezer storing vaccines or biologics.
   - Document CDC Vaccine Storage & Handling Toolkit requirements (temperature logs every 30 minutes during an outage).
   - Pre-identify alternate cold storage within 30-minute drive (hospital outpatient pharmacy, public health clinic).

4. **Insurance billing continuity:**
   - If the claims processor is down, pharmacies can dispense and bill retroactively ("prospective-to-retrospective" conversion) within payer windows (typically 7–14 days).
   - Maintain a written SOP for collecting insurance card images via phone camera (stored encrypted, deleted after claims resolution) to enable retrospective billing.

---

## 2. Detection & Analysis

### 2.1 Objectives
- Identify the incident rapidly and classify its severity.
- Preserve volatile evidence before it is lost.
- Determine scope: which systems, what data classes, and how many patients are affected.
- Begin the HIPAA breach risk assessment (164.404) within the first hour.

### 2.2 Key Actions

#### 2.2.1 Initial Detection Vectors

| Indicator | Likely Source | Priority |
|-----------|--------------|----------|
| Ransom note on screen (`.txt`, `.html`, wallpaper change) | End-user or EDR alert | **Critical** |
| Mass file encryption (.encrypted, .locked, random extensions) | File server monitoring | **Critical** |
| Abnormal RDP session, VPN logins from unusual geolocations | Firewall / VPN logs | **Critical** |
| EDR alerts: credential dumping, LSASS access, shadow copy deletion | EDR console | **High** |
| IoT sensor dashboard offline + local alarm triggered | Sensor vendor app / audible alarm | **High** (patient safety) |
| Unusual outbound SMB or RDP traffic | Firewall / IDS | **High** |
| Slow system performance, failed backups, antivirus disabled | Staff report / monitoring | **Medium** |

#### 2.2.2 Triage & Severity Classification (First 15 Minutes)

The Incident Commander (or first responder if IC unreachable) classifies using this matrix:

| Severity | Criteria | Examples | Response Tier |
|----------|----------|----------|---------------|
| **SEV-1 (Critical)** | PHI encrypted or exfiltrated; all systems offline; patient safety impact; >500 individuals likely affected | Ransomware across dispensary workstation, EHR, billing server, backup repository corrupted | Full IR activation; FBI IC3; HHS OCR; state board; cyber insurance; external IR firm |
| **SEV-2 (High)** | Partial system encryption; no confirmed exfiltration; <500 individuals; backup intact; no immediate patient safety risk | Single workstation encrypted; network share partially affected; backups confirmed clean | Internal IR team; notify BAs; begin containment |
| **SEV-3 (Medium)** | Suspicious activity detected; no confirmed encryption; isolated endpoint | Phishing email clicked; EDR blocked payload execution | Isolate endpoint; forensics triage; monitor 48h |
| **SEV-4 (Low)** | Attempted intrusion blocked by controls; no system impact | Firewall blocked brute-force RDP attempt from foreign IP | Log, review rules, no further action required |

**Decision Rule:** When in doubt, classify one tier higher. Ransomware can escalate in minutes.

#### 2.2.3 Evidence Preservation

The IT lead must act immediately to preserve forensic integrity, even as containment begins.

1. **Volatile evidence (do first):**
   - Do not power off infected systems if possible. Hibernation or network-disconnect preserves memory.
   - Capture RAM dump if EDR or IR toolkit supports it (e.g., Magnet RAM Capture, KAPE).
   - Photograph the ransom note on-screen (camera, not screenshot tool, to avoid overwriting disk artifacts).
   - Record exact time of discovery, user logged in, and any visible filenames/extensions.

2. **Non-volatile evidence:**
   - Snapshot or image affected virtual machines before any remediation.
   - Collect firewall, VPN, EDR, and DNS logs for the 72 hours prior to detection.
   - Export centralized SIEM logs (time-synchronized, UTC).
   - Chain of custody: label external drives with case ID, date/time, collector name, system origin.

3. **What NOT to do:**
   - Do not delete the ransom note.
   - Do not pay the ransom without Incident Commander approval, legal counsel, and cyber insurance input.
   - Do not run "cleanup" tools (antivirus scans, disk cleanup) on affected systems before forensic imaging.

#### 2.2.4 Scope Analysis (Minutes 15–120)

The Privacy Officer and IT Lead jointly determine:

- **Systems list:** Which hostnames/VMs are encrypted or compromised? Cross-reference with asset inventory.
- **Data classes:** PHI (ePrescriptions, patient profiles, insurance info), PII (staff data), financial data (billing, banking), proprietary (formulary pricing, supplier contracts).
- **Patient count estimate:** Use SQL query against the most recent clean backup (read-only restore to isolated environment) to count unique patient records in affected databases. If the entire EHR is encrypted and no backup is available, assume the full active patient census.
- **Business Associate impact:** Did the attack traverse BA VPN tunnels? Contact each BA to confirm their system status.

#### 2.2.5 Initial HIPAA Breach Risk Assessment

Per 45 CFR § 164.404, a breach is presumed unless the covered entity demonstrates low probability that PHI was compromised. The Privacy Officer begins documenting:

| Assessment Factor | Questions to Answer | Evidence Source |
|-------------------|---------------------|-----------------|
| Nature of PHI | What data elements? (Names, SSNs, DOBs, diagnoses, medications, insurance IDs) | Database schema + backup restore |
| Unauthorized person | Who accessed it? Internal account? External attacker? | EDR + authentication logs |
| Data acquired/viewed | Was PHI merely encrypted, or also exfiltrated? | Firewall egress logs, dark-web monitoring (if available), attacker communication |
| Risk mitigation | Can the data be rendered unusable? (e.g., encryption at rest may satisfy "unusable" if keys not compromised) | IT assessment of key escrow / key compromise |

**If >500 individuals affected** (or the count is uncertain and likely >500), HHS Secretary notification is required **without unreasonable delay** and **no later than 60 days** from discovery (§ 164.408). State board notification timing varies; California requires notification to the Board "without unreasonable delay" (BPC § 4110 et seq. interpreted via state breach law alignment).

---

## 3. Containment, Eradication & Recovery

### 3.1 Objectives
- Stop the spread of the attack.
- Eliminate attacker persistence mechanisms.
- Restore systems to known-good state.
- Resume patient care operations safely.
- Maintain regulatory compliance throughout.

### 3.2 Key Actions

#### 3.2.1 Containment Decision Tree

```
Ransomware Detected
│
├─ Can the affected system be disconnected from the network
│   without impacting life-safety or critical dispensing?
│   ├─ YES → Physically disconnect (pull cable / disable WiFi)
│   │         and leave powered on for forensic memory capture.
│   └─ NO  → Is it a critical workstation (e.g., main dispensary
│             terminal, and no backup terminal available)?
│             ├─ YES → Network-isolate at switch/firewall level
│             │         (preserve power, block all traffic except
│             │          logging to SIEM if safe). Activate paper
│             │          workflow immediately.
│             └─ NO  → Halt and escalate. Do not shut down if
│                       forensic capture is pending.
│
├─ Is lateral movement suspected (other systems showing
│   indicators, shared drives encrypting, domain controller
│   compromise)?
│   ├─ YES → Activate "network segmentation emergency":
│   │         - Disable inter-VLAN routing at firewall
│   │         - Block all outbound traffic except to known-good
│   │           SIEM/log collector
│   │         - Disable VPN tunnels (may cut off BA connectivity,
│   │           but stops attacker exfiltration)
│   └─ NO  → Monitor closely; continue scoped containment
│
├─ Are backups accessible and confirmed clean (last test restore
│   within 30 days, backup repository air-gapped or immutable)?
│   ├─ YES → Note restoration priority; begin staging recovery.
│   └─ NO  → Escalate to cyber insurance and external IR.
│             Consider forensic recovery of encrypted data
│             (rarely successful; plan for business continuity).
```

#### 3.2.2 Short-Term Containment (First 2 Hours)

| Action | Owner | Healthcare-Specific Consideration |
|--------|-------|-----------------------------------|
| Isolate affected endpoints | IT Lead | Ensure insulin/vaccine fridge monitoring is not disrupted by isolation (local alarm must still function) |
| Disable compromised accounts & force password reset on all accounts | IT Lead | Pharmacy staff may share workstation logins — this is a pre-existing violation; force individual accounts now |
| Block malicious IPs/domains at firewall / DNS sinkhole | IT Lead | Document block list for forensic report |
| Preserve logs & RAM | IT Lead | Prioritize EHR server and domain controller if present |
| Activate paper workflow | Patient Safety Lead | Dispense only urgent/critical medications; defer non-urgent refills if safe |
| Notify on-call pharmacist & physician network | Communications Lead | Ensure patients with anticoagulant, transplant, or HIV regimens know where to obtain emergency supplies |
| Verify cold-chain temps every 30 min | Patient Safety Lead | Log manually; if out of range, initiate vaccine waste documentation per CDC guidelines |
| Contact cyber insurance & external IR retainer | Incident Commander | Confirm coverage for forensic recovery, business interruption, and credit monitoring |
| Notify BAs (EHR, clearinghouse, wholesaler) | BA Liaison | Request their incident status; confirm they have not been compromised via shared tunnel |

#### 3.2.3 Long-Term Containment (Hours 2–24)

- **Forensic imaging continues:** Complete disk images of all affected systems before any remediation.
- **Persistence hunt:** Use EDR or IR tools to search for:
  - Scheduled tasks / cron jobs launching suspicious binaries
  - New local admin accounts or group policy changes
  - WMI event subscriptions, registry run keys, or startup folder additions
  - Shadow copy deletion events (`vssadmin delete shadows`)
  - Backdoors in remote-access tools (TeamViewer, AnyDesk, ScreenConnect)
- **Credential rotation:** Assume all credentials are compromised. Reset:
  - Domain admin / local admin passwords
  - EHR admin passwords
  - VPN credentials
  - Cloud service passwords (MFA must already be enabled; if not, enable during reset)
  - IoT sensor default passwords (if accessible)
- **Patch & harden:** Before reconnecting any system to the production network:
  - Apply all pending OS and application patches
  - Disable unused RDP; require MFA + VPN for remote access
  - Update EDR signatures
  - Verify backup immutability settings

#### 3.2.4 Eradication

Eradication means removing all attacker artifacts and closing the infection vector.

| Method | When to Use | Caution |
|--------|-------------|---------|
| **Rebuild from known-good image** | Workstations with clean gold images; EHR terminal servers with documented baselines | Ensure image is newer than earliest suspected compromise time |
| **Restore from clean backup** | File servers, databases, virtual machines with verified clean backup chain | Test restore integrity before production reconnection |
| **Full wipe & OS reinstall** | Systems with no clean image or backup; high-confidence persistence | Reinstall all applications from vendor media; do not restore application files from potentially compromised backups without scanning |
| **Replace hardware (extreme)** | Firmware-level compromise suspected (rare for commodity ransomware) | Costly; reserve for nation-state or advanced persistent threat scenarios |

**Pharmacy-specific:** The pill-counting workstation with the outdated Windows 7 interface may not have a supported modern OS available from the vendor. In this case:
- Isolate it permanently on a dedicated VLAN with no internet access.
- Use a secure data diode or manual USB workflow (scanned for malware before insertion) to transfer counting data to the modern dispensary system.
- Document this as a compensating control for HIPAA risk analysis (§ 164.308(a)(1)(ii)(A)).

#### 3.2.5 Recovery

Recovery prioritization for a pharmacy:

| Priority | System | Rationale | Recovery Method |
|----------|--------|-----------|-----------------|
| P0 | Cold-chain local alarms + manual thermometers | Patient safety; vaccine integrity | Already operational (battery/local) |
| P1 | EHR / PM system | PHI access; prescribing; state-required records | Restore from clean backup or rebuild from gold image |
| P2 | Dispensary workstation + label printers | Prescription fulfillment; revenue | Rebuild + restore local config from documented baseline |
| P3 | Claims processing / billing | Revenue cycle; insurance adjudication | Reconnect to clearinghouse once EHR is confirmed clean |
| P4 | Inventory / ordering system | Wholesale ordering; formulary management | Rebuild; sync with wholesaler after full network clearance |
| P5 | IoT sensor dashboards | Compliance documentation; convenience | Reconnect after firmware update + credential rotation |
| P6 | Non-critical workstations (office, break room) | General productivity | Standard rebuild |

**Recovery validation gates:**
1. Forensic team (internal or external) signs off: no persistent threats detected.
2. Vulnerability scan (authenticated) of rebuilt systems: critical/high vulnerabilities remediated.
3. EDR active and reporting healthy on all reconnected endpoints.
4. Backup integrity verified: spot-check restored patient records for completeness.
5. State Board of Pharmacy and BAs notified of recovery status if required by state law or BAA.

**Post-recovery patient safety actions:**
- Reconcile all paper-dispensed prescriptions against the restored EHR within 24 hours of go-live.
- Contact patients who received emergency supplies to schedule follow-up and insurance re-billing.
- Review temperature logs for any excursion events during the outage; report to state immunization program and vaccine manufacturers per VFC (Vaccines for Children) program requirements if applicable.

---

## 4. Post-Incident Activity

### 4.1 Objectives
- Document lessons learned and update the playbook.
- Fulfill all breach notification obligations.
- Quantify impact for insurance, regulatory, and internal improvement purposes.
- Strengthen defenses to reduce recurrence probability.

### 4.2 Key Actions

#### 4.2.1 Breach Notification Timeline

| Trigger | Action | Deadline | Responsible |
|---------|--------|----------|-------------|
| Discovery of ransomware affecting PHI | Begin breach risk assessment (164.404) | Immediate | Privacy Officer |
| Assessment confirms breach (unauthorized acquisition/access of unsecured PHI) | Notify affected individuals by first-class mail (or email if consented) | **≤ 60 days** from discovery | Privacy Officer / Communications Lead |
| Breach affects >500 individuals in a single state or jurisdiction | Notify prominent media outlets in that area | ≤ 60 days from discovery | Communications Lead |
| Breach affects >500 individuals (anywhere) | Notify **HHS Secretary** via OCR Breach Portal | ≤ 60 days from discovery | Privacy Officer |
| Breach affects <500 individuals | Notify HHS Secretary annually (by March 1 following the year of breach) | Annual aggregation | Privacy Officer |
| State-specific | Notify CA Attorney General if >500 CA residents; notify State Board of Pharmacy per state law | Varies; typically "without unreasonable delay" | Privacy Officer |
| Business Associates | If BA caused breach, BA notifies CE within 60 days of discovery | Per BAA; target ≤ 24 hours | BA Liaison |

**Note:** "Discovery" is the first day the organization knew or, by exercising reasonable diligence, would have known of the breach (§ 164.404). For a Saturday-evening incident at a closed pharmacy, discovery is Monday morning opening unless overnight monitoring (SOC, EDR, IoT alerts) notifies staff earlier.

#### 4.2.2 Law Enforcement & Regulatory Reporting

| Agency | Report Type | Method | When |
|--------|-------------|--------|------|
| FBI IC3 | Criminal complaint / incident report | [ic3.gov](https://ic3.gov) | Within 24–72 hours of confirmed ransomware |
| HHS OCR | Breach notification (if >500) or annual | [OCR Breach Portal](https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf) | Per timeline above |
| State Board of Pharmacy | Security incident / breach (varies by state) | Mail or online portal per state requirement | Per state law; many require "without unreasonable delay" |
| State Attorney General | Consumer protection breach notification | Per state law (e.g., CA AG online form) | Per state-specific timeline |
| Local police | Theft / property crime (if physical intrusion suspected) | Non-emergency line | If applicable |
| Cyber insurance carrier | Claim notification | Hotline / online portal | Within policy-specified window (often 24–48h) |

#### 4.2.3 After-Action Review (AAR)

Conduct within 14 business days of recovery. Attendees: Incident Commander, IT Lead, Privacy Officer, Patient Safety Lead, BA Liaison, and any external IR firm.

**AAR Agenda:**
1. Timeline reconstruction (exact sequence of detection, containment, recovery)
2. What went well?
3. What did not go well?
4. Detection gaps: Did we find out from EDR, staff report, or customer complaint? How can we improve?
5. Containment gaps: Did the attack spread further than expected? Why?
6. Recovery gaps: Were backups adequate? Was the paper workflow effective?
7. Patient impact: Any delayed medications? Any cold-chain excursions? Any complaints?
8. Regulatory gaps: Were notifications timely? Was documentation complete?
9. Financial impact: Downtime hours, revenue loss, recovery costs, insurance deductible.
10. Action items: Specific, assigned, with deadlines.

#### 4.2.4 Playbook & Control Updates

Update the following based on AAR findings:
- This playbook (roles, contact tree, decision trees, workflow details)
- Asset inventory (any new systems added during recovery)
- Backup schedule / test restore frequency
- Network segmentation diagram
- BAA breach-notification clauses (if any BA was slow to report)
- Staff training curriculum (phishing simulation frequency, paper workflow drill schedule)
- Cyber insurance coverage limits (if costs exceeded policy)

---

## Appendices

### Appendix A: HIPAA Breach Assessment Template (Synthetic Example)

**Case ID:** PHARM-IR-2026-001 (example)  
**Date of Discovery:** 2026-06-01  
**Privacy Officer:** [Name]  
**Affected System(s):** Dispensary Workstation PH-DISP-01, EHR Server PH-EHR-01  

| Factor | Assessment |
|--------|------------|
| Nature of data | Patient names, dates of birth, prescription histories, insurance member IDs. No SSNs or payment card data stored locally. |
| Unauthorized access | Unknown external actor via compromised RDP credentials. MFA not enabled on VPN at time of incident (now remediated). |
| Data acquired? | No evidence of exfiltration found in 72-hour firewall egress analysis. Files encrypted but not observed leaving network. Low probability of compromise per § 164.402(1) — but presumption applies; organization must demonstrate low probability. |
| Mitigation | All affected patients offered 12 months credit monitoring as goodwill measure (not required by HIPAA but reduces reputational risk). EHR encrypted at rest with AES-256; encryption keys stored in HSM not accessed by attacker. |
| Risk conclusion | **Breach confirmed.** PHI was accessed by unauthorized individual (attacker had domain-level access, thus had ability to view decrypted PHI in memory/on disk). >500 individuals affected. |
| Notification timeline | Individual letters mailed 2026-07-15 (Day 44). HHS Secretary notification submitted 2026-07-15. CA AG notified 2026-07-15. Local media (Riverside Press-Enterprise) notified 2026-07-15. |

### Appendix B: Patient Paper-Dispensing Log (Template)

**Emergency Dispensing Log — Ransomware Event**

| Date/Time | Patient (Last, First) | DOB | Medication | Qty | Sig | Prescriber | Verification (Pharmacist initials) | Insurance card image captured? | EHR reconciliation date |
|-----------|----------------------|-----|------------|-----|-----|------------|------------------------------------|-------------------------------|------------------------|
| Example: 2026-06-01 09:15 | Doe, J. | 01/15/1985 | Metformin 500mg | 30 | 1 tab BID | Dr. Smith | VP | Y | 2026-06-03 |

*Store this log in locked cabinet. Reconcile to EHR within 24 hours of system restoration. Shred after 6 years per state retention requirements (or scan to EHR if policy permits).*

### Appendix C: Cold-Chain Temperature Log (Manual)

| Time | Fridge A (Vaccines) | Fridge B (Biologics) | Freezer C (Varicella) | Ambient Temp | Recorder Initials | Notes |
|------|---------------------|----------------------|----------------------|-------------|-------------------|-------|
| Example: 06:01 | 38.1°F | 37.8°F | -4.2°F | 72°F | VP | IoT offline; manual mode |

*CDC acceptable ranges: Refrigerator 2–8°C (36–46°F). Freezer -50°C to -15°C (-58°F to 5°F) for varicella; -25°C to -15°C (-13°F to 5°F) for MMRV. Document any excursion immediately.*

---

## References

- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide*
- 45 CFR § 164.308, 164.404–164.408 (HIPAA Security Rule & Breach Notification Rule)
- HHS OCR, *Breach Notification Rule Guidance*
- FBI IC3, *Internet Crime Complaint Center* ([ic3.gov](https://ic3.gov))
- CDC, *Vaccine Storage and Handling Toolkit* ([cdc.gov/vaccines](https://cdc.gov/vaccines))
- California Civil Code § 1798.82 (California breach notification)
- California Business & Professions Code § 4110 (Board of Pharmacy)
- CISA, *Stop Ransomware* ([cisa.gov/stopransomware](https://cisa.gov/stopransomware))
