# Threat Model: Small-Pharmacy Ransomware Attack Surface
## Security Rationale for the IR Playbook

**Author:** Vincent Phan | CPhT — CVS Pharmacy Technician\
**Target:** Independent / small-chain outpatient pharmacies, compounding labs, clinic dispensaries  
**Version:** 1.0  
**Classification:** Internal Use / Portfolio Project

---

## 1. Scope & Assumptions

### 1.1 Organization Profile

| Attribute | Assumption |
|-----------|------------|
| Staff | 4–8 total; 1–2 pharmacists, 1–2 technicians, 1 front-of-house, 1 contracted IT admin |
| IT maturity | Low-to-medium; no dedicated security team; EHR and billing are critical |
| Budget constraints | Common; compensating controls preferred over expensive enterprise tools |
| Compliance drivers | HIPAA Security Rule, HIPAA Breach Notification Rule, state pharmacy board regulations, state breach notification laws, DEA 21 CFR 1301 for controlled substances |
| Threat actor motivation | Financial (ransomware / double-extortion); opportunistic, not targeted, but healthcare pays |

### 1.2 Attack Surface Inventory

| Asset | Function | Exposure | Known Weakness |
|-------|----------|----------|----------------|
| Dispensary workstation | Prescription fulfillment, EHR access, DUR, insurance adjudication | Internal LAN + VPN remote access | Standard Windows 10; staff may share logins |
| Back-office billing server | Claims processing, payment reconciliation, backup storage | Internal LAN + VPN + MPLS to clearinghouse | Windows Server 2019; USB backup drive permanently attached |
| Shared office laptop | Admin, HR, email, general web browsing | Internal LAN + WiFi | Used by multiple staff; lowest security hygiene |
| EHR (cloud-hosted) | Patient records, ePrescribing, refill management | Internet + site-to-site VPN tunnel | BAA-dependent; tunnel is a lateral-movement bridge |
| Pill-counting interface VM | Inventory counting, stock management | **Air-gapped** (no NIC) | Windows 7 (EOL); only "secure" because it is isolated |
| Networked label printers | Prescription label printing, auxiliary labels | Internal LAN (wireless or wired) | No authentication; accept any print job from LAN |
| IoT temp sensors | Vaccine/biologics temperature monitoring, alerts | Internal LAN + cloud dashboard | Default credentials; firmware rarely updated |
| Firewall / VPN concentrator | Remote access (IT admin), site-to-site tunnel (EHR vendor), general internet | Internet-facing VPN endpoints | OpenVPN; MFA not yet deployed |
| Backup repository | Nightly backups to USB + monthly encrypted cloud | USB: physically attached to billing server; Cloud: Backblaze B2 with encryption | USB drive is online and writable; no air-gap |
| Staff endpoints | Personal phones, tablets used for EHR portal check | BYOD; no MDM | Personal devices may sync photos containing PHI |
| Business associate tunnels | EHR vendor site-to-site VPN, clearinghouse MPLS | Always-on | If BA is compromised, tunnel becomes attacker highway |

---

## 2. Threat Scenarios Mapped to MITRE ATT&CK

### 2.1 Technique-by-Technique Mapping

| # | Threat Scenario | MITRE ATT&CK Technique(s) | Playbook Phase Addressing It | Control / Countermeasure |
|---|-----------------|--------------------------|------------------------------|-------------------------|
| 1 | **Phishing email to staff** containing malicious link or credential-harvesting form | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) — Phishing: Spearphishing Attachment; [T1566.002](https://attack.mitre.org/techniques/T1566/002/) — Phishing: Spearphishing Link | **Preparation** | Quarterly phishing simulation + immediate-reporting reward program; email filtering (SPF/DKIM/DMARC); web proxy blocking uncategorized domains |
| 2 | **IT admin VPN credentials phished**, attacker gains remote access | [T1078](https://attack.mitre.org/techniques/T1078/) — Valid Accounts; [T1133](https://attack.mitre.org/techniques/T1133/) — External Remote Services | **Preparation; Detection & Analysis** | MFA on all VPN accounts (prevention); VPN login anomaly alerts (detection); disable compromised account + rotate all creds (containment) |
| 3 | **RDP exposed via VPN** (IT admin remote maintenance); brute-force or credential reuse | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) — Remote Services: Remote Desktop Protocol; [T1110](https://attack.mitre.org/techniques/T1110/) — Brute Force | **Preparation; Detection & Analysis** | Disable RDP or require MFA + VPN; log all RDP sessions; EDR detects LSASS access / credential dumping; network segmentation limits lateral movement |
| 4 | **Lateral movement** from compromised workstation to billing server via SMB/RDP | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) — SMB/Windows Admin Shares; [T1570](https://attack.mitre.org/techniques/T1570/) — Lateral Tool Transfer | **Containment** | Firewall rules blocking inter-subnet SMB except from known admin jump hosts; VLAN segmentation; disable local admin password reuse; EDR behavioral detection |
| 5 | **Credential dumping** (Mimikatz, LSASS access) to escalate from local admin to domain-level access | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) — LSASS Memory; [T1003.004](https://attack.mitre.org/techniques/T1003/004/) — LSA Secrets | **Detection & Analysis; Containment** | EDR prevents LSASS access by unauthorized processes; LAPS (Local Administrator Password Solution) or unique local admin passwords per machine; credential rotation during containment |
| 6 | **Shadow copy deletion** (`vssadmin delete shadows /all /quiet`) to prevent local recovery | [T1490](https://attack.mitre.org/techniques/T1490/) — Inhibit System Recovery | **Preparation; Detection & Analysis** | Immutable backups (write-once, air-gapped, or cloud with object-lock); EDR detects vssadmin abuse; logging alerts on volume shadow copy service events |
| 7 | **Backup drive encryption/destruction** — attacker targets permanently attached USB drive | [T1490](https://attack.mitre.org/techniques/T1490/) — Inhibit System Recovery (variant); [T1485](https://attack.mitre.org/techniques/T1485/) — Data Destruction | **Preparation; Containment** | Air-gapped backups (disconnect after backup, reconnect only for restore); immutable cloud backup with versioning; backup integrity monitoring (hash verification) |
| 8 | **Mass file encryption** across dispensary workstation, billing server, shared drives | [T1486](https://attack.mitre.org/techniques/T1486/) — Data Encrypted for Impact | **Containment; Recovery** | Network segmentation to limit blast radius; offline gold images for rapid rebuild; clean backup restoration; paper workflow for patient safety continuity |
| 9 | **Data exfiltration** (double-extortion) — SMB copy of backup images and EHR sync cache to external staging server | [T1041](https://attack.mitre.org/techniques/T1041/) — Exfiltration Over C2 Channel; [T1567](https://attack.mitre.org/techniques/T1567/) — Exfiltration Over Web Service | **Detection & Analysis; Post-Incident** | Firewall egress monitoring (unusual outbound SMB, large file transfers); DLP (Data Loss Prevention) if budget permits; dark-web monitoring for leaked data; breach notification obligations triggered |
| 10 | **IoT sensor compromise** — default credentials used to access temp sensor dashboard, disable alerts, or pivot | [T1190](https://attack.mitre.org/techniques/T1190/) — Exploit Public-Facing Application; [T1071](https://attack.mitre.org/techniques/T1071/) — Application Layer Protocol | **Preparation; Containment** | Change default credentials on all IoT devices; place IoT on isolated VLAN with no access to pharmacy LAN or internet except to cloud dashboard IP; local audible alarms independent of network |
| 11 | **Label printer manipulation** — attacker sends fake prescription labels or disrupts printing | [T1491.001](https://attack.mitre.org/techniques/T1491/001/) — Defacement: Internal Defacement (functional disruption variant) | **Preparation; Detection** | Printer access control (MAC filtering or 802.1X if supported); print job logging; physical inspection of unusual labels; redundant printer capacity |
| 12 | **Business associate VPN tunnel compromise** — attacker uses site-to-site tunnel to access cloud EHR directly | [T1133](https://attack.mitre.org/techniques/T1133/) — External Remote Services; [T1195](https://attack.mitre.org/techniques/T1195/) — Supply Chain Compromise (BA as supply chain) | **Preparation; Post-Incident** | BAA requiring MFA and logging on BA side; quarterly BA security attestation; tunnel suspension by EHR vendor upon anomaly detection; BAA breach-notification timing ≤ 24 hours |
| 13 | **Windows 7 pill-counting VM compromise via air-gap bypass** — staff plugs infected USB into VM for "quick update" | [T1091](https://attack.mitre.org/techniques/T1091/) — Replication Through Removable Media; [T1200](https://attack.mitre.org/techniques/T1200/) — Hardware Additions | **Preparation; Containment** | Policy: no USB on air-gapped VM without IT approval + malware scan on separate quarantine machine; physical port locks; staff training |
| 14 | **Staff uses personal device for EHR access** during incident, creating shadow PHI copy | [T1659](https://attack.mitre.org/techniques/T1659/) — Content Injection? (No — this is [T1071](https://attack.mitre.org/techniques/T1071/) via BYOD); closest is [T1587.004](https://attack.mitre.org/techniques/T1587/004/) — Obtain Capabilities: Digital Certificates (not exact). **Better fit:** [T1078.004](https://attack.mitre.org/techniques/T1078/004/) — Valid Accounts: Cloud Accounts or [T1550](https://attack.mitre.org/techniques/T1550/) — Use Alternate Authentication Material | **Preparation; Post-Incident** | BYOD policy prohibiting PHI photos/screenshots on personal devices; MDM or containerization if budget permits; incident communication explicitly bans personal device use for PHI work during active events |

---

## 3. Risk Matrix

### 3.1 Risk Scoring Methodology

| Score | Likelihood | Impact |
|-------|-----------|--------|
| 1 | Rare (no historical precedent; strong controls) | Negligible (minor inconvenience, no PHI, no patient safety impact) |
| 2 | Unlikely (possible but requires multiple failures) | Minor (single workstation, <10 patients, no regulatory trigger, <$5K cost) |
| 3 | Possible (known vulnerability, no compensating control, industry precedent) | Moderate (partial system outage, 10–100 patients, state board notification, $5K–$50K cost) |
| 4 | Likely (active exploitation in wild, weak control, human factor) | Major (full outage, 100–500 patients, HHS breach notification if >500, $50K–$250K cost, reputational damage) |
| 5 | Almost Certain (no control, actively targeted, human factor guaranteed) | Critical (complete shutdown, >500 patients, HHS + media notification, >$250K cost, patient harm possible, license jeopardy) |

**Risk = Likelihood × Impact**

| Risk Score | Priority | Response |
|------------|----------|----------|
| 1–4 | Low | Accept with monitoring |
| 5–9 | Medium | Mitigate within 90 days |
| 10–16 | High | Mitigate within 30 days; escalate to pharmacy owner/board |
| 17–25 | Critical | Immediate action; suspend operations if patient safety at risk; emergency budget authorization |

### 3.2 Risk Matrix

| # | Threat Scenario | Likelihood | Impact | Risk Score | Priority |
|---|-----------------|-----------|--------|-----------|----------|
| 1 | Phishing to staff | 4 (Likely) | 3 (Moderate) | **12** | **High** |
| 2 | IT admin VPN credential compromise | 4 (Likely — MFA missing) | 4 (Major) | **16** | **High** |
| 3 | RDP brute-force / credential reuse via VPN | 3 (Possible) | 4 (Major) | **12** | **High** |
| 4 | Lateral movement via SMB/RDP | 4 (Likely — flat network) | 4 (Major) | **16** | **High** |
| 5 | Credential dumping (Mimikatz) | 3 (Possible) | 4 (Major) | **12** | **High** |
| 6 | Shadow copy deletion | 4 (Likely — standard ransomware behavior) | 3 (Moderate — if backups are good) | **12** | **High** |
| 7 | Backup drive encryption/destruction | 3 (Possible — depends on backup architecture) | 5 (Critical if no recovery path) | **15** | **High** |
| 8 | Mass file encryption (ransomware payload) | 4 (Likely — if initial access succeeds) | 5 (Critical — full shutdown) | **20** | **Critical** |
| 9 | Data exfiltration (double-extortion) | 3 (Possible) | 5 (Critical — breach notification, fines, lawsuits) | **15** | **High** |
| 10 | IoT sensor compromise | 3 (Possible — default creds) | 4 (Major — vaccine waste, patient safety, VFC reporting) | **12** | **High** |
| 11 | Label printer manipulation | 2 (Unlikely — low value to attacker) | 3 (Moderate — dispensing delay, label errors) | **6** | **Medium** |
| 12 | BA VPN tunnel compromise | 2 (Unlikely — requires BA breach first) | 5 (Critical — cloud EHR data, 1200+ patients) | **10** | **High** |
| 13 | Air-gapped VM bypass via USB | 2 (Unlikely — requires physical access + policy violation) | 3 (Moderate — inventory disruption only) | **6** | **Medium** |
| 14 | BYOD PHI leakage during incident | 3 (Possible — staff panic, no MDM) | 3 (Moderate — additional breach scope) | **9** | **Medium** |

### 3.3 Visual Risk Heat Map (Text)

```
                    IMPACT
          Negligible  Minor   Moderate   Major    Critical
            (1)       (2)      (3)        (4)       (5)
         ┌─────────┬─────────┬─────────┬─────────┬─────────┐
Almost   │    1    │    2    │    3    │    4    │    5    │
Certain  │         │         │         │   #8    │         │
  (5)    │         │         │         │         │         │
         ├─────────┼─────────┼─────────┼─────────┼─────────┤
 Likely  │    2    │    4    │    6    │    8    │   10    │
  (4)    │         │         │         │  #2,#4  │   #8    │
         ├─────────┼─────────┼─────────┼─────────┼─────────┤
 Possible│    3    │    6    │    9    │   12    │   15    │
  (3)    │         │         │  #1,#6  │ #3,#5   │ #7,#9   │
         │         │         │         │ #10     │         │
         ├─────────┼─────────┼─────────┼─────────┼─────────┤
 Unlikely│    4    │    8    │   12    │   16    │   20    │
  (2)    │         │         │         │         │         │
         ├─────────┼─────────┼─────────┼─────────┼─────────┤
  Rare   │    5    │   10    │   15    │   20    │   25    │
  (1)    │         │         │         │         │         │
         └─────────┴─────────┴─────────┴─────────┴─────────┘

LEGEND:
  #1  = Phishing to staff              #8  = Mass file encryption
  #2  = IT admin VPN cred compromise   #9  = Data exfiltration
  #3  = RDP brute-force                #10 = IoT sensor compromise
  #4  = Lateral movement               #11 = Label printer manipulation
  #5  = Credential dumping             #12 = BA VPN tunnel compromise
  #6  = Shadow copy deletion           #13 = Air-gapped VM bypass
  #7  = Backup drive destruction       #14 = BYOD PHI leakage
```

---

## 4. Playbook Phase Mapping

### 4.1 How Each Playbook Phase Counteracts Threats

| Playbook Phase | Threat(s) Directly Addressed | Mechanism |
|---------------|------------------------------|-----------|
| **Preparation** | #1 (phishing training), #2 (MFA on VPN), #3 (RDP hardening), #6 (immutable backups), #7 (air-gapped backups), #10 (IoT VLAN + credential rotation), #12 (BAA security requirements), #13 (USB policy), #14 (BYOD policy) | Reduces likelihood by hardening attack surface; reduces impact by ensuring recovery options exist |
| **Detection & Analysis** | #2 (VPN anomaly alerts), #3 (RDP logging), #4 (SMB egress monitoring), #5 (EDR LSASS alerts), #6 (shadow copy deletion alerts), #8 (file-encryption indicators), #9 (firewall exfiltration alerts), #10 (IoT dashboard offline alerts) | Shortens attacker dwell time; enables rapid SEV classification; begins breach assessment before damage expands |
| **Containment** | #2 (disable compromised account), #3 (block RDP/VPN), #4 (network segmentation emergency), #5 (credential rotation), #6 (immutable backups survive deletion), #7 (air-gapped backups unaffected), #8 (isolate encrypted systems), #9 (block egress IPs), #10 (local alarms independent of network), #12 (suspend BA tunnel), #13 (quarantine USB), #14 (ban personal devices) | Stops spread; preserves evidence; maintains patient safety via paper workflow and cold-chain continuity |
| **Eradication** | #2 (rotate ALL creds, enable MFA), #3 (disable unnecessary RDP), #4 (rebuild from gold images), #5 (LAPS deployment), #6 (restore from clean backup), #7 (rebuild backup architecture), #8 (rebuild all affected systems), #10 (firmware update + VLAN hardening), #13 (re-image VM from clean baseline) | Removes all persistence; closes infection vector; ensures no residual backdoors |
| **Recovery** | #8 (prioritized system restoration), #6 (restore from immutable backup), #7 (recovery from air-gapped/cloud backup), #10 (reconnect IoT after hardening), #12 (re-establish BA tunnel with new credentials + MFA), #11 (printer reconfiguration) | Restores operations in priority order; validates integrity before go-live; reconciles paper workflow |
| **Post-Incident** | #1 (update phishing training), #2 (MFA audit), #4 (segmentation review), #5 (credential policy), #6 (backup test frequency), #7 (backup architecture redesign), #9 (dark-web monitoring subscription), #10 (IoT vendor security review), #12 (BAA renegotiation), #13 (USB policy enforcement), #14 (MDM evaluation) | Institutionalizes lessons learned; reduces recurrence probability; fulfills regulatory obligations |

### 4.2 Residual Risk After Playbook Implementation

Even with full playbook implementation, residual risk remains:

| Residual Risk | Why It Persists | Mitigation (Beyond Playbook) |
|-------------|-----------------|------------------------------|
| Zero-day exploitation of EHR vendor | Vendor patch timeline outside pharmacy control | BAA requiring 24-hour vendor incident notification; monitor vendor status pages; maintain offline patient census for emergency |
| Insider threat (malicious staff) | Playbook assumes external attacker; insider has legitimate access | Background checks; least-privilege access; logging + quarterly access reviews; separation of duties for controlled substances |
| Nation-state APT targeting healthcare | Playbook addresses commodity ransomware; APTs use custom tooling and long dwell times | SOC-as-a-service or MDR (Managed Detection and Response) retainer; threat intelligence feeds; annual penetration test |
| Physical theft of backup drive or server | Playbook is cyber-focused; physical security is separate | Server in locked cage; backup drive in fireproof safe; offsite cloud backup as secondary |
| Supply-chain compromise of hardware/firmware | Pill-counting VM or printer firmware could be compromised at manufacture | Vendor risk assessment; purchase from authorized resellers; firmware integrity verification if supported |

---

## 5. Control Effectiveness Summary

| Control Domain | Current State (Pre-Playbook) | Target State (Post-Playbook) | Verification |
|---------------|------------------------------|------------------------------|--------------|
| **Identity & Access** | Shared workstation logins; no MFA on VPN | Unique accounts per staff; MFA on all remote access + cloud EHR | Quarterly account audit; MFA enrollment report |
| **Network Security** | Flat LAN; guest WiFi on same segment | Segmented VLANs (pharmacy LAN, IoT, guest); inter-VLAN firewall rules | Quarterly firewall rule review; network scan |
| **Endpoint Security** | Standard antivirus; no EDR | EDR on all endpoints; application allow-listing where feasible | Weekly EDR health dashboard |
| **Backup & Recovery** | Nightly USB (online); monthly cloud | 3-2-1 with air-gapped USB (disconnect after backup); immutable cloud with versioning | Monthly test restore; backup integrity hash check |
| **Monitoring & Detection** | Basic firewall logs; no SIEM | Centralized logging (SIEM or managed syslog); 72-hour log retention minimum; alerting on anomalies | Monthly alert tuning; quarterly log review |
| **Incident Response** | No documented plan | This playbook + Quick Reference + Tabletop Exercise schedule | Annual tabletop; post-incident AAR within 14 days |
| **Patient Safety Continuity** | No paper workflow; no cold-chain backup | Locked paper workflow cabinet; manual thermometer in every fridge; emergency pharmacy transfer agreements | Quarterly paper workflow drill; annual cold-chain alarm test |
| **Vendor / BA Management** | BAAs on file but no security attestation | BAAs with ≤24-hour breach notification; quarterly security attestation; MFA requirement | Annual BAA review; attestation collection |

---

## 6. Why This Playbook Is Designed This Way

### 6.1 Small-Pharmacy Realities

A 200-bed hospital has a SOC, a CISO, a 24/7 NOC, redundant EHR instances, and a $5M cyber insurance policy. A small pharmacy has:

- **One** IT admin, often contracted, often part-time.
- **One** pharmacist on duty at a time.
- **No** dedicated security staff.
- **Tight** margins — a $250K incident could close the business.
- **Regulatory** obligations identical to hospitals (HIPAA does not scale by size; state boards do not reduce requirements).

Therefore, this playbook:
- **Over-assigns roles** so that every critical function has an owner, even if one person wears multiple hats.
- **Emphasizes paper workflows** because digital redundancy may fail; patient safety cannot wait.
- **Assumes backup compromise** (shadow copy deletion, backup drive targeting) because this is standard ransomware behavior.
- **Prioritizes cold-chain** because vaccine waste + VFC reporting + patient harm is a pharmacy-specific catastrophe.
- **Mandates tabletop exercises** because small teams do not practice incident response organically.

### 6.2 Honest Limitations

This playbook is a **student portfolio piece**. It reflects real pharmacy workflows observed by a practicing CPhT, but it has not been validated by:
- A HIPAA-qualified attorney
- A CISSP or CISM-certified security professional
- A state board of pharmacy inspector
- A cyber insurance underwriter

**Before operational deployment, a real pharmacy should:**
1. Have this document reviewed by healthcare legal counsel.
2. Validate all contact numbers and BAA terms with actual vendors.
3. Conduct a live (not tabletop) backup restore test in an isolated environment.
4. Review state-specific breach notification laws (this document uses California as an example; other states differ).
5. Confirm cyber insurance policy terms align with playbook assumptions (e.g., does the policy cover ransomware negotiation firms? Business interruption due to IoT failure?)

---

## References

- MITRE ATT&CK® Framework, Enterprise Matrix v14.1 — [attack.mitre.org](https://attack.mitre.org)
- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide*
- NIST SP 800-30 Rev. 1, *Guide for Conducting Risk Assessments*
- CISA, *Stop Ransomware* — [cisa.gov/stopransomware](https://cisa.gov/stopransomware)
- HHS OCR, *Breach Notification Rule Guidance* — [hhs.gov/hipaa](https://hhs.gov/hipaa)
- CDC, *Vaccine Storage and Handling Toolkit*
- California Office of Information Security, *California Cybersecurity Maturity Metrics*

---

*Last updated: 2026-06-01 | Next review: 2026-12-01*
