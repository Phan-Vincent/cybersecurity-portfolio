# Ransomware Incident Response — Quick Reference
## First 24 Hours | Small Pharmacy / Clinic
**Version 1.0 | Keep printed & laminated near dispensary workstation & IT admin desk**

---

## ⚠️ FIRST 15 MINUTES

| # | Action | Who | Done? |
|---|--------|-----|-------|
| 1 | **STOP.** Do not turn off the affected computer yet. Hibernation or network-disconnect preserves evidence. | First discoverer | ☐ |
| 2 | **Isolate.** Pull the network cable or disable WiFi. If it is the only dispensary terminal and patients are waiting, isolate at the switch/firewall level instead (call IT). | First discoverer / IT | ☐ |
| 3 | **Photo the screen.** Use your phone camera. Capture the ransom note, any visible filenames, and the system clock. Do not use screenshot tools. | First discoverer | ☐ |
| 4 | **Record.** Write down: exact time of discovery, user logged in, what you were doing, any unusual popups or emails in the last 2 hours. | First discoverer | ☐ |
| 5 | **Notify Incident Commander (IC).** Call the on-duty Pharmacy Manager or Pharmacist-in-Charge immediately. | First discoverer | ☐ |
| 6 | **IC declares SEV-1.** If ransomware is confirmed and PHI systems are affected, this is SEV-1 (Critical). | IC | ☐ |
| 7 | **Contact IT lead.** If internal IT is unavailable, call external IT / MSP retainer. Provide hostname and symptoms. | IC | ☐ |
| 8 | **Activate paper workflow.** Begin manual dispensing log for urgent/critical medications only. Defer non-urgent refills. | Pharmacist on duty | ☐ |
| 9 | **Check cold-chain alarms.** Verify local audible alarms on all vaccine/biologic fridges. If IoT dashboard is down, switch to manual thermometer checks every 30 minutes. | Patient Safety Lead | ☐ |
| 10 | **Preserve other systems.** If lateral movement is suspected, IC orders: disable inter-VLAN routing, block all outbound traffic at firewall except logging, disable VPN tunnels. | IT Lead | ☐ |

---

## 📋 15 MINUTES – 2 HOURS

| # | Action | Who | Done? |
|---|--------|-----|-------|
| 11 | **Scope assessment.** IT + Privacy Officer determine: which systems encrypted, what data classes affected, estimated patient count. | IT / Privacy Officer | ☐ |
| 12 | **Evidence collection.** IT captures RAM dump (if safe), exports 72 hours of firewall/VPN/EDR logs, images affected VMs before any cleanup. | IT Lead | ☐ |
| 13 | **Business Associate alerts.** Contact EHR vendor, claims processor, wholesaler IT desk. Confirm their systems are not compromised via shared tunnel. | BA Liaison | ☐ |
| 14 | **Patient safety triage.** Identify patients on critical meds (antiretrovirals, anticoagulants, insulin, transplant meds). Contact them or their physicians to arrange emergency transfer if dispensing is halted >4 hours. | Patient Safety Lead | ☐ |
| 15 | **Cyber insurance notification.** Call hotline. Provide policy number from sealed envelope in manager safe. | IC | ☐ |
| 16 | **FBI IC3 report.** File initial complaint at ic3.gov (or via FBI local field office if >$100K demand or critical infrastructure). | IC | ☐ |
| 17 | **Legal counsel.** If your organization retains healthcare counsel, notify them now for breach-notification guidance. | IC | ☐ |
| 18 | **Staff communication.** Brief all on-duty staff: what happened, what not to do (no screenshots to personal devices, no social media, no email from personal accounts about the incident). | Communications Lead | ☐ |
| 19 | **Breach assessment kickoff.** Privacy Officer begins HIPAA Breach Risk Assessment (§ 164.404). Assume breach unless low probability is demonstrated. | Privacy Officer | ☐ |
| 20 | **Paper workflow sustain.** Continue manual DUR, dispensing logs, and insurance card image capture (encrypted storage, deleted after billing resolved). | Pharmacist / Tech | ☐ |

---

## 🔒 2 – 24 HOURS

| # | Action | Who | Done? |
|---|--------|-----|-------|
| 21 | **Containment confirmation.** IT confirms: no new encryptions appearing, firewall blocks holding, no unauthorized RDP/VPN sessions active. | IT Lead | ☐ |
| 22 | **Forensic imaging complete.** All affected systems imaged before remediation begins. Chain-of-custody labels applied. | IT Lead | ☐ |
| 23 | **Credential rotation.** Reset ALL passwords: domain admin, local admin, EHR admin, VPN, cloud services, IoT sensors. Enable MFA everywhere it was missing. | IT Lead | ☐ |
| 24 | **Persistence hunt.** Check for: new scheduled tasks, new local admins, WMI subscriptions, registry run keys, shadow-copy deletions, remote-access backdoors. | IT Lead / External IR | ☐ |
| 25 | **Recovery staging.** Prioritize: P0 cold-chain alarms (already local), P1 EHR, P2 dispensary workstation + label printers, P3 claims/billing, P4 inventory, P5 IoT dashboards, P6 other. | IT Lead | ☐ |
| 26 | **Patch & harden.** All rebuilt systems: OS patches applied, RDP disabled or MFA+VPN-required, EDR healthy, backup immutability verified. | IT Lead | ☐ |
| 27 | **Notification decision — >500 individuals?** If likely or confirmed: HHS Secretary notification must occur within 60 days. Begin drafting. If uncertain, assume >500. | Privacy Officer | ☐ |
| 28 | **State Board notification.** Notify state board of pharmacy "without unreasonable delay" per state law. | Privacy Officer | ☐ |
| 29 | **Patient notification prep.** Draft individual notification letters (or emails if consented). Include: what happened, what data was involved, steps taken, contact info for questions, credit monitoring offer (optional but recommended). | Privacy Officer / Comms | ☐ |
| 30 | **Media notification (if >500).** Draft notification for prominent media outlet in affected state/jurisdiction. | Communications Lead | ☐ |
| 31 | **Recovery validation.** Before go-live: forensic sign-off, vulnerability scan clean, EDR healthy, backup spot-check passed, BA recovery status confirmed. | IT Lead + IC | ☐ |
| 32 | **Reconcile paper logs.** Within 24 hours of EHR restoration, reconcile all emergency paper-dispensed prescriptions into the system. | Pharmacist / Tech | ☐ |
| 33 | **Retrospective billing.** Submit claims for emergency-dispensed medications within payer window (typically 7–14 days). | Billing Lead | ☐ |
| 34 | **Temperature excursion review.** If any cold-chain deviation occurred, document waste and notify state immunization program / VFC coordinator if applicable. | Patient Safety Lead | ☐ |

---

## 🚨 DECISION CHEATSHEET

| Situation | Decision |
|-----------|----------|
| Only 1 workstation encrypted, backups clean, no PHI exfiltration evidence | SEV-2. Internal IR. Notify BAs. Contain. Restore from backup. Breach assessment still required. |
| EHR + multiple systems encrypted; backups corrupted or unknown | SEV-1. Full activation. External IR. FBI IC3. Cyber insurance. Assume breach. Activate paper workflow immediately. |
| Ransom demand received | Do not pay without: IC approval + legal counsel + cyber insurance input + law enforcement consult. Payment does not guarantee decryption or prevent data sale. |
| Patient calls asking why their refill is delayed | Script: "We are experiencing a temporary systems issue and are filling prescriptions using our backup procedures. Urgent medications are our top priority. We will call you when your prescription is ready." Do not mention "ransomware" or "hack" to patients unless media notification already required. |
| Staff asks if they can work from home / check email on phone | No. Do not use personal devices for PHI work during an active incident. All remote access is suspended until containment is confirmed. |
| IoT sensor dashboard is down but local alarm is beeping | Local alarm is P0. Go to fridge. Check standalone thermometer. Log temps manually every 30 min. Call sensor vendor support after patient safety is stable. |

---

## 📞 CRITICAL CONTACTS (Fill in before laminating)

| Contact | Name / Role | Phone | After-Hours | Account # |
|---------|-------------|-------|-------------|-----------|
| Incident Commander (primary) | | | | — |
| Incident Commander (backup) | | | | — |
| IT Lead / MSP | | | | |
| Privacy Officer / HIPAA | | | | — |
| Cyber Insurance Hotline | | | | Policy #: |
| FBI IC3 | — | Online: ic3.gov | — | — |
| HHS OCR Breach Portal | — | [ocrportal.hhs.gov](https://ocrportal.hhs.gov) | — | — |
| State Board of Pharmacy | | | | License #: |
| EHR Vendor Support | | | | |
| Claims Processor | | | | |
| Wholesale Supplier IT | | | | |
| Cold-Chain Sensor Vendor | | | | |
| External IR Retainer | | | | Contract #: |
| Legal Counsel | | | | — |
| Pharmacy After-Hours Line | | | | — |

---

*Last updated: 2026-06-01 | Next review: 2026-12-01*
