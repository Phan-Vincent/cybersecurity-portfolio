# Tabletop Exercise: "Saturday Night Lock"
## Ransomware Incident Response — Small Pharmacy Setting

**Version:** 1.0  
**Classification:** Internal Training — Synthetic Scenario  
**Target Participants:** Pharmacy Manager, Pharmacist-in-Charge, IT Admin / MSP, Privacy Officer, Pharmacy Technician(s), Front-of-House Staff  
**Duration:** 3 hours (with option to compress to 90 minutes for a tabletop walkthrough)  
**Facilitator:** Designated Incident Commander or external IR consultant  

---

## 1. Scenario Overview

### 1.1 Setting

**Greenfield Community Pharmacy** is a small independent pharmacy in a suburban area. The pharmacy serves approximately 1,200 active patients, with 200–300 prescriptions filled weekly. Staff:

- 1 Pharmacy Manager (also PIC, HIPAA Privacy Officer)
- 2 Staff Pharmacists (rotating shifts)
- 2 Certified Pharmacy Technicians (CPhT)
- 1 Front-of-House Clerk
- 1 contracted IT administrator (visits twice weekly; remote monitoring via RDP over VPN)

**Systems:**
- 1 primary dispensary workstation (Windows 10, connected to EHR via web portal)
- 1 back-office billing workstation (Windows 10, claims processing software)
- 1 shared office laptop (Windows 11, admin tasks, HR, email)
- Cloud-based EHR (hosted by vendor "MediCloudRx")
- On-premise insurance billing server (physical tower, Windows Server 2019, connects to clearinghouse)
- IoT temperature sensors (4 units: 2 vaccine fridges, 1 biologics fridge, 1 varicella freezer) — cloud-dashboard dependent, but with local audible alarms
- Networked thermal label printers (2 units, Zebra ZD421)
- Wholesale ordering portal (web-based, accessed via browser)
- Backups: nightly to external USB 3.0 drive (connected to billing server); monthly offsite to encrypted cloud storage (Backblaze B2)

**Known weaknesses (pre-exercise):**
- The pill-counting interface runs on an isolated Windows 7 virtual machine (no network card, no internet access — documented compensating control).
- The IT admin uses RDP over an OpenVPN tunnel for remote access. MFA was "planned for next quarter."
- One backup USB drive is permanently plugged into the billing server.
- Staff have received phishing simulation emails quarterly; last training was 4 months ago.
- Business Associate VPN tunnel: the EHR vendor maintains a site-to-site VPN for data sync. The clearinghouse uses a dedicated MPLS line.

### 1.2 The Event

**Saturday, June 13, 2026. 6:47 PM PDT.**

The pharmacy closed at 6:00 PM. Sarah, a pharmacy technician, returned at 6:30 PM to retrieve her forgotten phone. She noticed the dispensary workstation screen was on — unusual, as the auto-sleep is set to 15 minutes. The wallpaper had changed to a black screen with red text:

> **YOUR FILES HAVE BEEN ENCRYPTED.**  
> **All data on this network has been locked with military-grade encryption.**  
> **To recover your files, you must pay $85,000 in Bitcoin within 72 hours.**  
> **Do not attempt to restore from backups. We have already deleted your shadow copies and infected your backup drive.**  
> **Contact us at: darkrecovery2026@onionmail.org**  
> **Your patient data will be sold on the dark web if you do not comply.**

Sarah takes a photo with her personal phone and calls the on-call pharmacist, Dr. James Park (Pharmacist-in-Charge), at 6:49 PM.

**Current state at 6:47 PM:**
- Dispensary workstation: encrypted, ransom note visible.
- IoT sensor dashboard (accessed via web browser): loading slowly, then shows "Connection Timeout."
- Local audible alarm on vaccine fridge A: **beeping** (intermittent, not the usual steady hum).
- Billing server: unknown — no one is in the back office.
- EHR (MediCloudRx): accessible from Sarah's phone browser? **Yes, but extremely slow. Dashboard shows a yellow warning banner: "Unusual sync activity detected. Site-to-site tunnel unstable."
- Back office shared laptop: unknown.
- The pharmacy reopens Monday at 9:00 AM — **18 hours away.**
- Sunday is typically the busiest phone day (patients calling in refills for Monday pickup).

---

## 2. Exercise Injects

Injects are delivered by the facilitator at specified intervals to stress-test decisions and reveal gaps.

### Inject 1 — T+30 Minutes (7:17 PM)

**Facilitator announces:**

> Dr. Park arrives at the pharmacy at 7:10 PM. He checks the back office and finds the billing server screen also showing a ransom note — different Bitcoin address, same threat actor styling. The permanently attached USB backup drive's LED is blinking rapidly (unusual). He disconnects the drive.
>
> Dr. Park logs into the MediCloudRx EHR from his phone. The patient search function works, but prescription history pages load with garbled formatting — some records show "SYNC_ERROR" in red. The EHR vendor's status page (public) shows: "Degraded Performance — Site-to-site connectivity issues under investigation."
>
> The local audible alarm on vaccine fridge A is now **continuous**. The standalone thermometer inside reads **52°F** (CDC max: 46°F). Vaccine fridge B reads 41°F (normal). Biologics fridge reads 39°F (normal). Varicella freezer reads -2°F (CDC min: -13°F for varicella).

**Discussion questions for participants:**
1. What is your SEV classification now? Has it changed from the initial report?
2. Do you activate the full paper workflow immediately, or wait for more information?
3. Who do you call next, and in what order? (IT admin, EHR vendor, cold-chain sensor vendor, state board, cyber insurance?)
4. Vaccine fridge A is out of range. What is your immediate action? Do you move vaccines to fridge B (risking overfilling and temperature fluctuation), or to an external location?
5. The EHR is partially accessible but showing sync errors. Is the EHR compromised, or is this a symptom of the site-to-site tunnel being attacked? Do you trust it for patient lookups during the emergency?

### Inject 2 — T+2 Hours (8:47 PM)

**Facilitator announces:**

> The IT admin, Marcus, arrives remotely (he is at a family dinner 90 minutes away). He connects via VPN — **the VPN connection fails**. He tries the secondary VPN endpoint; it connects but immediately drops. He calls the firewall vendor support line and learns:
>
> - The primary VPN endpoint has been blacklisted by the firewall due to "excessive failed authentication attempts from an IP in Romania."
> - The secondary endpoint shows active sessions from two unknown IPs: one in Romania, one in Moldova. Both authenticated successfully within the last 4 hours using the IT admin's own credentials.
> - Firewall logs show large SMB file-copy operations from the billing server to an external IP between 5:30 PM and 6:15 PM — before encryption began.
>
> Marcus realizes his VPN credentials were phished three days ago. He received an email appearing to be from the firewall vendor with a "critical security update" link. He entered his credentials. He did not report it because "the page looked legit and nothing bad happened."
>
> The EHR vendor (MediCloudRx) calls Dr. Park directly (they have his cell from the BAA): "We are seeing anomalous database queries originating from your site-to-site tunnel. We have suspended the tunnel as a precaution. Your patient data in our cloud environment appears intact, but we are conducting a forensic audit. We will keep the tunnel down until we complete our investigation — estimated 24–48 hours."

**Discussion questions:**
1. The attacker had Marcus's VPN credentials for 3 days. What does this imply about the "window of compromise"? How far back do you need to review logs?
2. SMB file-copy operations occurred **before** encryption. Is this evidence of data exfiltration, or could it be shadow-copy deletion staging? Does this change your breach assessment?
3. Marcus is a business associate (contracted IT). His credential compromise triggered the incident. What BAA obligations are triggered? Does the pharmacy bear full breach responsibility, or shared?
4. The EHR vendor has suspended the tunnel for 24–48 hours. You cannot sync prescription data to the cloud EHR. Can you still use the web portal for read-only patient lookups? If not, how do you verify patient identity and prescription history for emergency dispensing?
5. Do you contact law enforcement now? FBI IC3? Local police? What information do you have that makes this a criminal matter vs. a security incident?
6. The ransom note threatened to sell patient data on the dark web. You have evidence of pre-encryption file-copy. Do you begin individual breach notification preparation now, or wait for forensic confirmation of what was copied?

### Inject 3 — T+8 Hours (Sunday, 2:47 AM)

**Facilitator announces:**

> Overnight, the pharmacy's Google Business Profile receives a 1-star review: "Tried to call for my mom's insulin refill at 10 PM. No answer. Voicemail full. This pharmacy is unreliable." The reviewer is a real patient (John M., verified Google user).
>
> At 2:00 AM, the on-call pharmacist (Dr. Park, still awake) receives a text message from an unknown number:
> 
> *"Hi Dr. Park. We have your patient database. 1,247 patients. Nice list. We will release it in 48 hours unless you pay. Here is a sample: [partial redacted screenshot of a patient record — Maria G., DOB 03/14/1962, Lisinopril 10mg, Anthem BCBS member ID]. This is real. Check your EHR if you don't believe us."*
>
> Dr. Park checks the EHR via web portal. The patient record for Maria G. is accessible and appears normal — but the "last modified" timestamp shows 5:42 PM yesterday, when the pharmacy was already closed. No staff were logged in.
>
> The IT admin (Marcus) has been working remotely with the firewall vendor. They confirm: the SMB copies included files from the billing server's `D:\Backups\` directory, which contained the nightly backup images. The backup drive that was disconnected earlier? Forensic imaging shows it was **not** encrypted — but it contains corrupted backup headers, suggesting the attacker attempted to destroy backups before encryption.

**Discussion questions:**
1. The text message with a real patient record is strong evidence of exfiltration. Does this definitively prove a breach under HIPAA § 164.402? What additional factors does the Privacy Officer need to assess?
2. The "last modified" timestamp on Maria G.'s record changed at 5:42 PM when the pharmacy was closed. Could the attacker have modified cloud EHR data via the site-to-site tunnel? What does this mean for data integrity? Do you need to notify patients that their records may have been altered?
3. The backup drive was not encrypted but has corrupted headers. Is there any path to recovery from local backups? What is your recovery strategy now?
4. The Google review is public. Do you respond? Do you disclose the incident? What is your patient communication strategy for Monday morning when the pharmacy opens and patients arrive expecting refills?
5. Marcus's credentials were compromised for 3 days. He is a contracted BA. What disciplinary or contractual actions are appropriate? Does this change your BAA review process going forward?
6. The ransom deadline is 72 hours from 6:47 PM Saturday = 6:47 PM Tuesday. It is now 2:47 AM Sunday. You have approximately 64 hours remaining. Do you engage a ransomware negotiation firm (via cyber insurance)? Do you consider paying? What are the ethical, legal, and business considerations for a pharmacy handling PHI?

### Inject 4 — T+24 Hours (Sunday, 6:47 PM)

**Facilitator announces:**

> The pharmacy has been closed all Sunday. Staff have been rotating through in pairs to monitor cold-chain temperatures manually every 30 minutes. Vaccine fridge A was emptied at 8:30 PM Saturday (vaccines transferred to a nearby hospital outpatient pharmacy with an emergency agreement). The varicella freezer remained at -2°F for 6 hours before a portable freezer unit was delivered by a local medical supply company at 3:00 AM Sunday.
>
> At 6:00 PM Sunday, MediCloudRx restores the site-to-site tunnel in **read-only mode**. Cloud EHR data is intact, but the sync-audit reveals that 73 patient records had unauthorized "view" access timestamps between 5:15 PM and 5:55 PM Saturday — consistent with the attacker browsing the database via the compromised tunnel. No modifications were detected in the cloud layer (the 5:42 PM "last modified" on Maria G.'s record was a cache artifact, confirmed by MediCloudRx).
>
> The external IR firm (retained via cyber insurance) completes forensic imaging of the dispensary workstation, billing server, and backup drive. Their preliminary report:
> - **Ransomware family:** LockBit 3.0 variant (confirmed by encrypted file extensions `.abcd1234` and ransom note styling).
> - **Initial access:** Phished VPN credentials (IT admin) → RDP lateral movement → credential dumping (Mimikatz) → local admin escalation → mass encryption.
> - **Exfiltration:** Confirmed. Approximately 3.2 GB of data copied via SMB to external staging server (IP geolocated to Romania, now offline). Data includes: billing server backup images (containing encrypted PHI), EHR sync cache files (unencrypted PHI including names, DOBs, diagnoses, medications, insurance IDs), and patient contact lists.
> - **No payment:** The pharmacy has not paid the ransom. The attacker's wallet has received payments from other victims but not this address.
> - **Patient count:** 1,247 unique individuals in the exfiltrated dataset. **>500 individuals.**

**Discussion questions:**
1. With >500 individuals confirmed affected, HHS Secretary notification is mandatory within 60 days. When do you begin drafting? Who approves the language? Do you use a template or legal counsel?
2. The exfiltrated data included backup images (encrypted at rest with AES-256) and EHR sync cache files (unencrypted in transit/cache). Does the backup encryption satisfy the "unusable, unreadable, or indecipherable" safe harbor under § 164.402(1)? What about the unencrypted cache files?
3. Vaccine fridge A was out of range for approximately 2 hours (6:47 PM to 8:30 PM). Varicella freezer was out of range for 6 hours. What is the CDC / VFC reporting obligation? Do you discard the affected vaccines? What is the cost, and is it covered by insurance?
4. The pharmacy reopens Monday at 9:00 AM. What is your go-live checklist? In what order do you restore systems? Do you open the doors if the EHR is still read-only?
5. Staff are exhausted. Marcus (IT admin) is emotionally distressed and considering resigning. What is your team welfare protocol during a prolonged incident?
6. What are your top 3 playbook updates based on this exercise? What controls would have prevented or mitigated this incident?

---

## 3. Expected Decisions & Reference Solutions

The facilitator should not present these as "correct answers" until after discussion. They represent a well-reasoned baseline.

### Inject 1 — Expected Decisions
- **SEV-1 (Critical)** — confirmed by second encrypted system + IoT disruption + patient safety impact.
- **Activate paper workflow immediately** — do not wait for IT assessment; patient safety is time-critical.
- **Call order:** (1) IT admin/MSP, (2) EHR vendor, (3) cyber insurance, (4) cold-chain sensor vendor (after patient safety stabilized), (5) state board (after initial containment).
- **Vaccine fridge A:** Document temperatures. If >46°F for >2 hours, initiate waste protocol. Move vaccines to fridge B only if fridge B has capacity and will not exceed 46°F. Otherwise, contact emergency cold-storage partner (hospital outpatient pharmacy, 15-minute drive).
- **EHR with sync errors:** Use for read-only patient ID verification only. Do not rely on it for prescription history accuracy during the emergency. Cross-check with hard-copy prescription logs if available.

### Inject 2 — Expected Decisions
- **Window of compromise:** Minimum 72 hours (phishing event + 3 days). Review logs for 7 days prior to detection to identify reconnaissance.
- **SMB copies before encryption:** Strong indicator of double-extortion (exfiltrate, then encrypt). Treat as confirmed data theft for breach assessment purposes.
- **BAA obligations:** Marcus is a BA. His credential compromise is a BA breach. The CE (pharmacy) must document whether the BA notified within the BAA timeframe. The CE remains responsible for patient notification.
- **EHR tunnel down:** If web portal read-only is functional, use for patient ID verification. For prescription history, rely on hard-copy refill logs and patient self-report (with pharmacist professional judgment). For controlled substances, defer to physician contact or transfer to another pharmacy.
- **Law enforcement:** FBI IC3 within 24 hours. Local police only if physical break-in suspected (not applicable here).

### Inject 3 — Expected Decisions
- **Text message evidence:** Strong evidence of exfiltration. Begin breach notification preparation immediately. Do not wait for full forensic report.
- **Data integrity:** The cache artifact explanation is plausible but must be verified by EHR vendor's forensic audit. Notify patients that unauthorized access occurred; data modification risk is low but not zero.
- **Backup recovery:** Corrupted headers on an unencrypted drive may be recoverable by forensic specialists. Engage data recovery service via cyber insurance. Primary recovery path: cloud EHR data + rebuild billing server from OS image + reconfigure clearinghouse connection. Secondary path: data recovery from backup drive.
- **Public communication:** Do not respond to the Google review with incident details. Draft a holding statement: "We experienced a temporary technical issue and are working to restore full service. We apologize for any inconvenience." If media notification is required (>500), prepare a factual press release in consultation with legal counsel.
- **Ransom payment:** Generally not recommended for healthcare. Payment does not guarantee data deletion, may violate OFAC sanctions if threat actor is on SDN list, and does not absolve breach notification obligations. Engage negotiation firm only if cyber insurance approves and legal counsel concurs.

### Inject 4 — Expected Decisions
- **HHS notification:** Begin drafting immediately. Submit within 60 days. Legal counsel reviews. Include: nature of breach, types of PHI involved, steps taken, contact information.
- **Safe harbor:** Backup encryption (AES-256, keys not compromised) may qualify as "unusable" for the backup images. However, the unencrypted EHR sync cache files do NOT qualify. Breach is confirmed for the cache data.
- **Vaccine waste:** Document temperature excursion. Discard vaccines from fridge A (out of range >2 hours). Varicella freezer at -2°F for 6 hours — varicella vaccine must be stored at -50°C to -15°C. Discard. Report to state immunization program and VFC coordinator (if VFC vaccines). Cost: ~$4,000–$8,000. Cyber insurance business interruption coverage may apply; property coverage may not.
- **Go-live Monday:** Open with paper workflow for controlled substances and new prescriptions. EHR read-only for verification. Claims processing: retrospective billing only (collect insurance images, bill within 7-day window). Dispensary workstation: rebuild from gold image or replace hardware.
- **Staff welfare:** Rotate shifts. Provide clear handoffs. Offer EAP if available. Marcus needs support, not blame — but BAA breach documentation is still required.
- **Playbook updates:** (1) MFA on VPN immediately, (2) air-gapped backups (disconnect after backup, test restore monthly), (3) phishing simulation monthly with immediate reporting reward, (4) BAA addendum requiring BA incident notification within 4 hours.

---

## 4. Facilitator Guide

### 4.1 Pre-Exercise Setup (1 Week Before)

| Task | Owner | Done? |
|------|-------|-------|
| Print scenario and injects (do not distribute injects to participants in advance) | Facilitator | ☐ |
| Print Quick Reference and Playbook for each participant | Facilitator | ☐ |
| Confirm participant roles map to pharmacy org chart (adjust roles if staff numbers differ) | Facilitator | ☐ |
| Set up room: whiteboard, projector for timeline, sticky notes for decision capture | Facilitator | ☐ |
| Prepare evaluation form (see section 4.3) | Facilitator | ☐ |
| Notify cyber insurance carrier of exercise (some policies require notification for tabletop exercises) | Pharmacy Manager | ☐ |

### 4.2 Exercise Flow

| Phase | Time | Activity |
|-------|------|----------|
| **Introduction** | 0:00–0:15 | Facilitator explains rules: no penalties for wrong answers, all phones on silent, decisions are documented but not acted upon in real systems. Distribute roles. |
| **Scenario briefing** | 0:15–0:30 | Read the "Event" section. Participants ask clarifying questions about the pharmacy setting only (not about the attack). |
| **Inject 1** | 0:30–1:15 | Deliver Inject 1. Facilitated discussion. Capture decisions on whiteboard. Do not guide. |
| **Inject 2** | 1:15–2:00 | Deliver Inject 2. Discussion. |
| **Break** | 2:00–2:15 | — |
| **Inject 3** | 2:15–2:45 | Deliver Inject 3. This is the highest-stress inject; allow emotional reactions and document them. |
| **Inject 4** | 2:45–3:15 | Deliver Inject 4. Focus on recovery, go-live, and regulatory compliance. |
| **Hot wash** | 3:15–3:45 | Open discussion: what was hardest? What surprised you? What do you need that you don't have? |
| **Closeout** | 3:45–3:55 | Facilitator presents expected decisions (reference solutions) for comparison. No scoring — only learning. |
| **Action items** | 3:55–4:00 | Each participant writes one personal action item on a sticky note. Aggregated into AAR. |

### 4.3 Evaluation Criteria

Use this form to assess participant performance qualitatively (not scored, but noted for improvement).

| Criterion | Observed? | Notes |
|-----------|-----------|-------|
| Incident declared within 15 minutes of discovery | ☐ Yes ☐ No ☐ Partial | |
| Correct SEV classification applied | ☐ Yes ☐ No ☐ Partial | |
| Patient safety prioritized over IT recovery | ☐ Yes ☐ No ☐ Partial | |
| Evidence preservation attempted before remediation | ☐ Yes ☐ No ☐ Partial | |
| Business Associates contacted within 2 hours | ☐ Yes ☐ No ☐ Partial | |
| Breach assessment initiated within first hour | ☐ Yes ☐ No ☐ Partial | |
| Cold-chain contingency activated correctly | ☐ Yes ☐ No ☐ Partial | |
| Paper workflow activated smoothly | ☐ Yes ☐ No ☐ Partial | |
| Law enforcement (FBI IC3) notified appropriately | ☐ Yes ☐ No ☐ Partial | |
| Cyber insurance engaged appropriately | ☐ Yes ☐ No ☐ Partial | |
| Staff communication controlled (no leaks, no panic) | ☐ Yes ☐ No ☐ Partial | |
| Ransom payment not the first resort | ☐ Yes ☐ No ☐ Partial | |
| Recovery prioritized correctly (P0→P6) | ☐ Yes ☐ No ☐ Partial | |
| Regulatory notifications (HHS, state board) planned correctly | ☐ Yes ☐ No ☐ Partial | |
| Post-incident improvement actions identified | ☐ Yes ☐ No ☐ Partial | |

### 4.4 Common Gaps to Watch For

1. **"Let's just reboot it."** — Some participants will want to restart the encrypted workstation. Facilitator should not intervene unless the group is unanimously going down this path; instead, ask: "What happens to volatile memory evidence if you reboot?"
2. **"We have backups, we'll be fine."** — Participants may assume backup recovery is trivial. Inject 3 (corrupted headers) tests this assumption.
3. **"Call the FBI first."** vs. **"Call IT first."** — Both are reasonable, but the facilitator should note whether patient safety or legal/compliance concerns are being delayed.
4. **"We can't open Monday."** vs. **"We must open Monday no matter what."** — Both extremes reveal gaps in business continuity planning. The goal is a risk-based go-live.
5. **No one claims the Privacy Officer role.** — In small pharmacies, the PIC is often the Privacy Officer, but they may not self-identify during the exercise. The facilitator should prompt: "Who is responsible for assessing whether this is a HIPAA breach?"
6. **IoT/cold-chain ignored until late.** — The IoT alarm in Inject 1 is a distractor that tests whether technical staff fixate on the "main" attack (ransomware on workstations) while ignoring physical safety signals.

### 4.5 Post-Exercise Actions

Within 5 business days of the tabletop:
1. Facilitator writes a 1-page AAR summarizing key decisions, gaps, and action items.
2. Pharmacy Manager assigns action items with deadlines.
3. Playbook and Quick Reference updated based on lessons learned.
4. Schedule next tabletop in 6–12 months, or sooner if major staff/system changes occur.
5. If the exercise revealed that the pharmacy is missing critical capabilities (e.g., no cyber insurance, no external IR retainer, no air-gapped backups), the Pharmacy Manager budgets for remediation.

---

## 5. Synthetic Data Pledge

All patient names, dates of birth, medication histories, insurance member IDs, and system identifiers in this exercise are **entirely synthetic**:

- **Maria G.** — Synthetic patient. No real individual matches this name + DOB combination.
- **Anthem BCBS member ID** — Formatted as a typical member ID but not valid.
- **Bitcoin addresses** — Fictional.
- **Email addresses** (`darkrecovery2026@onionmail.org`) — Fictional.
- **IP addresses** — Geolocation references (Romania, Moldova) are illustrative; no specific IPs are listed.
- **MediCloudRx** — Fictional EHR vendor name.
- **Greenfield Community Pharmacy** — Fictional organization.

No real PHI, PII, passwords, credentials, or system configurations are disclosed in this document.

---

*Facilitator: [Name] | Date: _______________ | Next tabletop: _______________*