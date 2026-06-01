# Incident Ticket — Ransomware Response Log

**ITSM / Ticketing Template for Internal Incident Documentation**

> **SYNTHETIC TEMPLATE** — This is a student-created template for a cybersecurity portfolio project. It is intended for educational and training purposes.

---

## Ticket Header

| Field | Value |
|-------|-------|
| **Ticket ID** | {{TICKET_ID}} |
| **Incident Type** | Ransomware / Malware Outbreak |
| **Severity** | {{SEVERITY}} (P1-Critical / P2-High / P3-Medium / P4-Low) |
| **Status** | {{STATUS}} (Open / In Progress / Contained / Eradicated / Closed) |
| **Created By** | {{CREATED_BY}} |
| **Created Date/Time** | {{CREATED_DATETIME}} |
| **Assigned To** | {{ASSIGNED_TO}} |
| **Incident Commander** | {{INCIDENT_COMMANDER}} |

---

## 1. Discovery & Initial Detection

### Discovery Timestamp
- **First observed:** {{FIRST_OBSERVED_DATETIME}}
- **Reported by:** {{REPORTED_BY}} (user / automated alert / third party)
- **Detection method:** {{DETECTION_METHOD}} (EDR alert / SIEM correlation / user report / antivirus / third-party notification)

### Initial Indicators of Compromise (IOCs)

{{#INITIAL_IOCS}}
- **Indicator:** {{INDICATOR}}
- **Type:** {{TYPE}} (file hash / domain / IP / registry key / process name / ransom note filename)
- **Affected host:** {{HOSTNAME}}
- **Timestamp:** {{IOC_TIMESTAMP}}
- **Severity:** {{IOC_SEVERITY}}
{{/INITIAL_IOCS}}

### Initial Symptoms Observed

- {{SYMPTOM_1}}
- {{SYMPTOM_2}}
- {{SYMPTOM_3}}

### Ransom Note Details (if applicable)

- **Filename:** {{RANSOM_NOTE_FILENAME}}
- **Extension pattern:** {{FILE_EXTENSION_PATTERN}}
- **Ransom demand amount:** {{RANSOM_DEMAND}}
- **Payment method requested:** {{PAYMENT_METHOD}}
- **Contact mechanism:** {{CONTACT_METHOD}}
- **Leak site mentioned:** {{LEAK_SITE}}
- **Deadline:** {{DEADLINE}}

---

## 2. Affected Systems

### Confirmed Affected Hosts

| Hostname | Role | OS | IP | Status | Encryption % | Criticality |
|----------|------|-----|-----|--------|-------------|-------------|
{{#AFFECTED_HOSTS}}
| {{HOSTNAME}} | {{ROLE}} | {{OS}} | {{IP}} | {{STATUS}} | {{ENCRYPTION_PERCENT}} | {{CRITICALITY}} |
{{/AFFECTED_HOSTS}}

### Affected Data / Systems

- **Patient database:** {{PATIENT_DB_STATUS}} (encrypted / intact / unknown)
- **Billing system:** {{BILLING_STATUS}}
- **Prescription processing:** {{RX_STATUS}}
- **Backup systems:** {{BACKUP_STATUS}}
- **Domain controller:** {{DC_STATUS}}
- **Email / communication:** {{EMAIL_STATUS}}

---

## 3. Containment Actions Taken

### Immediate Containment (0–4 hours)

| Time (from discovery) | Action | Performed By | Status |
|----------------------|--------|--------------|--------|
{{#CONTAINMENT_ACTIONS}}
| {{RELATIVE_TIME}} | {{ACTION}} | {{PERFORMED_BY}} | {{STATUS}} |
{{/CONTAINMENT_ACTIONS}}

### Network Isolation Details

- **Internet disconnected:** {{INTERNET_DISCONNECTED}} (Y/N — timestamp)
- **Inter-VLAN routing disabled:** {{VLAN_ROUTING_DISABLED}} (Y/N — timestamp)
- **VPN tunnels terminated:** {{VPN_TERMINATED}} (Y/N — timestamp)
- **Affected hosts isolated:** {{HOSTS_ISOLATED}} (Y/N — timestamp)
- **WiFi disabled:** {{WIFI_DISABLED}} (Y/N — timestamp)

### Backup Integrity Check

- **Last known good backup:** {{LAST_GOOD_BACKUP_DATE}}
- **Backup location:** {{BACKUP_LOCATION}} (NAS / cloud / tape / offsite)
- **Backup verification status:** {{BACKUP_VERIFIED}} (verified / unverified / corrupted / inaccessible)
- **Restoration tested:** {{RESTORATION_TESTED}} (Y/N / in progress)
- **Estimated restoration time:** {{RTO_HOURS}} hours

---

## 4. Evidence Preservation

### Forensic Preservation Status

- **Memory dumps captured:** {{MEMORY_DUMPS_STATUS}} (completed / pending / N/A)
- **Disk images captured:** {{DISK_IMAGES_STATUS}}
- **Log collection:** {{LOG_COLLECTION_STATUS}}
- **Chain of custody initiated:** {{COC_INITIATED}} (Y/N — case number: {{COC_CASE_NUMBER}})

### Logs Collected

| Log Source | Location / Path | Retention Status | Notes |
|-----------|-----------------|------------------|-------|
{{#LOGS_COLLECTED}}
| {{SOURCE}} | {{PATH}} | {{RETENTION}} | {{NOTES}} |
{{/LOGS_COLLECTED}}

### Evidence Storage

- **Primary evidence location:** {{EVIDENCE_LOCATION}}
- **Encryption:** {{EVIDENCE_ENCRYPTED}} (Y/N)
- **Access controls:** {{ACCESS_CONTROLS}}
- **Retention period:** {{RETENTION_PERIOD}}

---

## 5. Notification Decisions & Status

### Internal Notifications

| Stakeholder | Notified | Method | Timestamp | Notes |
|-------------|----------|--------|-----------|-------|
| Pharmacy Manager / CEO | {{MANAGER_NOTIFIED}} | {{MANAGER_METHOD}} | {{MANAGER_TIME}} | {{MANAGER_NOTES}} |
| Privacy Officer | {{PRIVACY_NOTIFIED}} | {{PRIVACY_METHOD}} | {{PRIVACY_TIME}} | {{PRIVACY_NOTES}} |
| IT / Security Team | {{IT_NOTIFIED}} | {{IT_METHOD}} | {{IT_TIME}} | {{IT_NOTES}} |
| Legal Counsel | {{LEGAL_NOTIFIED}} | {{LEGAL_METHOD}} | {{LEGAL_TIME}} | {{LEGAL_NOTES}} |
| Board of Directors | {{BOARD_NOTIFIED}} | {{BOARD_METHOD}} | {{BOARD_TIME}} | {{BOARD_NOTES}} |

### External Notifications (Regulatory / Law Enforcement)

| Agency | Notified | Method | Timestamp | Case / Reference # |
|--------|----------|--------|-----------|-------------------|
| FBI (IC3 or field office) | {{FBI_NOTIFIED}} | {{FBI_METHOD}} | {{FBI_TIME}} | {{FBI_CASE}} |
| CISA | {{CISA_NOTIFIED}} | {{CISA_METHOD}} | {{CISA_TIME}} | {{CISA_CASE}} |
| HHS OCR | {{OCR_NOTIFIED}} | {{OCR_METHOD}} | {{OCR_TIME}} | {{OCR_CASE}} |
| State Attorney General | {{AG_NOTIFIED}} | {{AG_METHOD}} | {{AG_TIME}} | {{AG_CASE}} |
| State Health Department | {{STATE_HEALTH_NOTIFIED}} | {{STATE_HEALTH_METHOD}} | {{STATE_HEALTH_TIME}} | {{STATE_HEALTH_CASE}} |
| Local Police (if required) | {{POLICE_NOTIFIED}} | {{POLICE_METHOD}} | {{POLICE_TIME}} | {{POLICE_CASE}} |

### Business Associate Notifications

| Business Associate | BAA Date | Notified | Timestamp | Response Received |
|--------------------|----------|----------|-----------|-------------------|
{{#BA_NOTIFICATIONS}}
| {{BA_NAME}} | {{BAA_DATE}} | {{NOTIFIED}} | {{TIMESTAMP}} | {{RESPONSE}} |
{{/BA_NOTIFICATIONS}}

---

## 6. Impact Assessment

### Operational Impact

- **Pharmacy operations:** {{OPERATIONS_STATUS}} (normal / degraded / suspended / offline)
- **Prescription dispensing:** {{DISPENSING_STATUS}}
- **Insurance billing:** {{BILLING_IMPACT}}
- **Patient appointments:** {{APPOINTMENTS_IMPACT}}
- **Estimated revenue impact:** {{REVENUE_IMPACT}}

### Data Impact

- **Records potentially affected:** {{AFFECTED_RECORD_COUNT}}
- **Types of PHI involved:** {{PHI_TYPES}}
- **Uniqueness of records:** {{UNIQUENESS}} (full records / partial / unknown)
- **Encryption status:** {{ENCRYPTION_STATUS}} (encrypted / unencrypted / mixed / unknown)
- **Exfiltration suspected:** {{EXFILTRATION_SUSPECTED}} (Y/N / investigating)
- **Leak site posting:** {{LEAK_SITE_POSTING}} (confirmed / not observed / unknown)

### Breach Determination (HIPAA 45 CFR § 164.402)

- **Unsecured PHI:** {{UNSECURED_PHI}} (Y/N — if N, notification may not be required)
- **Breach presumed:** {{BREACH_PRESUMED}} (Y/N — under the Breach Notification Rule)
- **Risk assessment completed:** {{RISK_ASSESSMENT_COMPLETED}} (Y/N / date)
- **Low probability of compromise:** {{LOW_PROBABILITY}} (Y/N — if Y, document factors)

---

## 7. Next Steps & Action Items

| Action Item | Owner | Due Date | Priority | Status |
|-------------|-------|----------|----------|--------|
{{#ACTION_ITEMS}}
| {{ACTION}} | {{OWNER}} | {{DUE_DATE}} | {{PRIORITY}} | {{STATUS}} |
{{/ACTION_ITEMS}}

### Recovery Priorities

1. {{RECOVERY_PRIORITY_1}}
2. {{RECOVERY_PRIORITY_2}}
3. {{RECOVERY_PRIORITY_3}}
4. {{RECOVERY_PRIORITY_4}}
5. {{RECOVERY_PRIORITY_5}}

### Communication Timeline

| Milestone | Target Date | Responsible Party | Status |
|-----------|-------------|-------------------|--------|
| Internal notification complete | {{INTERNAL_NOTIF_TARGET}} | {{INTERNAL_NOTIF_OWNER}} | {{INTERNAL_NOTIF_STATUS}} |
| Law enforcement briefing | {{LE_BRIEFING_TARGET}} | {{LE_BRIEFING_OWNER}} | {{LE_BRIEFING_STATUS}} |
| Business associate notifications sent | {{BA_NOTIF_TARGET}} | {{BA_NOTIF_OWNER}} | {{BA_NOTIF_STATUS}} |
| Individual notifications mailed | {{INDIVIDUAL_NOTIF_TARGET}} | {{INDIVIDUAL_NOTIF_OWNER}} | {{INDIVIDUAL_NOTIF_STATUS}} |
| HHS OCR notification | {{OCR_NOTIF_TARGET}} | {{OCR_NOTIF_OWNER}} | {{OCR_NOTIF_STATUS}} |
| Media release (if >500 affected) | {{MEDIA_TARGET}} | {{MEDIA_OWNER}} | {{MEDIA_STATUS}} |
| System restoration complete | {{RESTORATION_TARGET}} | {{RESTORATION_OWNER}} | {{RESTORATION_STATUS}} |
| Post-incident review scheduled | {{PIR_TARGET}} | {{PIR_OWNER}} | {{PIR_STATUS}} |

---

## 8. Timeline of Events

| Date/Time (Local) | Event | Source | Notes |
|-------------------|-------|--------|-------|
{{#EVENT_TIMELINE}}
| {{DATETIME}} | {{EVENT}} | {{SOURCE}} | {{NOTES}} |
{{/EVENT_TIMELINE}}

---

## 9. Lessons Learned & Post-Incident Notes

*(To be completed during/after post-incident review)*

- **What worked well:** {{LESSONS_POSITIVE}}
- **What could be improved:** {{LESSONS_NEGATIVE}}
- **Process gaps identified:** {{PROCESS_GAPS}}
- **Technical gaps identified:** {{TECHNICAL_GAPS}}
- **Training needs:** {{TRAINING_NEEDS}}
- **Recommended policy changes:** {{POLICY_CHANGES}}

---

## 10. Attachments

- [ ] Ransom note (screenshot / file)
- [ ] IOC list (hashes, domains, IPs)
- [ ] Network diagram (affected segment)
- [ ] Forensic report (preliminary)
- [ ] Legal assessment memo
- [ ] Risk assessment worksheet
- [ ] Communication log
- [ ] Chain of custody forms

---

**Ticket Closed Date:** {{CLOSED_DATETIME}}
**Closed By:** {{CLOSED_BY}}
**Closure Reason:** {{CLOSURE_REASON}}
**Post-Incident Review Scheduled:** {{PIR_SCHEDULED}} (Y/N — date: {{PIR_DATE}})

---

*This document is confidential and may contain attorney-client privileged information. Distribution should be limited to incident response team members, legal counsel, and authorized management personnel.*
