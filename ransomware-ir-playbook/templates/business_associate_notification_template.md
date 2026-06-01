# Business Associate Notification Letter

**Template for Notifying Business Associates under 45 CFR § 164.504(e)**

> **SYNTHETIC TEMPLATE** — This is a student-created template for a cybersecurity portfolio project. It is not legal advice and should be reviewed by qualified counsel before use in a real incident.

---

**Date:** {{NOTIFICATION_DATE}}

**To:** {{BA_ORGANIZATION_NAME}}
**Attn:** Privacy Officer / Security Officer / Legal Counsel
**Address:** {{BA_ADDRESS}}

**Re:** Security Incident Notification — {{PHARMACY_NAME}} | Reference: {{INCIDENT_REFERENCE_NUMBER}}

---

Dear {{BA_CONTACT_NAME}},

We are writing to notify you of a security incident at {{PHARMACY_NAME}} that may affect protected health information (PHI) disclosed to your organization under our Business Associate Agreement (BAA) dated {{BAA_DATE}}.

This notification is provided in accordance with 45 CFR § 164.504(e), which requires covered entities to notify business associates of any breach of unsecured protected health information, and under the reciprocal notification obligations set forth in our BAA.

### Incident Summary

On {{INCIDENT_DISCOVERY_DATE}}, {{PHARMACY_NAME}} discovered unauthorized access to certain systems containing PHI. Our forensic investigation indicates that the incident occurred between {{INCIDENT_START_DATE}} and {{INCIDENT_END_DATE}}.

The unauthorized party gained access through {{BRIEF_ATTACK_VECTOR}} (e.g., phishing email, exploited vulnerability, compromised credentials).

### PHI Potentially Affected

Based on our investigation, the following categories of PHI that were disclosed to your organization under our BAA may have been accessed or acquired:

{{#AFFECTED_PHI_CATEGORIES}}
- {{CATEGORY}} — {{DESCRIPTION}}
{{/AFFECTED_PHI_CATEGORIES}}

**Approximate volume:** {{AFFECTED_RECORDS_COUNT}} records
**Data elements involved:** {{DATA_ELEMENTS}}

### Your Obligations Under the BAA

Under Section {{BAA_SECTION_NUMBER}} of our Business Associate Agreement, we request the following:

1. **Confirm your own incident response status.** Please confirm whether your systems, networks, or workforce members were involved in, affected by, or had access to the compromised data during the incident window.

2. **Notify us of any breach at your end.** If you determine that this incident constitutes a breach of unsecured PHI under 45 CFR § 164.402 at your organization, please notify us within {{NOTIFICATION_TIMEFRAME}} as required by our BAA and applicable HIPAA regulations.

3. **Provide a summary of containment actions.** Please describe any steps your organization has taken or plans to take to contain the incident, secure any PHI in your possession related to {{PHARMACY_NAME}} patients, and prevent recurrence.

4. **Confirm continued safeguard compliance.** Please confirm that your organization continues to implement and maintain the administrative, physical, and technical safeguards required by 45 CFR § 164.308, § 164.310, and § 164.312 with respect to PHI received from {{PHARMACY_NAME}}.

### Timeline for Mutual Notification

To ensure compliance with the 60-day breach notification requirement under 45 CFR § 164.408(c), we request your response and any reciprocal notification no later than {{RESPONSE_DEADLINE}}.

Our own individual notification process is scheduled to begin on {{INDIVIDUAL_NOTIFICATION_START_DATE}}. If your investigation determines that additional individuals should be notified, we will coordinate with you to ensure timely and accurate notification.

### Evidence Preservation

Both parties agree to preserve all logs, records, and evidence related to this incident in accordance with our BAA and applicable legal hold obligations. Please confirm that your organization has suspended automatic log deletion and has preserved all relevant system logs, access records, and backup media for the period {{INCIDENT_START_DATE}} through {{INCIDENT_END_DATE}} plus 30 days.

### Contact Information

For questions or to provide your response, please contact:

**{{PHARMACY_NAME}} Incident Response Team**
{{IR_TEAM_LEAD_NAME}} — {{IR_TEAM_LEAD_TITLE}}
Phone: {{IR_PHONE}}
Email: {{IR_EMAIL}}
Secure Fax: {{IR_FAX}}

**{{PHARMACY_NAME}} Privacy Officer**
{{PRIVACY_OFFICER_NAME}}
Phone: {{PRIVACY_OFFICER_PHONE}}
Email: {{PRIVACY_OFFICER_EMAIL}}

### Confidentiality

This notice and all related communications are confidential and may be subject to attorney-client privilege, work product protections, or other applicable legal privileges. Please do not disclose the contents of this notice to third parties without prior written consent, except as required by law.

We appreciate your partnership in responding to this incident and maintaining the trust of our patients.

Sincerely,

{{PHARMACY_MANAGER_NAME}}
{{PHARMACY_MANAGER_TITLE}}
{{PHARMACY_NAME}}

---

**cc:** {{PHARMACY_LEGAL_COUNSEL}}
**cc:** {{PRIVACY_OFFICER_NAME}}
**cc:** {{SECURITY_OFFICER_NAME}}
