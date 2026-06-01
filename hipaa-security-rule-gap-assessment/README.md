# HIPAA Security Rule Gap Assessment Toolkit

> A GRC portfolio project by Vincent Phan, CPhT — pharmacy technician turned cybersecurity student.

## Problem Statement

Small-to-mid-size healthcare entities (pharmacies, clinics, private practices) struggle to operationalize HIPAA Security Rule compliance. Regulatory text is dense, gap assessments are expensive, and remediation roadmaps often lack technical rigor. This toolkit bridges that gap with a structured, repeatable, and automatable approach.

## What It Demonstrates

- **Governance, Risk & Compliance (GRC)** — mapping regulatory controls to operational practice
- **Risk Quantification** — scoring gaps by likelihood and impact, not just checkboxes
- **Healthcare Domain Knowledge** — grounded in pharmacy/PHI handling (CPhT background, CVS experience)
- **Automation** — Python-driven ingestion, scoring, and report generation
- **Security Rationale** — threat-modeling the assessment process itself

## Repository Structure

```
hipaa-security-rule-gap-assessment/
├── README.md                          # This file
├── data/
│   ├── controls.json                    # Control framework catalog (JSON)
│   ├── hipaa-controls.json              # HIPAA Security Rule controls reference
│   └── sample_pharmacy_assessment.csv   # Synthetic filled assessment for demo
├── scripts/
│   └── generate_checklist.py            # Generates empty assessment checklist from controls catalog
├── output/
│   └── (generated artifacts — not committed)
└── docs/
    ├── threat-model.md                   # Security rationale for the toolkit itself
    └── hipaa-safeguards-reference.md     # CFR cross-reference guide
```

## Quick Start

```bash
# 1. Review the control framework
less controls/hipaa_security_controls.json

# 2. Generate an empty assessment checklist
python scripts/generate_checklist.py \
    --output output/my_assessment.csv \
    --controls controls/hipaa_security_controls.json

# 3. Open the CSV and fill in assessment_status, evidence_description,
#    finding_notes, remediation_owner, and target_date for each control.
```

## Control Framework

The toolkit covers all three safeguard categories from 45 CFR Part 164 Subpart C:

| Category | CFR Section | Controls |
|----------|-------------|----------|
| **Administrative** | 164.308 | Security Management, Workforce Security, Access Management, Training, Incident Response, Contingency Planning, Evaluation, Business Associates |
| **Physical** | 164.310 | Facility Access, Workstation Use/Security, Device & Media Controls |
| **Technical** | 164.312 | Access Control, Audit Controls, Integrity, Authentication, Transmission Security |

Each control is tagged with:
- **Standard** (Required vs Addressable per CFR)
- **Implementation Level** (1-5 maturity scale)
- **PHI Exposure** (High/Medium/Low — how much PHI this control protects)
- **Regulatory Reference** (exact CFR subsection)

## Risk Scoring Methodology

Gap severity is computed as:

```
Risk Score = Likelihood (1-5) × Impact (1-5) × PHI Exposure Multiplier

PHI Exposure Multiplier:
  High    = 1.5
  Medium  = 1.25
  Low     = 1.0

Severity Bands:
  Critical  = ≥ 30
  High      = 20-29
  Medium    = 10-19
  Low       = < 10
```

**Why this model:** In pharmacy operations, a missing workstation lock (Physical) may seem minor, but a single unlocked terminal in the dispensing area exposes hundreds of patient records. The PHI Exposure multiplier ensures controls protecting large datasets score higher — aligning with breach notification thresholds and OCR enforcement patterns.

## Skills Demonstrated

- Regulatory analysis and control mapping (HIPAA → operational controls)
- Risk quantification with domain-specific weighting
- Python automation (CSV ingestion, JSON processing, Markdown generation)
- Synthetic data handling (never real PHI — see threat model)
- Security-by-design tooling (input validation, least privilege, audit logging)

## Honest Scope Notes

This is a **student portfolio project**, not a production GRC platform. What's real:
- The control framework maps to actual 45 CFR text (researched from HHS sources)
- The risk scoring is defensible for a student-tier project
- The code is runnable and tested

What's simplified:
- No multi-user RBAC (single assessor model)
- Cost estimates in remediation are rough order-of-magnitude
- No integration with real ticketing systems (static markdown output)
- Evidence collection is manual (CSV upload) rather than API-driven

**What a hiring manager should see:** Someone who understands both healthcare operations *and* security engineering enough to build repeatable compliance tooling from first principles.

## License

MIT — synthetic data only, no real PHI. See `data/sample-assessment.csv` for data format; never populate with production data.

---

*Built by Vincent Phan | CPhT | CSU San Bernardino, BS Information Systems — Cybersecurity (Fall 2026)*
