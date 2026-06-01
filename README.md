# Vincent Phan — Cybersecurity Portfolio

**Certified Pharmacy Technician (CPhT) with four years of HIPAA-regulated PHI handling experience, now transferring to CSU San Bernardino for a BS in Information Systems — Cybersecurity concentration.** This portfolio bridges healthcare operations and defensive security: every project is grounded in real patient-data sensitivity, built with synthetic-data ethics, and documented with the kind of risk-aware judgment that SOC teams need on Day 1.

---

## Projects

### Detection & Monitoring

| Project | Pitch |
|---------|-------|
| [auth-log-analyzer](./auth-log-analyzer/) | A SIEM-lite log analyzer that turns raw Linux auth logs into actionable, MITRE-mapped security alerts. |
| [nmap-vuln-scanner-wrapper](./nmap-vuln-scanner-wrapper/) | An ethics-first nmap wrapper that parses reconnaissance into structured, prioritized vulnerability intelligence with a `--demo` mode for safe evaluation. |
| [threat-intel-ioc-extractor](./threat-intel-ioc-extractor/) | A threat-intel pipeline that extracts and validates IOCs from unstructured feeds into STIX-lite bundles and SOC-ready daily briefs. |
| [phishing-awareness-toolkit](./phishing-awareness-toolkit/) | An offline heuristic email analyzer that scores phishing risk across headers, URLs, and urgency language for triage and awareness training. |

### Hardening & Architecture

| Project | Pitch |
|---------|-------|
| [clinic-network-segmentation](./clinic-network-segmentation/) | A defense-in-depth network design for a small clinic using VLAN segmentation, firewall rule engineering, and HIPAA Security Rule mapping. |
| [linux-hardening-toolkit](./linux-hardening-toolkit/) | A CIS-aligned Bash toolkit that audits or hardens Ubuntu servers against 30+ controls with scored markdown reports and ePHI-aware checks. |
| [openclaw-home-lab](./openclaw-home-lab/) | A documented macOS security lab demonstrating SOC analyst competencies through real automation, logging, hardening, and incident response. |

### Cloud & AppSec

| Project | Pitch |
|---------|-------|
| [aws-iam-least-privilege-audit](./aws-iam-least-privilege-audit/) | A boto3 IAM scanner that flags wildcard permissions, stale keys, missing MFA, and over-permissioned roles with severity-scored remediation guidance. |
| [secure-code-review](./secure-code-review/) | A standalone security review and STRIDE threat model of an LLM-powered health pipeline, with before/after vulnerability fixes mapped to OWASP Top 10 and OWASP LLM Top 10. |

### GRC & Incident Response

| Project | Pitch |
|---------|-------|
| [hipaa-security-rule-gap-assessment](./hipaa-security-rule-gap-assessment/) | A GRC toolkit that ingests synthetic assessment data, scores HIPAA Security Rule gaps by PHI exposure, and generates prioritized remediation roadmaps. |
| [ransomware-ir-playbook](./ransomware-ir-playbook/) | A healthcare-specific NIST SP 800-61 incident response playbook for independent pharmacies, with tabletop exercises, triage scripts, and HIPAA breach notification calculators. |
| [credential-hygiene-auditor](./credential-hygiene-auditor/) | A privacy-preserving password auditor that evaluates credential hygiene against NIST 800-63B, detects reuse, and simulates HIBP k-anonymity breach checks offline. |

---

## Skills Demonstrated

| Project | SIEM | IR | Cloud Security | GRC / HIPAA | Scripting | Threat Intel | AppSec / LLM |
|---------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **auth-log-analyzer** | ✅ Log analysis, alert lifecycle | | | | Python | MITRE mapping | |
| **nmap-vuln-scanner-wrapper** | | | | | Python | | |
| **threat-intel-ioc-extractor** | | | | | Python | ✅ IOC lifecycle, STIX | |
| **phishing-awareness-toolkit** | ✅ Heuristic detection, scoring | | | | Python | | |
| **clinic-network-segmentation** | | | | ✅ Safeguard crosswalk | | | |
| **linux-hardening-toolkit** | | | | ✅ CIS, ePHI | Bash | | |
| **openclaw-home-lab** | ✅ Monitoring, log analysis | ✅ Prompt-injection IR | | ✅ PHI handling | Python / Bash | | |
| **aws-iam-least-privilege-audit** | | | ✅ IAM, PoLP | ✅ Cloud PHI | Python | | |
| **secure-code-review** | | | | ✅ PHI mindset | Python | | ✅ OWASP Top 10, LLM Top 10 |
| **hipaa-security-rule-gap-assessment** | | | | ✅ Full gap assessment | Python | | |
| **ransomware-ir-playbook** | | ✅ NIST 800-61 | | ✅ Breach notification | Python / Bash | ✅ IOC hunting | |
| **credential-hygiene-auditor** | | | | ✅ Access controls | Python | | |

---

*All data is synthetic and all projects are student work — built to demonstrate real security competencies, not production deployments.*
