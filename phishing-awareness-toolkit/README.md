# Phishing Simulation & Awareness Toolkit

> **AUTHORIZED SECURITY TRAINING USE ONLY**  
> This toolkit is designed for **authorized internal security awareness training** with explicit participant consent. It does not and cannot send emails to real users without an organization's security team operating it. All examples use **synthetic, fictional data** — no real patient health information (PHI), credentials, or personally identifiable information (PII) are included.

---

## Overview

Phishing remains the #1 initial access vector in breaches ([Verizon DBIR, 2024](https://www.verizon.com/business/resources/reports/dbir/)). Organizations lose billions annually to credential theft, business email compromise (BEC), and malware delivery via deceptive emails. Yet awareness training is often reactive, boring, or absent — leaving employees as the weakest link.

This toolkit demonstrates how a security-conscious developer can:
- **Build** a lightweight phishing email classifier using heuristic analysis
- **Generate** realistic (but fully synthetic) phishing scenarios for authorized training exercises
- **Educate** end users with practical, non-patronizing guidance
- **Think adversarially** — modeling threats the tool addresses *and* the threats it could create if misused

It is a **student portfolio project** by Vincent Phan, built to bridge a healthcare operations background into cybersecurity. It reflects entry-level SOC-analyst thinking: observational heuristics, structured analysis, and clear documentation.

---

## What This Project Demonstrates

| Capability | Evidence |
|-----------|----------|
| **Security-minded development** | Threat model, misuse mitigations, and ethical-use guardrails baked in from day one |
| **Heuristic analysis** | A rule-based phishing classifier scoring emails across URL, header, content, and urgency dimensions |
| **Adversarial thinking** | Synthetic templates designed to mimic real attack patterns (BEC, credential harvesting, invoice fraud) |
| **Technical communication** | End-user awareness guide written for non-technical audiences |
| **Software engineering** | Modular Python, unit tests, CLI interface, clear project structure |
| **Ethical grounding** | Explicit consent model, synthetic data only, misuse threat modeling |

---

## Quick Start

### Requirements
- Python 3.10+
- `pyyaml` (YAML config parsing)
- `pytest` for tests

```bash
pip install -r requirements.txt
```

### Run the Analyzer
```bash
# Analyze a single email file (human-readable output)
python phishing_analyzer.py data/sample_emails/sample_01_obvious_phish.eml

# JSON output for automation / SIEM ingestion
python phishing_analyzer.py data/sample_emails/sample_01_obvious_phish.eml --json

# Score only (useful for shell scripts / CI)
python phishing_analyzer.py data/sample_emails/sample_01_obvious_phish.eml --score-only

# Custom heuristic configuration
python phishing_analyzer.py email.eml --config config/heuristics.yaml

# Print the full indicator catalogue
python phishing_analyzer.py --list-indicators
```

### Run Tests
```bash
pytest tests/ -v
```

### Analyze Programmatically
```python
from phishing_analyzer import PhishingAnalyzer

analyzer = PhishingAnalyzer(config_path="config/heuristics.yaml")
result = analyzer.analyze_file("email.eml")
print(f"Score: {result.composite_score}/100  Risk: {result.risk_level}")
```

---

## How the Analyzer Works

The classifier uses **layered heuristic scoring** — no ML model, no external API calls, no data exfiltration. This is intentional: a SOC analyst at a constrained organization may need tooling that runs fully offline, is auditable, and has no supply-chain risk.

### Analysis Categories

| Category | Max Score | What It Checks |
|----------|-----------|----------------|
| **Headers** | 25 pts | SPF/DKIM/DMARC hints, sender spoofing, Reply-To/Return-Path mismatches, routing anomalies, HTML-only multipart |
| **URLs** | 40 pts | IP-based URLs, URL shorteners, suspicious TLDs, HTTP (not HTTPS), homoglyphs, lookalike domains, deep subdomains, `@` trick, data URIs |
| **Urgency Language** | 35 pts | Predefined fear/urgency regex patterns, fear-word density, ALL-CAPS shouting, excessive punctuation |

### Composite Scoring

Each category score is normalised against its ceiling, summed, and boosted when multiple categories fire simultaneously (attackers typically layer techniques). The final score is mapped to:

| Score | Risk Level | Guidance |
|-------|-----------|----------|
| 0–19 | VERY_LOW | Likely legitimate |
| 20–34 | LOW | Minimal concern |
| 35–69 | MEDIUM | Suspicious — review recommended |
| 70–84 | HIGH | Likely phishing — do not interact |
| 85–100 | CRITICAL | High-confidence phishing — quarantine |

All weights, thresholds, and pattern scores are configurable via `config/heuristics.yaml`. See [`docs/security-rationale.md`](docs/security-rationale.md) for design decisions and known limitations.

---

## Project Structure

```
phishing-awareness-toolkit/
├── README.md                          ← You are here
├── phishing_analyzer.py               ← Main CLI + analysis engine (~800 LOC, production-quality Python)
├── config/
│   └── heuristics.yaml                ← Configurable rules, weights, and thresholds
├── tests/
│   ├── conftest.py                    ← Path setup for imports
│   ├── test_analyzer.py               ← 44 pytest unit + integration tests
│   └── test_sample_fixtures.py        ← Regression tests over the 8 .eml fixtures
├── data/
│   └── sample_emails/                 ← 8 synthetic .eml fixtures
│       ├── sample_01_obvious_phish.eml
│       ├── sample_02_healthcare_hipaa_breach.eml
│       ├── sample_03_cvs_pharmacy_refill.eml
│       ├── sample_04_paypal_lookalike.eml
│       ├── sample_05_azure_ad_login.eml
│       ├── sample_06_shipping_notification.eml
│       ├── sample_07_legitimate_newsletter.eml
│       └── sample_08_internal_memo.eml
├── requirements.txt                   ← Runtime + dev dependencies
├── guide/
│   └── awareness-guide.md             ← End-user guide: how to spot phishing
└── docs/
    ├── threat-model.md                ← Threats addressed + misuse risks
    └── security-rationale.md          ← Design decisions, limitations, false-positive analysis
```

---

## Threat Model & Security Rationale

This toolkit was built with **security-first thinking** — not as an afterthought.

- **Threats it addresses**: Credential harvesting, BEC, invoice fraud, malware delivery via email. See [`docs/threat-model.md`](docs/threat-model.md) for the full attack surface.
- **Threats it could create if misused**: Anyone with this code could craft convincing phishing emails. We mitigate this with:
  - Explicit consent requirement in every training scenario
  - Synthetic data only — no real PHI, PII, or credentials
  - No outbound email-sending capability built in
  - Clear documentation that this is for **authorized internal training only**
- **Trust boundaries**: The analyzer runs entirely locally. No network calls. No data leaves the machine.

Read the full threat model: [`docs/threat-model.md`](docs/threat-model.md)

Read the security rationale: [`docs/security-rationale.md`](docs/security-rationale.md)

---

## Skills Demonstrated

| Skill | How This Project Shows It |
|-------|---------------------------|
| **Threat Analysis** | Full threat model documenting both defensive and offensive risks |
| **Secure Design** | Offline-only operation, no external dependencies, explicit misuse mitigations |
| **Python Development** | Clean modular architecture, type hints, CLI interface, test coverage |
| **Technical Writing** | Awareness guide written for non-technical end users; clear docs for technical audiences |
| **Adversarial Thinking** | Templates mimic real attacker TTPs; scoring designed to catch subtle deception |
| **Ethical Judgment** | Consent model, synthetic data policy, and misuse threat modeling baked into design |
| **SOC Analyst Mindset** | Heuristic-based detection, structured scoring, alert triage thresholds, false-positive awareness |

---

## Honest Scope Notes

This is a **student portfolio project**. Here is what is real and what is aspirational:

### What is real (working today)
- ✅ `phishing_analyzer.py` — heuristic email analyzer with multi-dimensional scoring
- ✅ `config/heuristics.yaml` — fully configurable rule engine
- ✅ 8 synthetic `.eml` email fixtures covering obvious phish, subtle phish, and legitimate baselines
- ✅ 56 pytest unit, integration, and fixture-regression tests
- ✅ Complete documentation: threat model, security rationale, user guide
- ✅ CLI tool with JSON/text/score-only output modes, runs offline with zero network calls

### What is aspirational (future roadmap)
- 🔄 Integration with real mail APIs (Graph, Gmail) for *authorized* phishing simulations in enterprise environments
- 🔄 Machine learning model trained on public phishing datasets (e.g., Enron + OpenPhish) for higher accuracy
- 🔄 Dashboard for tracking employee click rates in training campaigns
- 🔄 Integration with SIEM alerting for live email stream analysis
- 🔄 YARA-style rule engine for attachment analysis

### Why heuristics and not ML?
A heuristic model is **fully auditable** — a SOC analyst can read the rules and understand *why* an email was flagged. An ML model is a black box. For a portfolio project, this also means it runs without model weights, GPU access, or API keys. The trade-off is lower accuracy on novel attacks; see [`docs/security-rationale.md`](docs/security-rationale.md) for the full analysis.

---

## Ethical Use Disclaimer

> **By using this toolkit, you agree to the following:**

1. **Authorized Use Only**: This toolkit is for **authorized internal security awareness training** within an organization that has explicitly consented to phishing simulation exercises.

2. **No Real Data**: All training scenarios use **synthetic, fictional data**. Never use real patient information, real credentials, real financial data, or any actual PII/PHI in training exercises.

3. **No Unauthorized Sending**: This toolkit does not send emails. If you build email-sending functionality on top of it, you must:
   - Obtain explicit written consent from all recipients
   - Work within your organization's security team
   - Comply with all applicable laws and regulations

4. **No Harm**: Phishing simulations should never cause distress, financial loss, or reputational damage. Debrief participants after exercises.

5. **Transparency**: If you are a student or job seeker showcasing this project, be clear that the phishing templates are **synthetic training materials** — not real attacks you performed.

**Misuse of phishing tools is illegal in many jurisdictions. Use this toolkit responsibly and ethically.**

---

## About the Author

**Vincent Phan** — Pharmacy Technician (CPhT) transitioning into cybersecurity.  
Currently: CVS Pharmacy (2020–present), handling PHI/HIPAA-regulated data daily.  
Incoming: CSU San Bernardino, BS Information Systems — Cybersecurity concentration (Fall 2026).

This project bridges healthcare compliance experience with security operations thinking. The same attention to data privacy, access controls, and audit trails that protects patient information also protects organizations from phishing.

- GitHub: [github.com/Phan-Vincent](https://github.com/Phan-Vincent)
- LinkedIn: *(add when ready)*

---

## License

MIT License — see `LICENSE` file.  
*Note: The license covers the code. The ethical-use disclaimer above is a condition of use, not a legal restriction. Please use this tool responsibly.*
