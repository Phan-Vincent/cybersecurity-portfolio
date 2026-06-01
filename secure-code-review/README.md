# Secure Code Review: LLM Data-Leakage Threat Model

> **Project:** Independent security review of an LLM-powered health analytics pipeline — the [Privacy-First LLM-Driven Bodybuilding Auditor](https://github.com/Phan-Vincent/Privacy-First-LLM-Driven-Bodybuilding-Auditor).  
> **Reviewer:** Vincent Phan — CVS Pharmacy Technician (CPhT), CSU San Bernardino BS IT (Cybersecurity), Fall 2026.  
> **Date:** June 2026

---

## One-Line Pitch

A hiring-manager-ready secure code review and threat model that audits a real Python/LLM pipeline for data-leakage, prompt injection, and OWASP Top 10 / OWASP LLM Top 10 violations — with concrete before/after vulnerability fixes.

---

## What This Project Demonstrates

This repository is a **standalone security review package**. It does not replace the original application; it analyzes it.

- **Threat modeling** (STRIDE) for an LLM-powered healthcare-adjacent pipeline handling synthetic nutrition/strength data.
- **Secure code review** methodology: static analysis, data-flow tracing, trust-boundary mapping.
- **OWASP Top 10 (2021)** and **OWASP Top 10 for LLM Applications (2025)** mapping with real code citations.
- **Before/after vulnerability demonstrations** — runnable Python files showing the bug and the fix.
- **Synthetic data only** — no real PHI, no real secrets, no real API keys.

**Skills demonstrated:**
- Threat modeling & risk assessment (STRIDE)
- OWASP Top 10 / OWASP LLM Top 10 applied knowledge
- Secure Python code review
- Prompt injection mitigation
- Secret management & least privilege
- Input validation & sanitization
- Output validation & schema enforcement
- Security test case authoring (pytest)
- Health-data privacy awareness (HIPAA/PHI mindset from pharmacy practice)

---

## How to Run

### Prerequisites

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Run the Review Tests

```bash
pytest tests/ -v
```

This runs:
- Vulnerability reproduction tests (prompt injection, path traversal, etc.)
- Mitigation verification tests (confirming the fixes actually work)
- Schema validation tests

### Run the Vulnerable vs. Mitigated Demo

```bash
# Vulnerable version (synthetic data only)
python vulnerable/demo_pipeline.py --nutrition data/synthetic_nutrition.csv --training data/synthetic_training.csv

# Mitigated version
python mitigated/demo_pipeline.py --nutrition data/synthetic_nutrition.csv --training data/synthetic_training.csv
```

*Note: The vulnerable demo runs **offline** — no real API keys are needed. The LLM call is mocked in tests.*

### Generate the Threat-Model Diagram

```bash
python scripts/generate_threat_model_diagram.py
# Opens threat_model_diagram.html in your browser
```

---

## Repository Layout

```
secure-code-review/
├── README.md                          ← This file
├── THREAT_MODEL.md                    ← Formal STRIDE threat model
├── OWASP_MAPPING.md                   ← OWASP Top 10 + OWASP LLM Top 10 mapping
├── findings/
│   ├── FINDING-01-prompt-injection.md
│   ├── FINDING-02-sensitive-data-disclosure.md
│   ├── FINDING-03-insecure-output-handling.md
│   ├── FINDING-04-input-validation.md
│   ├── FINDING-05-insufficient-logging.md
│   ├── FINDING-06-least-privilege.md
│   └── FINDING-07-cost-overrun.md
├── vulnerable/                        ← Before (intentionally buggy)
│   ├── demo_pipeline.py
│   ├── llm_audit.py
│   ├── ingestion.py
│   └── processing.py
├── mitigated/                         ← After (hardened)
│   ├── demo_pipeline.py
│   ├── llm_audit.py
│   ├── ingestion.py
│   └── processing.py
├── tests/
│   ├── test_prompt_injection.py
│   ├── test_input_validation.py
│   ├── test_output_validation.py
│   ├── test_secrets.py
│   ├── test_permissions.py
│   └── test_cost_guards.py
├── data/
│   ├── synthetic_nutrition.csv
│   └── synthetic_training.csv
├── scripts/
│   └── generate_threat_model_diagram.py
└── requirements.txt
```

---

## Threat Model at a Glance

| Threat | Risk | Severity | Mitigation Status |
|--------|------|----------|-------------------|
| Prompt injection via user-controlled CSV fields | High | **Critical** | Mitigated (input validation + prompt hardening) |
| PHI/health data disclosure to LLM provider | Medium | **High** | Mitigated (data minimization + synthetic-only demo) |
| Schema validation bypass (LLM output) | Medium | **High** | Mitigated (strict `additionalProperties: false` + reject) |
| Path traversal / arbitrary file read | Medium | **High** | Mitigated (chroot + suffix whitelist) |
| Sensitive data in log files | Low | **Medium** | Mitigated (sanitized logging + `0o600` permissions) |
| API key exposure via `.env` | Medium | **High** | Mitigated (key validation + permission checks) |
| Token cost overrun (post-hoc budget) | Low | **Medium** | Mitigated (pre-flight estimation + `max_tokens`) |

Full threat model: [`THREAT_MODEL.md`](THREAT_MODEL.md)

---

## Honest Scope Notes

- **This is a student project.** I reviewed my own code. A production SOC review would involve a team, external tools (Semgrep, Bandit, CodeQL), and a formal SDLC.
- **No live LLM calls** in the test suite — everything is mocked to keep costs at $0 and prevent accidental data leakage.
- **Synthetic data only** — the CSV files contain entirely fabricated nutrition and training records. No real user data.
- **I do not hold CISSP, CEH, or OSCP** (yet). The value here is applied learning, methodology, and honest documentation — not credential inflation.
- **The original application** is a real public repo on my GitHub. This review references specific commit hashes and file paths from that codebase.

---

## License

MIT — feel free to use this as a template for your own portfolio reviews.
