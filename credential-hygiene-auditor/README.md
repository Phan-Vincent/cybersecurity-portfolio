# Credential Hygiene & Password Policy Auditor

A Python CLI tool that audits password/credential hygiene against NIST SP 800-63B guidelines, with offline breach detection and cross-service reuse analysis. Built as a student portfolio project with a focus on healthcare cybersecurity awareness (HIPAA §164.312 access controls) and privacy-first design.

## Overview

Weak and reused credentials remain the #1 initial access vector in data breaches (Verizon DBIR). In healthcare settings, where PHI exposure carries severe regulatory and patient-safety consequences, credential hygiene is not optional — it is foundational. This tool demonstrates a privacy-preserving approach to credential auditing using **synthetic data only**, with no network dependency for the core breach checks.

### What It Demonstrates

- **NIST SP 800-63B alignment**: Modern password policy (length > complexity, no arbitrary rotation)
- **k-anonymity API design**: Understanding of HIBP's prefix-range protocol for safe breach checking
- **Risk scoring**: Quantified credential posture (0-100 scale)
- **Synthetic data ethics**: All bundled credentials are fake; no real passwords in repo
- **CLI design**: argparse, colorized output, multiple report formats
- **Python fundamentals**: Type hints, docstrings, stdlib-only (except pytest)

### Background Context

This project is grounded in the author's background as a **CVS CPhT** (healthcare/PHI exposure), **CSUSB cybersecurity transfer student**, and **OpenClaw home lab operator**. The author also maintains the "Privacy-First LLM-Driven Bodybuilding Auditor" project, demonstrating a consistent interest in privacy-preserving tooling.

## Problem Statement

Healthcare organizations, pharmacies, and individuals routinely face:
- Password reuse across critical systems (email, banking, health portals)
- Use of known weak passwords from breach databases
- Compliance pressure (HIPAA §164.312(a)(2)(i): unique user identification)
- Fear of sending credentials to third-party APIs for checking

This tool addresses these concerns by bundling an offline weak-hash database and explaining how k-anonymity APIs work without exposing real credentials.

## Architecture

```
├── main.py                      # CLI entry point (argparse, colorized output)
├── auditor.py                   # Core engine: orchestrates policy + breach + reuse
├── policy.py                    # NIST 800-63B password evaluator
├── breach.py                    # Offline weak-hash check + HIBP k-anonymity mock
├── report.py                    # Markdown + JSON report generator
├── data/
│   └── known_weak_hashes.txt    # ~100 synthetic SHA-1 hashes (offline demo)
│   └── sample_credentials.json  # 10 synthetic records (NO REAL DATA)
└── tests/
    └── test_auditor.py          # pytest suite (policy, breach, reuse, report)
```

## How to Run

```bash
# Install test dependency
pip install -r requirements.txt

# Run the built-in demo (uses synthetic sample data)
python main.py --demo

# Audit your own synthetic credentials file
python main.py --input data/sample_credentials.json --output report.md --format md

# Output JSON instead
python main.py --input data/sample_credentials.json --output report.json --format json

# Run tests
pytest tests/test_auditor.py -v
```

## Module Contracts

### `policy.evaluate_password(password)` → dict
- Returns NIST 800-63B assessment: length, character variety, entropy, compliance, score (0-4), feedback
- Does NOT require rotation (NIST says don't force arbitrary rotation)
- Does NOT require special characters (NIST says allow any Unicode)
- Focuses on length + memorability + entropy

### `breach.check_weak_password(password, weak_hashes)` → dict
- SHA-1 hash of password vs bundled weak hash set
- Offline: no network request, no credential leakage
- Returns breached (bool), reason (str), hash_prefix (str)

### `breach.check_hibp_mock(password)` → dict
- Simulates HIBP k-anonymity API
- Explains real-world usage: prefix + range query prevents full hash exposure
- Returns simulated_breach_count (int), checked (bool), note (str)

### `auditor.audit_credentials(credentials, weak_hashes)` → dict
- Each credential: `{username, password, service, last_changed}`
- Runs policy + breach + reuse detection + age analysis
- Returns overall_risk_score (0-100), per-credential findings, reuse table, NIST compliance summary

### `report.generate_markdown_report(result)` / `generate_json_report(result)` → str
- Markdown: human-readable with tables, emoji indicators, risk descriptions
- JSON: machine-parseable for downstream automation
- Both include overall_risk_score, per-credential findings, reuse table, NIST compliance summary

## Threat Model & Security Rationale

### Why bundled weak hashes?
The `known_weak_hashes.txt` file contains ~106 SHA-1 hashes of common synthetic passwords. This enables **offline** breach checking — no network request is made, so no credentials leave the machine. This is ideal for:
- Air-gapped environments
- Healthcare systems with strict data-loss-prevention policies
- Demonstrating breach detection without API keys or rate limits

### Why SHA-1?
SHA-1 is used here for **HIBP API compatibility** demonstration only. The real HIBP API uses SHA-1. This tool does NOT use SHA-1 for password storage — it is only used for the offline comparison and the k-anonymity mock.

For production password storage, use **bcrypt, Argon2, or PBKDF2**.

### Why no real passwords in the repo?
All credentials in `data/sample_credentials.json` are synthetic. The repo contains no real usernames, no real passwords, and no real service mappings. This is a deliberate ethical choice: credential auditing tools should never be a vector for credential exposure.

### k-anonymity explanation
The HIBP k-anonymity protocol works by:
1. Client SHA-1 hashes the password locally
2. Client sends only the first 5 hex characters (prefix) to the API
3. Server returns all suffixes (remaining 35 hex chars) that match the prefix, with breach counts
4. Client checks locally if the full hash suffix is in the response

**Result:** The full hash is never transmitted. Even if the API endpoint is compromised or logging requests, the server cannot reconstruct the password from the prefix alone.

## Skills Demonstrated

| Skill | Evidence |
|-------|----------|
| Python | Type hints, docstrings (Google style), stdlib usage |
| CLI design | argparse, colorized terminal output, `--demo` flag |
| Cryptography basics | SHA-1 hashing, entropy estimation, k-anonymity concept |
| Compliance awareness | NIST 800-63B alignment, HIPAA §164.312 reference |
| Risk scoring | Weighted 0-100 risk model with multi-factor inputs |
| Synthetic data ethics | No real credentials, explicit banner, synthetic-only dataset |
| Testing | pytest suite with edge cases, parametrized reuse detection |
| Security communication | Threat model, honest scope notes, production guidance |

## Honest Scope Notes

This is a **student/entry-level portfolio project**. It demonstrates understanding of:
- Password policy evaluation
- Offline hash comparison
- k-anonymity API design (mocked)
- Risk quantification
- Privacy-first tooling

It is **not** production-grade software. For production use, you would need:
- Real HIBP API integration with rate-limit handling
- Integration with Active Directory / LDAP / identity provider APIs
- Audit logging and SIEM integration
- Argon2-based password hashing for any stored credentials
- Multi-factor authentication (MFA) status checks
- More sophisticated entropy models (e.g., zxcvbn algorithm)

## License

MIT License — see LICENSE file (if present). This project is for educational and portfolio purposes.
