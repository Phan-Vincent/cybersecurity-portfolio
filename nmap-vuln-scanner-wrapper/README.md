# nmap-vuln-scanner-wrapper

A Python security toolkit that wraps `nmap` for authorized network reconnaissance, parses XML scan output into structured vulnerability findings, and cross-references exposed services against a curated CVE-prone version database. Built as a **student portfolio project** demonstrating real-world security tooling, ethical scope enforcement, and defensive operations thinking.

> **⚠️ Authorized Use Only.** This tool is designed for **authorized penetration testing, home lab hardening, and educational SOC analyst workflows**. Always obtain written scope-of-engagement authorization before scanning any network you do not own.

---

## One-Line Pitch

A disciplined, ethics-first network reconnaissance wrapper that turns raw nmap XML into actionable, prioritized vulnerability intelligence — with a `--demo` mode so hiring managers can run it immediately without touching any real network.

---

## Problem It Solves

Entry-level SOC analysts and security students often run `nmap` scans but struggle to:
1. **Parse XML consistently** into structured data pipelines
2. **Prioritize findings** by real risk (not just "port 80 is open")
3. **Document scope and authorization** for audit trails
4. **Cross-reference versions** against known CVEs without manual lookup

This wrapper automates the pipeline from **scan → parse → score → report**, with guardrails that force ethical documentation and synthetic data for safe demonstration.

---

## What It Demonstrates

| Skill | Evidence |
|-------|----------|
| **Network Security Fundamentals** | nmap integration, port/service enumeration, banner grabbing |
| **Defensive Operations Mindset** | Risk scoring, prioritization, structured reporting for SOC triage |
| **Python Engineering** | CLI design (`argparse`), XML parsing, modular architecture, type hints |
| **Security Ethics & Compliance** | Mandatory `--scope` flag, synthetic demo mode, HIPAA-aware design (see Threat Model) |
| **Version Intelligence** | Curated CVE-prone service database with severity scoring |
| **Documentation Quality** | Threat model, honest scope notes, runnable README |

---

## How to Run

### Prerequisites
- Python 3.10+
- `nmap` installed (`brew install nmap` on macOS, `sudo apt install nmap` on Linux)
- Install Python dependencies: `pip install -r requirements.txt`

### Demo Mode (No Real Scan Required)
```bash
python3 scanner.py --demo --scope "Portfolio Demo — Synthetic Data Only"
```
This runs the full pipeline against bundled sample `nmap` XML in `demo_data/`, generating a complete vulnerability report without touching any network.

### Real Scan Mode (Authorized Networks Only)
```bash
# Basic scan against authorized target with full reporting
python3 scanner.py --target 192.168.1.0/24 --scope "CSUSB Lab Network — Authorized 2026-06-01"

# Scan with aggressive service detection and report output
python3 scanner.py --target 192.168.1.10 --scope "Home Lab Router — Personal Authorized" --output report.json
```

### Running the Test Suite
```bash
python3 -m pytest tests/ -v
```

---

## Project Structure

```
.
├── scanner.py                  # Main CLI wrapper (entrypoint)
├── nmap_parser.py              # XML → structured Python objects
├── vuln_db.py                  # Curated CVE/version database
├── report_generator.py         # JSON/Markdown report builder
├── threat_model.md             # Security rationale & design decisions
├── requirements.txt            # Python dependencies
├── demo_data/
│   ├── sample-scan.xml         # Synthetic nmap XML for --demo mode
│   └── risky-services.yaml     # Service → risk profile mappings
├── tests/
│   ├── test_parser.py          # Unit tests for XML parsing
│   ├── test_vuln_db.py         # Unit tests for scoring logic
│   └── test_report.py          # Unit tests for report generation
└── README.md                   # This file
```

---

## Threat Model & Security Rationale

See [`threat_model.md`](threat_model.md) for the full security analysis. Key design decisions:

1. **Mandatory `--scope` flag** — Prevents accidental "I forgot I was on the corporate VPN" incidents. Forces a conscious authorization statement before any scan.

2. **Synthetic demo mode** — Hiring managers and professors can evaluate the full pipeline without network access, reducing risk of unauthorized scan demonstrations.

3. **No hardcoded credentials or API keys** — The CVE database is a curated local YAML file, not a live API call that could leak scan targets or expose API keys in packet captures.

4. **Version fuzzing in demo data** — Synthetic scan results use plausible but non-live version strings to prevent accidental exposure of real internal patch levels.

5. **HIPAA-aware design** — As a pharmacy technician with real PHI exposure, the tool is explicitly designed to **never accept, process, or store protected health information**. All data is synthetic network telemetry only.

6. **Read-only on target** — The wrapper only invokes nmap in ways that do not modify the target (no intrusive scripts, no exploitation, pure reconnaissance).

---

## Skills Demonstrated

- **Python 3 + type hints** — Modern, readable, maintainable code
- **Security tooling integration** — Subprocess management with safety checks
- **XML parsing & data transformation** — `xml.etree.ElementTree` for structured extraction
- **Risk scoring & triage logic** — Severity-based prioritization for SOC workflows
- **CLI UX design** — `argparse` with validation, help text, and error handling
- **Unit testing** — `pytest` coverage for parser, database, and report logic
- **Threat modeling** — Documented security rationale for design decisions
- **Ethical security practice** — Scope enforcement, authorized-use design, synthetic data

---

## Honest Scope Notes

This is a **student portfolio project** built by an entry-level candidate transitioning from healthcare IT to cybersecurity. It is:

- **Real code** that runs and produces real output
- **Not a commercial tool** — it is intentionally scoped to demonstrate specific skills
- **Not a live vulnerability scanner** — the CVE database is static and curated; it does not perform live CVE lookups
- **Built for demonstration and learning** — the `--demo` mode exists specifically for safe evaluation
- **Grounded in actual experience** — the author has 4+ years of healthcare IT exposure (HIPAA, PHI handling, least-privilege access) and runs a self-hosted security home lab

The code is open-source and available for review, critique, and improvement. Feedback is welcome.

---

## Author

**Vincent Phan**  
- CVS Pharmacy Technician (CPhT) — 4+ years healthcare IT/PHI exposure
- CSU San Bernardino, BS Information Systems — Cybersecurity concentration (Fall 2026)
- Home lab: OpenClaw AI security stack on macOS Apple Silicon
- [GitHub Portfolio](https://github.com/Phan-Vincent)

---

## License

MIT License — See repository for full text. Use responsibly. Unauthorized network scanning may violate laws and organizational policies.
