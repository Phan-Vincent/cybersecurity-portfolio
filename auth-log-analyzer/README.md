# Auth Log Analyzer (SIEM-lite)

A lightweight Python security analytics tool that parses Linux authentication logs, detects brute-force SSH attacks, impossible-travel anomalies, and privilege escalation events. Built as a portfolio project demonstrating SOC analyst workflow understanding.

## One-Line Pitch

> "I built a SIEM-lite log analyzer that turns raw auth logs into actionable, MITRE-mapped security alerts — the kind of visibility a SOC analyst needs on Day 1."

## What This Demonstrates

- **Log Parsing & Normalization:** Structured parsing of unstructured syslog-style auth logs into a queryable format.
- **Anomaly Detection:** Time-window based brute-force detection, impossible-travel geolocation logic, and privilege escalation monitoring.
- **Threat Intelligence Mapping:** Every detection maps to MITRE ATT&CK technique IDs with rationale.
- **Alert Lifecycle:** JSON-structured alerts with severity scoring and human-readable summaries for triage.
- **Defense-in-Depth Thinking:** Threat-model documentation explaining *why* these detections matter in a real SOC.

## How to Run

```bash
# Setup
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run against sample data
python src/main.py --log data/sample-auth.log --rules data/ruleset.yaml --output reports/

# Run tests
pytest tests/ -v
```

## Project Structure

```
auth-log-analyzer/
├── README.md                  # This file
├── requirements.txt           # Dependencies
├── src/
│   ├── main.py               # CLI entry point
│   ├── parser.py             # Auth log parser
│   ├── detections.py         # Detection engine
│   ├── formatter.py          # Alert formatter (JSON + human)
│   └── config.py             # Configuration & thresholds
├── data/
│   ├── sample-auth.log       # Synthetic auth log for testing
│   └── ruleset.yaml          # Detection rules configuration
├── tests/
│   └── test_parser.py        # Unit tests
└── docs/
    ├── threat-model.md       # Security rationale & detection design
    └── mitre-mapping.md      # ATT&CK technique mappings
```

## Skills Demonstrated

| Skill | Evidence |
|-------|----------|
| Log Analysis | Structured parsing of auth events (PAM, SSH, sudo) |
| Pattern Matching | Regex-based extraction with validation |
| Temporal Analysis | Time-window aggregation for brute-force detection |
| Geolocation Logic | Impossible-travel distance/time correlation |
| MITRE ATT&CK | Technique IDs mapped with real detection logic |
| Python | Clean, tested, documented code |
| Security Mindset | Threat-model documentation, severity scoring |

## Honest Scope Notes

This is a student-built portfolio project designed to show SOC analyst workflow understanding. It is **not** a production SIEM replacement.

- Uses a local rules engine rather than a correlation backend (like Splunk or Chronicle).
- GeoIP uses a static lookup table (production would use MaxMind or similar).
- Alerting is file-based JSON output (production would integrate with SOAR or email/SIEM ingestion).
- All data is synthetic. No real credentials, hostnames, or logs are used.

## Threat Model & Security Rationale

See [docs/threat-model.md](docs/threat-model.md) for why each detection exists, what it catches, and what it misses.

## MITRE ATT&CK Mapping

See [docs/mitre-mapping.md](docs/mitre-mapping.md) for technique ID mappings and detection coverage.

## About the Author

**Vincent Phan** — CVS Pharmacy Technician (CPhT), transferring to CSU San Bernardino for BS Information Systems, Cybersecurity concentration. This project was built to practice the log-analysis and alert-triage skills expected of an entry-level SOC analyst.

---

*All sample data is synthetic. No real credentials or system information is included.*
