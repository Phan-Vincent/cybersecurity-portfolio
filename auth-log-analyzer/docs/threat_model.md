# Threat Model & Security Rationale

## Author Context

Vincent Phan — CVS Pharmacy Technician (CPhT) since 2020. Daily exposure to HIPAA, PHI handling, and least-privilege access in a regulated healthcare environment. Transferring to CSUSB BS IS — Cybersecurity concentration (Fall 2026). Built this as a self-directed portfolio project while running a local OpenClaw AI homelab on macOS.

## What Attackers Are We Worried About?

| Attacker | Capability | Motivation |
|----------|-----------|------------|
| Internet opportunist | Masscan + password list | Compromise any reachable SSH host for botnet/cryptomining |
| Credential-stuffing actor | Leaked databases | Re-use passwords against exposed `sshd` |
| Lateral-movement insider | Valid low-priv account | Escalate via `sudo`/`su` misconfigurations |
| Compromised user device | Stolen key / session | Log in from impossible geography after phishing |

## Why Synthetic Data?

- **No real PHI:** The author works with HIPAA-protected data professionally. Real auth logs can contain usernames, source IPs, and timestamps that, combined with public records, can re-identify individuals.
- **No employer data:** CVS auth infrastructure is proprietary and protected. Nothing in this repo derives from production systems.
- **Sample data is hand-crafted:** Every entry in `data/sample_auth.log` was authored for demonstration. IP addresses are from RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

## Tool Limitations (Honest Scope)

| Limitation | Why It Exists |
|------------|---------------|
| Batch-only (no real-time tail) | Student scope; real-time needs `pyinotify`/systemd integration |
| Mock geo-lookup | Real IP-to-geo requires API keys and GDPR/privacy risk. The static table is illustrative. |
| No ML / statistical baseline | Rule-based is enough to show security logic; ML adds complexity beyond portfolio scope |
| Single-host parsing | No centralized aggregation. A real SOC would use syslog/ELK/Splunk |
| No log integrity verification | No chain-of-custody or signed log hashes. Production SIEMs need tamper evidence. |

## MITRE ATT&CK Coverage

This tool maps detections to ATT&CK for **analyst vocabulary alignment**, not full coverage:

- **T1110 — Brute Force:** Detected via repeated `Failed password` events.
- **T1078 — Valid Accounts (abuse):** Impossible-travel indicates account compromise or credential sharing.
- **T1548 — Abuse Elevation Control Mechanism:** `sudo`/`su` anomalies flag potential privilege escalation.

## Design Security Decisions

1. **Least-privilege by default:** The parser opens the log file read-only. No network egress except optional (not included) webhook alerting.
2. **No secrets in repo:** Config thresholds only; no API keys, no passwords, no private keys.
3. **Deterministic output:** Same log + config → same alerts. Reproducible for testing and CI.
4. **Fail-open for parser errors:** Malformed lines are logged to stderr but do not crash the run, ensuring availability during incident response.

## Future Hardening (Not Implemented)

- SHA-256 log file hash on ingest for tamper evidence.
- Syslog forwarding output module.
- Integration with MaxMind GeoLite2 (self-hosted MMDB) for real geo without API calls.
- Statistical baseline builder (7-day rolling mean) to reduce false positives.
