# MITRE ATT&CK Mapping

## Detection Coverage

| Detection | Technique ID | Technique Name | Tactic | Rationale |
|-----------|--------------|----------------|--------|-----------|
| Brute-force SSH | T1110 | Brute Force | Credential Access | Multiple failed logins in short window |
| Brute-force SSH | T1110.001 | Brute Force: Password Guessing | Credential Access | Rapid password attempts against single user |
| Credential Stuffing Success | T1110.001 | Brute Force: Password Guessing | Credential Access | Success after repeated failure = valid creds compromised |
| Impossible Travel | T1078 | Valid Accounts | Initial Access / Persistence | Credential reuse or account sharing across geos |
| Impossible Travel | T1078.001 | Valid Accounts: Default Accounts | Initial Access | If attacker uses default/shared creds from new geo |
| Privilege Escalation — Sudo | T1548.003 | Abuse Elevation Control Mechanism: Sudo | Privilege Escalation | Leveraging sudo for unauthorized root access |
| Privilege Escalation — Suspicious Cmd | T1083 | File and Directory Discovery | Discovery | cat /etc/shadow = credential discovery |
| Privilege Escalation — Suspicious Cmd | T1049 | System Network Connections Discovery | Discovery | netcat / nmap = network reconnaissance |
| Off-Hours Useradd | T1136.001 | Create Account: Local Account | Persistence | New local account for persistence |
| Off-Hours Useradd | T1098 | Account Manipulation | Persistence | Account creation as post-exploitation step |

## What This Coverage Demonstrates

As a student project, this covers **four core MITRE tactics** relevant to SOC analyst work:

1. **Credential Access (T1110)** — The most common initial attack vector. SOC analysts spend significant time on brute-force and credential stuffing alerts.

2. **Initial Access / Persistence (T1078, T1136)** — Detecting account compromise and backdoor creation. These are "post-breach" detections that indicate successful compromise.

3. **Privilege Escalation (T1548)** — Catching lateral movement and privilege abuse. Sudo logging is standard on Linux; knowing how to query it is a core SOC skill.

4. **Discovery (T1083, T1049)** — Attackers don't just breach; they explore. Detecting shadow file reads and network scans shows understanding of the *kill chain*.

## Gaps (Honest Assessment)

| Missing Coverage | Why | What Would Extend It |
|------------------|-----|----------------------|
| T1567 — Exfiltration | No network flow logs | Add netflow / proxy log ingestion |
| T1059 — Command Execution | Only sudo commands logged | Add bash history / auditd ingestion |
| T1071 — C2 | No network indicator rules | Add DNS / beaconing detection |
| T1486 — Ransomware | No file-system events | Add FIM (File Integrity Monitoring) |
| T1190 — Exploit Public-Facing App | No HTTP logs | Add web server log parsing |

This is a deliberate scope boundary. A student project that claims to detect *everything* is suspicious. This tool detects authentication-layer anomalies well, which is exactly what an entry-level SOC analyst needs to demonstrate.
