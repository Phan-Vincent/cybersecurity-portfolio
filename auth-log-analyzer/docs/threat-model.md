# Threat Model & Security Rationale

## Why This Tool Exists

A SOC analyst's job is to find the signal in the noise of millions of log lines. This project demonstrates understanding of that workflow: parsing unstructured logs, applying time- and pattern-based detections, and producing alerts a human can act on.

## What Each Detection Catches (and Misses)

### 1. Brute-force SSH (T1110)

**What it catches:** Rapid-fire failed logins from a single IP — the most basic and common attack pattern.

**What it misses:**
- Distributed attacks (many IPs, few attempts each) — would need DGA or username-correlation logic.
- Slow brute force (one attempt per hour) — evades time-window detection.
- Valid usernames with password spraying — same pattern, but the "invalid user" lines would be absent.

**Rationale:** This is a "first line" detection. It won't catch sophisticated adversaries, but it catches noisy ones, and noisy ones are common.

### 2. Credential Stuffing Success (T1110.001)

**What it catches:** A successful login that immediately follows repeated failures. This is the "oh no" moment — the attacker got in.

**Why it's critical:** Brute-force without success is reconnaissance. With success, it's a breach.

**False positive risk:** Low if threshold is tuned. A user forgetting their password then getting it right looks identical, but that's still worth a review if the IP is external.

### 3. Impossible Travel (T1078)

**What it catches:** Same user logging in from two geolocations faster than physically possible. Suggests:
- Compromised credentials sold/shared
- VPN hopping
- Session hijacking

**What it misses:**
- VPN users (legitimate travel via corporate VPN)
- Users with legitimate fast travel (executives on private jets)
- Mobile users on cellular networks with dynamic geolocation

**Rationale:** This is a medium-confidence anomaly, not a smoking gun. It should trigger a review, not an automatic lockout.

**Design choice:** Uses a static synthetic lookup table. Production would use MaxMind GeoIP2 or similar.

### 4. Privilege Escalation — Sudo to Root (T1548.003)

**What it catches:** Non-admin users executing sudo to root. Even if the command is benign (restarting nginx), the *privilege* is what matters.

**Severity modulation:**
- Medium: Generic sudo to root
- High: Sudo to root + suspicious command (cat /etc/shadow, netcat shells, etc.)

**What it misses:**
- Kernel exploits (no sudo needed)
- Sudo misconfigurations (user already has NOPASSWD)
- Polkit/CVE-2021-4034 style bypasses

**Rationale:** This is a detective control, not preventive. It assumes sudo is properly configured and logged.

### 5. Off-Hours Account Creation (T1136.001)

**What it catches:** User accounts created outside business hours. Low severity because it's often legitimate (offshore contractors, automated provisioning).

**Why include it?**
- Persistence is a key MITRE tactic
- Backdoor accounts are a common post-exploitation step
- Correlating with change tickets is standard SOC hygiene

**False positive risk:** High. This is intentionally low-severity and requires analyst judgment.

## Detection Philosophy

| Principle | Application |
|-----------|-------------|
| **Defense in depth** | No single detection catches everything. We stack brute-force + success + escalation + persistence. |
| **Signal vs. noise** | Every detection includes a confidence score. Low-confidence alerts (impossible travel, off-hours useradd) are medium/low severity. |
| **Analyst-centric** | Human-readable output includes MITRE context, source events, and recommendations. Alerts should be actionable in < 60 seconds. |
| **Honest limitations** | Documented in code comments and this file. No detection is perfect; we know what we miss. |

## Synthetic Data Rationale

All sample data is synthetic because:
1. **Ethics:** Real auth logs contain usernames, IPs, and behavioral patterns that could identify individuals.
2. **Legality:** PHI and system logs may be subject to HIPAA, PCI-DSS, or corporate confidentiality.
3. **Pedagogy:** Synthetic data lets us craft specific attack scenarios for demonstration.

The sample log (`data/sample-auth.log`) is intentionally designed to trigger every detection at least once.
