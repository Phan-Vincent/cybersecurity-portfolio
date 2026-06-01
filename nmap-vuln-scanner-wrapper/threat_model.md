# Network Recon & Vuln Scanner Wrapper — Threat Model & Security Rationale

**Author:** Vincent Phan  
**Date:** 2026-06-01  
**Version:** 1.0.0

---

## 1. Project Purpose

This is a **student portfolio project** demonstrating how an entry-level cybersecurity candidate can build production-quality defensive tooling. It wraps `nmap` to perform authorized host/port discovery, parses structured XML output, and cross-references detected services against a curated vulnerability database. The target audience is **hiring managers** and **SOC team leads** evaluating a candidate's coding ability, security mindset, and ethical judgment.

---

## 2. Threat Model

### 2.1 What This Tool Does
- **Reads** nmap XML output (already-generated scan results)
- **Parses** host metadata, open ports, service banners, and OS fingerprints
- **Scores** findings against a static, local YAML database of known risky services/versions
- **Reports** prioritized findings in JSON or Markdown for SOC triage

### 2.2 What This Tool Does NOT Do
- ❌ Execute any exploits against discovered services
- ❌ Perform live CVE lookups via external APIs (avoids leaking scan targets + API keys)
- ❌ Store, process, or transmit any protected health information (PHI)
- ❌ Modify target systems in any way
- ❌ Run without an explicit `--scope` authorization statement

### 2.3 Adversarial Threats Considered

| Threat | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| **Unauthorized scan by user** | High | Legal / policy violation | `--scope` mandatory flag; demo mode for safe evaluation; README emphasizes authorized use only |
| **Accidental exposure of scan results** | Medium | Data leak | Reports are local files only; no cloud upload; no hardcoded credentials |
| **Orphaned temp files with scan data** | Low | Disk leak | Temp files are written to `NamedTemporaryFile` with explicit cleanup in production usage |
| **Malicious input in nmap XML** | Low | XML parsing vulnerability | Uses Python's built-in `xml.etree.ElementTree` (no external entity expansion); input is trusted local file |
| **Synthetic demo data mistaken for real** | Medium | Misrepresentation | Demo XML explicitly contains `<!-- Synthetic nmap scan data for demo mode. No real network was scanned. -->` |

---

## 3. Security Design Decisions

### 3.1 Mandatory `--scope` Flag

**Rationale:** The most common security incident in entry-level reconnaissance is the "I forgot I was on the VPN" scan. By requiring a human-readable authorization statement *before* the tool executes any subprocess call, we force a conscious decision and create an audit trail.

**Validation:** Minimum 10 characters; no regex magic, just "be descriptive."

### 3.2 Static YAML Database (No Live CVE API)

**Rationale:** Three reasons:
1. **Offline operation** — Works in air-gapped home labs without internet
2. **No API key exposure** — No risk of leaking NVD API keys in packet captures or git history
3. **Demonstration safety** — Hiring managers can run `--demo` without any network calls

**Trade-off:** Database is static and may miss zero-days. This is acceptable for a student portfolio project; a production tool would layer live CVE enrichment on top of the base scoring.

### 3.3 Synthetic Demo Mode

**Rationale:** Anyone evaluating this project should be able to run it immediately without:
- Installing nmap
- Having a target network
- Risking an unauthorized scan

The bundled `sample-scan.xml` uses **plausible but non-live** version strings and IP addresses in RFC 1918 space (`192.168.1.0/24`). The XML contains an explicit synthetic-data comment.

### 3.4 HIPAA-Aware Design

**Rationale:** As a pharmacy technician with 4+ years of healthcare IT exposure, I am acutely aware of PHI handling requirements. This tool is explicitly scoped to **network telemetry only** (IPs, ports, banners). It:
- Never accepts patient data as input
- Never stores healthcare identifiers
- Uses synthetic data in all demonstrations

This is documented in the README to signal regulatory awareness to hiring managers in healthcare-adjacent security roles.

### 3.5 Read-Only nmap Flags

**Rationale:** The wrapper uses only SYN stealth scan (`-sS`), version detection (`-sV`), and OS fingerprinting (`-O`). It does **not** use:
- `-A` (aggressive, includes script scanning)
- `--script` (NSE scripts can be intrusive)
- `-T5` (insanely fast, may overwhelm targets)

This keeps the tool in the **reconnaissance** phase of the kill chain, never crossing into exploitation.

### 3.6 Subprocess Safety

**Rationale:** The wrapper constructs the nmap command as a list (not a string) to prevent shell injection. It validates the nmap binary exists before execution and caps scan duration at 5 minutes to prevent runaway processes.

---

## 4. Honest Limitations (Student Project Scope)

This tool is intentionally scoped. Honest limitations include:

| Limitation | Why It's Acceptable |
|------------|-------------------|
| Static CVE database | Demonstrates architecture; live enrichment is a v2 feature |
| No authenticated scanning | Out of scope for a single-project portfolio piece |
| No differential / trend analysis | Would require a database; kept stateless for simplicity |
| Single-threaded | nmap handles parallelism; wrapper is sequential post-processing |
| No IDS/IPS evasion | This is a defensive tool, not a red-team framework |

---

## 5. Risk Scoring Philosophy

The scoring engine uses a **defensive triage** model, not a precise CVSS calculator. Rationale:

- **CVSS is complex** and often misapplied by entry-level analysts
- **A simple 0-100 scale** with clear severity labels is more actionable for SOC triage
- **The goal is prioritization**, not perfect vulnerability quantification

Scoring factors:
1. **Base risk** per service (e.g., telnet = 95, SSH = 20)
2. **Version vulnerability bonus** (e.g., OpenSSH 7.x gets +30)
3. **Banner leakage penalty** (+10 for long version strings = information disclosure)
4. **OS identification discount** (-5 if OS is known, slightly reducing uncertainty)

This is **heuristic**, not empirical, but it demonstrates defensive thinking: "What would a SOC analyst care about first?"

---

## 6. Conclusion

This project is a **demonstration of engineering judgment** as much as coding ability. The security design decisions — scope enforcement, static offline database, synthetic demo mode, read-only nmap flags, HIPAA awareness — are all signals that the author thinks like a defender, not just a script writer.

Feedback and critique are welcome. This is a learning project, and the threat model itself is a learning exercise.
