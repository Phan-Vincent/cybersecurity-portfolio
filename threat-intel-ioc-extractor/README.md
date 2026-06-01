# Threat Intel Feed & IOC Extractor

> **One-liner:** A Python CLI tool that ingests threat intelligence feeds (RSS/Atom), extracts structured Indicators of Compromise (IOCs), scores them by confidence, and exports SOC-ready STIX-lite JSON or Markdown daily briefs — all without ever writing raw source text to disk.

---

## Problem Statement

SOC analysts and security teams are flooded with threat intelligence feeds, blog posts, and advisories. Buried in unstructured text are critical IOCs — IPs, domains, file hashes, CVEs — that need to be extracted, validated, and actioned quickly. Manual copy-paste is error-prone and slow. Existing enterprise tools are expensive, over-complicated, or require cloud APIs that risk data leakage (especially in healthcare environments governed by HIPAA).

This project solves that problem with a lightweight, privacy-first, open-source extraction engine.

---

## What This Project Demonstrates

- **Regex & pattern engineering:** Hand-crafted regexes for IPv4/IPv6, domains, hashes (MD5/SHA1/SHA256), and CVE IDs with validation beyond simple matching.
- **Data validation:** Octet checks, hash length verification, domain TLD sanity, RFC 1918 private IP detection.
- **Confidence scoring:** Heuristic scoring based on context enrichment (threat keywords), hash verification, and IP routability — not just "it matched."
- **STIX 2.1 familiarity:** Produces structurally correct STIX-lite indicator bundles with proper pattern syntax, labels, and confidence fields.
- **Threat intelligence lifecycle:** Ingestion → Extraction → Deduplication → Scoring → Dissemination (STIX + brief).
- **Security-by-design:** Memory-only processing of raw source text to prevent accidental PHI/PII leakage. A lesson learned from working in HIPAA-regulated healthcare (CVS Pharmacy).
- **CLI craftsmanship:** argparse-driven, sensible defaults, exit codes, logging to stdout only, and a bash convenience wrapper.

---

## Who Built This

**Vincent Phan** — CVS Pharmacy Technician (CPhT) since 2020, with daily exposure to PHI handling, HIPAA compliance, and pharmacy information systems. Transferring to CSU San Bernardino (Fall 2026) for a BS in Information Systems with a Cybersecurity concentration. This is a student portfolio project built to demonstrate SOC-analyst-relevant skills to hiring managers.

**Honest scope:** This is a student project. It uses synthetic data only. It is designed for an entry-level SOC analyst portfolio, not as a production replacement for enterprise TIP/SOAR platforms. It is believable because a motivated student with healthcare IT exposure can genuinely build and explain it.

---

## How to Run

### Installation

```bash
git clone https://github.com/Phan-Vincent/threat-intel-ioc-extractor.git
cd threat-intel-ioc-extractor
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Quick Start (Offline Demo Mode)

```bash
python -m src.cli --samples --output-dir ./output --format both
```

Or use the convenience script:

```bash
bash run.sh
```

### Live Feed Mode

```bash
python -m src.cli --feed https://feodotracker.abuse.ch/feodotracker.rss --format brief
```

### CLI Arguments

| Flag | Description |
|------|-------------|
| `--feed <url>` | RSS/Atom feed URL (repeatable) |
| `--samples` | Use bundled synthetic articles instead of live feeds |
| `--output-dir <dir>` | Where to write output files (default: `./output`) |
| `--format {stix,brief,both}` | Output format (default: `both`) |
| `--confidence-threshold <0-100>` | Minimum confidence to include (default: `0`) |
| `--no-phi-log` | Default `True`. Never writes raw source text to disk. |
| `--verbose` | Enable debug logging |

### Exit Codes

- `0` — Success
- `1` — Error (bad feed, file not found, etc.)
- `2` — No IOCs found (or none met confidence threshold)

---

## Output Examples

### STIX-lite JSON (`output/latest.json`)

```json
{
  "type": "bundle",
  "id": "bundle--20240615120000",
  "spec_version": "2.1",
  "metadata": {
    "tool": "ThreatIntel-IOCEngine/1.0",
    "iocs_extracted": 3
  },
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--0001",
      "name": "IPV4:192.0.2.1",
      "pattern": "[ipv4-addr:value = '192.0.2.1']",
      "pattern_type": "stix",
      "confidence": 85,
      "labels": ["automated-extraction", "ipv4", "high"]
    }
  ]
}
```

### Markdown Brief (`output/latest.md`)

```markdown
# Threat Intel Daily Brief

**Generated:** 2024-06-15 12:00 UTC
**Feeds:** samples
**Articles processed:** 7
**IOCs extracted:** 12

## 🔒 Block These IPs
- `192.0.2.1` — confidence **high** (85.0)
- `203.0.113.5` — confidence **high** (82.0)

## 🌐 Monitor / Block These Domains
- `evil.example.com` — confidence **medium** (70.0)

## 🔍 File Hashes for Hunting
- `d41d8cd98f00b204e9800998ecf8427e` (MD5)
- `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (SHA256)

## ⚠️ CVEs to Track
- `CVE-2024-1234` — confidence **medium** (75.0)

## 🏠 Internal / Private IPs (Informational)
- `10.0.0.5`
- `172.16.0.10`
```

<!-- Screenshot: Run `bash run.sh` and capture the terminal output + output directory listing here -->

---

## Threat Model & Security Rationale

### 1. Why Memory-Only Processing?

In healthcare and pharmacy environments, raw incident reports, SIEM alerts, or advisory emails may contain **Protected Health Information (PHI)** — patient names, medical record numbers, prescription details. If a tool logs raw source text to disk for debugging, that becomes a HIPAA breach waiting to happen.

**Design choice:** `extractor.py` processes raw text in-memory only. It extracts structured IOCs and immediately discards the source string. Only IOC dataclasses (type, value, confidence, truncated context) are passed downstream. The `--no-phi-log` flag (default `True`) enforces this contract at the CLI level. No raw text ever hits the output directory.

### 2. Why Input Validation Matters

Regex alone is dangerous. A 32-character hex string could be an MD5 hash, or it could be a UUID, a database ID, or a random alphanumeric string. Without validation, you flood your SIEM with false positives.

**Design choice:** Every extracted IOC is validated:
- IPv4: octet range check (0-255), 4 octets
- IPv6: `ipaddress.IPv6Address` parsing
- Hashes: exact length + hex character check
- Domains: structural sanity (no `..`, no leading/trailing dots), greylist exclusion
- CVEs: year range sanity (1999–current+1)

### 3. Why Confidence Scoring?

Not every IOC is equally actionable. An IP mentioned in a blog post about a 5-year-old campaign is less urgent than a hash from a CISA alert.

**Design choice:** Confidence is additive and transparent:
- `regex_match` (30) — base hit
- `context_enriched` (up to 25) — threat keywords nearby (`malware`, `c2`, `ransomware`, `phishing`)
- `hash_verified_length` (20) — hash passed length check
- `ip_not_private` (15) — public routable IP (not RFC 1918)
- `domain_not_greylisted` (10) — not a placeholder domain
- `cve_valid_year` (10) — CVE year is reasonable

Bands: **low** (<60), **medium** (60–80), **high** (≥80). SOC analysts can set `--confidence-threshold` to tune noise vs. signal.

### 4. Why Separate Private IPs?

If a threat report mentions `10.0.0.5`, it is not a "block at the firewall" IOC — it is an internal lateral-movement indicator. We report it separately so analysts don't accidentally block internal infrastructure.

### 5. Why Rate-Limiting & Polite Headers?

Threat intel feeds are free resources run by security researchers. Aggressive scraping gets you IP-banned and burns community goodwill. We send a descriptive `User-Agent` and enforce a 2-second delay between requests.

---

## Skills Demonstrated

| Skill | Where It Shows |
|-------|----------------|
| **Regex engineering** | `src/config.py` — IPv4/IPv6, domain, hash, CVE patterns with named groups |
| **STIX 2.1 familiarity** | `src/output.py` — `to_stix_lite()` produces indicator bundles with valid pattern syntax |
| **Threat intel lifecycle** | `src/cli.py` — ingest → extract → dedup → score → output (STIX + brief) |
| **Python & type hints** | All modules use `from __future__ import annotations`, dataclasses, and `Final` typing |
| **Data validation** | `src/extractor.py` — octet checks, hash length verification, domain sanity |
| **CLI design** | `src/cli.py` — argparse, exit codes, stdout-only logging, `--no-phi-log` |
| **Security-by-design** | Memory-only processing, PHI-aware logging, input validation, private IP separation |
| **Unit testing** | `tests/` — pytest with mocked network calls, invalid input rejection, schema checks |
| **Healthcare context** | Sample data includes ransomware targeting hospitals; author understands HIPAA from CVS |

---

## Architecture

```
src/
  config.py     # Regexes, scoring weights, feed URLs, constants
  extractor.py  # IOC extraction, validation, deduplication, confidence scoring
  ingest.py     # RSS/Atom parsing, sample loading, rate-limited HTTP fetching
  output.py     # STIX-lite JSON and Markdown brief formatters
  cli.py        # argparse entry point, orchestration, stdout logging

tests/
  test_extractor.py  # Regex, validation, dedup, scoring, PHI-safety tests
  test_ingest.py     # RSS/Atom parsing, sample mode, network mock tests
  test_output.py     # STIX schema validation, brief structure checks

data/
  samples.json  # 7 synthetic threat articles with embedded IOCs
```

---

## Honest Scope Notes

- **Student project.** Built for a cybersecurity portfolio while preparing for a BS in Information Systems (Cybersecurity concentration) at CSU San Bernardino.
- **Synthetic data only.** No real patient data, no real pharmacy systems, no real internal IPs. All sample articles are fictional.
- **STIX-lite, not full STIX.** I intentionally simplified the spec to keep the codebase readable and focused. It demonstrates I understand the structure without bloating the project with full SDO/SRO relationship graphs.
- **Not a production TIP.** This is a learning project. A real enterprise deployment would need async workers, a database, API authentication, YARA integration, and more. I know that, and I can talk about the gap.
- **Built with OpenClaw.** I run a self-hosted AI home lab on macOS (Apple Silicon) that helps with code generation, testing, and documentation. The architecture and design decisions are mine; the AI is a pair-programmer, not a ghost-writer.

---

## License

MIT — use it, fork it, learn from it. If you're a student building your own portfolio, star this repo and go build something better.

---

*Last updated: June 2025*
