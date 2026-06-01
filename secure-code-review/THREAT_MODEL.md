# Threat Model: Privacy-First LLM-Driven Bodybuilding Auditor

## System Overview

A Python CLI pipeline that ingests structured CSV exports (nutrition, training), computes deterministic health metrics, and sends sanitized aggregates to an OpenAI LLM for a weekly audit report. The LLM is treated as an **untrusted** external component.

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│  USER WORKSTATION  (Trusted — runs locally)                         │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐              │
│  │   CSV Input │ → │  Ingestion  │ → │ Processing  │              │
│  │  (synthetic)│   │  (sanitize) │   │ (deterministic)              │
│  └─────────────┘   └─────────────┘   └─────────────┘              │
│                                               │                     │
│                                               ▼                     │
│                              ┌─────────────────────┐                │
│                              │  Sanitized Metrics  │                │
│                              │  (JSON, no raw CSV) │                │
│                              └─────────────────────┘                │
│                                               │                     │
│                    ╔═══════════════════════════════════════╗        │
│                    ║  TRUST BOUNDARY 1: Network edge     ║        │
│                    ╚═══════════════════════════════════════╝        │
│                                               │                     │
│                                               ▼                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  OPENAI API  (Untrusted — third-party, logs prompts)       │    │
│  │  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐      │    │
│  │  │  LLM Call   │ → │  JSON Output│ → │  Schema Val │      │    │
│  │  │  (encrypted)│   │             │   │  (reject bad)│      │    │
│  │  └─────────────┘   └─────────────┘   └─────────────┘      │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                               │                     │
│                    ╔═══════════════════════════════════════╗        │
│                    ║  TRUST BOUNDARY 2: Return data        ║        │
│                    ╚═══════════════════════════════════════╝        │
│                                               │                     │
│                                               ▼                     │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐              │
│  │  Report Gen │ → │  PDF/JSON   │ → │  Local Disk │              │
│  │  (sanitize) │   │  (0o600)    │   │  (user-only)│              │
│  └─────────────┘   └─────────────┘   └─────────────┘              │
└─────────────────────────────────────────────────────────────────────┘
```

**Data Classification:** Synthetic health data (nutrition, bodyweight, training volume). No real PHI. Treat as **Sensitive** because the *pattern* is what a real deployment would protect.

## STRIDE Threat Catalog

### Spoofing

| ID | Threat | Description | Mitigation |
|----|--------|-------------|------------|
| S1 | API key spoofing | Attacker uses stolen or guessed OpenAI API key | Scoped API keys, rotation, `.env` excluded from git |
| S2 | Malicious CSV file | Attacker tricks user into running a crafted CSV | File extension check, schema validation, no executable content |

### Tampering

| ID | Threat | Description | Mitigation |
|----|--------|-------------|------------|
| T1 | CSV data tampering | Attacker modifies CSV contents to inject malicious payloads | Row sanitization (strip null bytes), input validation |
| T2 | Prompt injection | Attacker embeds instructions in CSV fields that reach the LLM | Strict system prompt, no dynamic roles, delimiter guard |
| T3 | Output tampering | Man-in-the-middle alters LLM JSON response | TLS 1.2+ enforced by OpenAI SDK, no downgrade |

### Repudiation

| ID | Threat | Description | Mitigation |
|----|--------|-------------|------------|
| R1 | No audit trail | Cannot prove who ran the pipeline or what data was sent | Token usage logging, file timestamps, deterministic logging (no raw data) |
| R2 | No non-repudiation for LLM response | Cannot prove the LLM returned a specific output | Save raw response + hash before validation |

### Information Disclosure

| ID | Threat | Description | Mitigation |
|----|--------|-------------|------------|
| I1 | PHI leakage to LLM provider | OpenAI logs prompts for training/review; personal health data could be retained | Data minimization (only aggregates), synthetic-only demo, no raw CSV |
| I2 | API key in logs | Crash traceback or verbose log includes `OPENAI_API_KEY` | No secret logging, sanitized exception messages |
| I3 | Report file readable by others | PDF/JSON written with default permissions (`0o644`) | Explicit `0o600` on token log; recommend same on reports |
| I4 | Error message disclosure | Verbose error messages reveal file paths or schema internals | Generic user-facing errors; detailed logs only in file |

### Denial of Service

| ID | Threat | Description | Mitigation |
|----|--------|-------------|------------|
| D1 | Token cost overrun | Large input or infinite loop causes excessive API spend | Token budget check **before** call, `max_tokens` limit, input size caps |
| D2 | CSV bomb / DoS | Extremely large CSV causes memory exhaustion | Row count limits, file size caps, streaming read |
| D3 | LLM API unavailability | OpenAI outage halts pipeline | Timeout (30s), max_retries (1), graceful degradation |

### Elevation of Privilege

| ID | Threat | Description | Mitigation |
|----|--------|-------------|------------|
| E1 | Path traversal | `--nutrition` argument points outside working directory | `Path.resolve()` + allowlist, or chroot-like validation |
| E2 | Arbitrary code execution | `pickle` or `eval` in CSV parsing (not present, but verify) | No `eval`, no `pickle`, standard `csv.DictReader` only |
| E3 | `.env` file privilege | `.env` readable by other users on shared machine | `chmod 600 .env` check on startup, warn if loose |

## Risk Matrix

| Threat | Likelihood | Impact | Risk | Priority |
|--------|------------|--------|------|----------|
| T2 — Prompt injection | High | High | **Critical** | P0 |
| I1 — PHI to LLM | Medium | High | **High** | P1 |
| T1 — CSV tampering | Medium | Medium | Medium | P2 |
| S1 — API key spoofing | Low | High | Medium | P2 |
| D1 — Cost overrun | Medium | Low | Low | P3 |
| I3 — File permissions | Low | Medium | Low | P3 |

## Assumptions

1. The user machine is not compromised at the OS level (if it is, all bets are off).
2. OpenAI's API and TLS stack are trusted for transport security.
3. Synthetic data is used for all demonstrations.
4. The user has physical control of the machine.

## Out of Scope

- Network-level attacks (DNS hijacking, BGP) — handled by TLS.
- OpenAI infrastructure compromise — outside our control.
- Physical theft of the machine — handled by OS-level FDE (FileVault).
- Supply-chain attacks on `openai` Python package — use lockfiles + hash verification.
