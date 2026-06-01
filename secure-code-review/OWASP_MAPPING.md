# OWASP Mapping: Findings → Top 10

This document maps each discovered vulnerability to the relevant OWASP framework.

## OWASP Top 10 for LLM Applications (2025)

| # | Category | Finding | Severity |
|---|----------|---------|----------|
| **LLM01** | **Prompt Injection** | FINDING-01: User-controlled `muscle_group` strings reach the LLM via `json.dumps` payload. System-prompt defense is advisory, not enforced. | **Critical** |
| **LLM02** | **Sensitive Information Disclosure** | FINDING-02: Health metrics (bodyweight, nutrition) sent to OpenAI. No DPA/BAA. PHI-class data in prompts. | **High** |
| **LLM03** | **Insecure Output Handling** | FINDING-03: Schema validation exists but hard-fails with raw LLM output in exception messages. No output encoding for downstream PDF. | **High** |
| **LLM06** | **Excessive Agency** | FINDING-07: Token budget checked **after** API call. No `max_tokens` parameter. Could spend unlimited money before abort. | **Medium** |
| **LLM07** | **Insecure Plugin Design** | N/A — no plugins in this app. | — |

## OWASP Top 10 (2021)

| # | Category | Finding | Severity |
|---|----------|---------|----------|
| **A01** | **Broken Access Control** | FINDING-06: Output files created with default permissions. Token log does `0o600` but reports are `0o644`. | **Medium** |
| **A03** | **Injection** | FINDING-01: Prompt injection. Also FINDING-04: Path traversal via `--nutrition ../../etc/passwd`. | **Critical** / **High** |
| **A05** | **Security Misconfiguration** | FINDING-05: `.env` file permissions not checked. `OPENAI_API_KEY` loaded without validation. Verbose exception logging. | **Medium** |
| **A06** | **Vulnerable and Outdated Components** | `openai` SDK is current; no SBOM. Dependency scanning (Bandit) not integrated. | **Low** |
| **A09** | **Security Logging and Monitoring Failures** | FINDING-05: No structured audit log. No non-repudiation hash for LLM responses. No alert on cost threshold breach. | **Medium** |
| **A10** | **Server-Side Request Forgery (SSRF)** | N/A — no URL inputs. | — |

## Cross-Reference Matrix

```
                     A01  A03  A05  A06  A09  LLM01  LLM02  LLM03  LLM06
FINDING-01 (Prompt)        ✓                      ✓
FINDING-02 (PHI)                                         ✓
FINDING-03 (Output)                                              ✓
FINDING-04 (Path)          ✓    ✓
FINDING-05 (Logging)                 ✓          ✓
FINDING-06 (Perms)   ✓
FINDING-07 (Cost)                                                     ✓
```
