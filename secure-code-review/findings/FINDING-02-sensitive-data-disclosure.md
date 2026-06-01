# FINDING-02: Sensitive Data Disclosure to LLM Provider

**Severity:** High  
**OWASP:** LLM02 — Sensitive Information Disclosure  
**CWE:** CWE-200 (Exposure of Sensitive Information)

---

## Summary

The application sends computed health metrics (bodyweight, calorie intake, protein intake, training volume) to OpenAI's API. In a real deployment, this would be **personal health information (PHI)**. Even though the current repository uses synthetic data for demos, the architecture is designed to process real user data.

OpenAI's API may log prompts for:
- Training data improvement (opt-out available but not enabled by default)
- Abuse detection and content moderation
- Debug/error analysis by platform engineers

There is no **Business Associate Agreement (BAA)** or Data Processing Agreement (DPA) configured. The application does not inform the user that their health data is leaving the local machine.

## Vulnerable Code

File: `vulnerable/llm_audit.py` (lines 98–108)

```python
def generate_audit(processed_metrics: dict[str, Any]) -> dict[str, Any]:
    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY")
    model_name = os.getenv("LLM_MODEL", "gpt-4o-mini")

    if not api_key:
        raise LLMAuditError("OPENAI_API_KEY is not configured")

    safe_payload = _safe_metrics_payload(processed_metrics)
    # SECURITY: Only sanitized structured metrics are sent to LLM.
    # Raw CSV data is never forwarded.
    client = OpenAI(api_key=api_key, timeout=30.0, max_retries=1)
    completion = client.responses.create(
        model=model_name,
        input=_build_prompt_messages(safe_payload),
        temperature=0,
        response_format={"type": "json_object"},
    )
```

**Note:** The comment says "Only sanitized structured metrics are sent to LLM." This is true *within the app*, but the metrics are still health data. The app is privacy-first *relative to sending raw CSV*, but not *relative to sending any health data at all to a third party*.

## Attack Scenario / Privacy Failure

1. User runs the pipeline with their real Cronometer export.
2. The app computes `protein_per_lb`, `bodyweight_lb`, `calorie_adherence_pct`.
3. These values are sent to OpenAI.
4. OpenAI logs the prompt. A platform engineer reviewing logs sees:
   - `bodyweight_lb: 148.8`
   - `avg_protein_g: 145.2`
   - `calorie_adherence_pct: 92.1`
5. Combined with other data or IP address, this becomes identifiable health information.

## Impact

- **Regulatory:** HIPAA violation if deployed in a healthcare context (Vincent is a CPhT — he knows this).
- **Privacy:** User health data is retained by a third party with no explicit user consent.
- **Trust:** Undermines the "Privacy-First" branding of the application.

## Mitigation

1. **Data minimization:** Only send *truly necessary* fields. Question whether `bodyweight_lb` is needed for the audit, or if a normalized index (`bodyweight_z_score`) could suffice.
2. **Local model option:** Add a flag to run against a local LLM (e.g., Ollama, llama.cpp) so no data leaves the machine.
3. **Explicit consent:** Before first run, display a warning: *"This will send computed health metrics to OpenAI. No raw CSV data is sent, but aggregated metrics may be logged by the provider."*
4. **Opt-out of training:** Set `OpenAI(...)` with `api_key` and ensure the organization has disabled data retention (OpenAI enterprise/team accounts).
5. **Synthetic-only demo mode:** The default demo uses synthetic data and requires an explicit `--live` flag for real API calls.

## Mitigated Code

File: `mitigated/llm_audit.py`

Key changes:
- `generate_audit()` takes an `allow_remote: bool = False` parameter.
- Default behavior: returns a mock audit (no network call).
- `--live` flag required on CLI to enable real LLM calls.
- Added `CONSENT_MESSAGE` printed to stderr before the first live call.

## Test

```bash
pytest tests/test_secrets.py -v
```

The test verifies that the mitigated code does not call `OpenAI()` unless `--live` is passed.
