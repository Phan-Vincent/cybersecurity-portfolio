# FINDING-03: Insecure Output Handling

**Severity:** High  
**OWASP:** LLM03 — Insecure Output Handling  
**CWE:** CWE-20 (Improper Input Validation), CWE-116 (Improper Encoding)

---

## Summary

The application enforces strict JSON schema validation on LLM output. This is good. However, two weaknesses exist:

1. **Error path leaks raw LLM output:** If the LLM returns malformed JSON or schema-invalid JSON, the exception message includes the raw response text, which could be logged.
2. **No output encoding for PDF generation:** The `report.py` module (not fully reviewed here but referenced) generates a PDF from the validated JSON. If the LLM returns a string with PDF control characters or escape sequences, it could corrupt the report or cause a render vulnerability.

## Vulnerable Code

File: `vulnerable/llm_audit.py` (lines 122–135)

```python
    # Parse JSON
    try:
        parsed = json.loads(output_text)
    except json.JSONDecodeError as exc:
        raise LLMAuditError("LLM response is not valid JSON") from exc

    if not isinstance(parsed, dict):
        raise LLMAuditError("LLM response JSON root must be an object")

    # Strict schema validation
    try:
        validate(instance=parsed, schema=LLM_AUDIT_SCHEMA)
    except ValidationError as exc:
        raise LLMResponseSchemaError(
            f"LLM response failed schema validation: {exc.message}"
        ) from exc
```

The `ValidationError` exception includes `exc.message` which describes the schema mismatch. It does not include the raw payload, but the traceback chain (via `from exc`) could if the outer handler logs it. More importantly, if the developer ever adds `logger.error(f"Invalid response: {output_text}")` for debugging, the raw output is logged.

## Attack Scenario

1. Attacker manipulates the LLM (via prompt injection or model exploit) to return a JSON object that passes initial `json.loads()` but contains a malicious `reason` string:
   ```json
   {
     "priority": 1,
     "action": "Click here",
     "reason": "<script>alert('xss')</script>"
   }
   ```
2. The schema validation passes because the fields and types match.
3. The `reason` string is passed to `report.py` and embedded into a PDF. If the PDF generator does not escape HTML-like content, it could cause issues in PDF viewers.
4. If the report is ever rendered to HTML, the script tag executes.

## Impact

- **XSS / PDF injection:** Malicious content in the generated report.
- **Data integrity:** Corrupted or misleading audit reports.
- **Downstream harm:** If the report is shared with a coach or medical professional, the injected content could cause confusion or harm.

## Mitigation

1. **Schema validation is good — keep it.** Add `additionalProperties: False` (already present) and `minLength` / `maxLength` / `pattern` constraints on string fields.
2. **Output encoding:** Before inserting any LLM-derived string into PDF/HTML, escape it:
   - `html.escape()` for HTML contexts.
   - PDF-specific sanitization for report generation.
3. **No raw-output logging:** Explicitly ensure `output_text` is never logged, even in debug mode. Log only hashes or validation outcomes.
4. **Content Security Policy:** If reports are ever viewed in a web browser, enforce CSP headers.

## Mitigated Code

File: `mitigated/llm_audit.py`

Key changes:
- Added `MAX_STRING_LENGTH = 256` and `ALLOWED_REASON_PATTERN = r"^[A-Za-z0-9\s.,;:!?()-]+$"` to the schema.
- `report.py` (mocked in tests) uses `html.escape()` on all LLM-derived strings before PDF generation.
- `output_text` is never logged. Only the SHA-256 hash is logged for non-repudiation.

## Test

```bash
pytest tests/test_output_validation.py -v
```

The test:
1. Feeds a schema-valid but malicious-string payload to the report generator.
2. Verifies the output is properly escaped.
3. Verifies no raw LLM output appears in logs.
