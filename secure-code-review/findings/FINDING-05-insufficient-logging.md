# FINDING-05: Insufficient Logging & Monitoring

**Severity:** Medium  
**OWASP:** A09 — Security Logging and Monitoring Failures  
**CWE:** CWE-778 (Insufficient Logging), CWE-532 (Insertion of Sensitive Information into Log File)

---

## Summary

The application logs operational events to `pipeline.log` and token usage to `token_usage.log`. However:

1. **No structured audit log:** There is no single, append-only, tamper-evident log of who ran the pipeline, what files were ingested, what the LLM response hash was, and whether any anomalies occurred.
2. **Potential sensitive data leakage in logs:** While the current code is careful, the `logger.warning` and `logger.exception` calls in `main.py` could accidentally capture exception messages that contain sensitive data if the exception objects include it. For example, an `OpenAIError` might contain the full request body in its message.
3. **No non-repudiation:** The LLM response is not hashed and saved before validation. If a dispute arises, there is no proof of what the model actually returned.
4. **No alerting:** If the token budget is exceeded or a schema validation fails, it is logged but no alert is sent.

## Vulnerable Code

File: `vulnerable/main.py` (lines 65–90)

```python
def _configure_file_logger(output_dir: Path) -> logging.Logger:
    output_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("pipeline")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(output_dir / "pipeline.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler(handler)
    return logger

# ... in run_cli() ...
except Exception as exc:
    logger.exception("Unexpected pipeline failure: %s", type(exc).__name__)
    print("Error: Unexpected pipeline failure.")
    return 1
```

`logger.exception` writes the full traceback to the log file. If any exception in the chain contains sensitive data (e.g., the API key from an `OpenAIError` response body), it is persisted to disk.

## Attack Scenario

1. A misconfigured API key causes an `OpenAIError` with a 401 response.
2. The error object contains the request headers, including `Authorization: Bearer sk-...`.
3. `logger.exception` writes the full traceback to `pipeline.log`.
4. An attacker with read access to the output directory (e.g., another user on a shared server) reads the log file and extracts the API key.

## Impact

- **Secret exposure:** API keys or other sensitive data in log files.
- **No accountability:** Cannot prove what the LLM said vs. what the user claims.
- **Delayed incident response:** No alerts on anomalies; issues are only discovered by manual log review.

## Mitigation

1. **Sanitized logging:** Never log exception objects directly. Log only the exception type and a sanitized message. Use a custom formatter that strips known secret patterns.
2. **Audit log:** Create a separate `audit.log` with a structured format:
   ```json
   {"timestamp": "...", "event": "llm_call", "input_hash": "sha256:...", "output_hash": "sha256:...", "status": "success"}
   ```
3. **Tamper resistance:** Append-only, `0o600` permissions. Consider writing to a system log (syslog / macOS unified log) for tamper resistance.
4. **Alerting:** On schema validation failure or token budget breach, write an alert entry to `audit.log` and optionally print a warning to stderr.
5. **Secret scrubber:** Use a regex-based log filter to strip `sk-...`, `Bearer ...`, and other secret patterns before writing to disk.

## Mitigated Code

File: `mitigated/main.py`

Key changes:
- `_configure_file_logger()` uses a `SecretScrubbingFormatter` that redacts `Bearer sk-...`, `OPENAI_API_KEY=...`, etc.
- `logger.exception()` replaced with `logger.error("Pipeline failure: %s", type(exc).__name__, exc_info=False)`.
- `audit.log` created with structured JSON lines, `0o600` permissions.
- `_hash_payload()` computes SHA-256 of the LLM input and output for non-repudiation.

## Test

```bash
pytest tests/test_permissions.py -v
```

The test:
1. Creates a mock exception containing a fake API key.
2. Verifies the log file does NOT contain the key after the mitigated code handles it.
3. Verifies the audit.log contains the expected structured entry.
