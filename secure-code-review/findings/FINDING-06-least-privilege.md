# FINDING-06: Least Privilege — File Permissions & Secret Storage

**Severity:** Medium  
**OWASP:** A01 — Broken Access Control  
**CWE:** CWE-276 (Incorrect Default Permissions), CWE-732 (Incorrect Permission Assignment)

---

## Summary

The application creates `token_usage.log` with explicit `0o600` permissions (good). However:

1. **Output directory:** `output_dir.mkdir(parents=True, exist_ok=True)` creates directories with default permissions (typically `0o755` on macOS/Linux). Other users can list the directory contents.
2. **`.env` file:** The application loads secrets from `.env` but never checks its permissions. If `.env` is `0o644`, any user on the system can read the API key.
3. **Report files:** `write_json_report()` and `write_pdf_report()` (in `report.py`) create files with default permissions. No explicit `chmod` is applied.
4. **No key validation:** The API key is loaded with `os.getenv("OPENAI_API_KEY")` but there is no check that the key is a well-formed secret (e.g., starts with `sk-`, minimum length). A misconfigured key could be a password or other non-secret string.

## Vulnerable Code

File: `vulnerable/main.py` (lines 55–62)

```python
def _log_token_usage(output_dir: Path, token_usage: dict[str, int | float]) -> None:
    usage_file = output_dir / "token_usage.log"
    serialized = json.dumps(token_usage, ensure_ascii=False)
    usage_file.parent.mkdir(parents=True, exist_ok=True)

    if not usage_file.exists():
        fd = os.open(str(usage_file), os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        os.close(fd)
    with usage_file.open("a", encoding="utf-8") as handle:
        handle.write(serialized + "\n")
```

File: `vulnerable/llm_audit.py` (lines 95–100)

```python
def generate_audit(processed_metrics: dict[str, Any]) -> dict[str, Any]:
    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY")
    model_name = os.getenv("LLM_MODEL", "gpt-4o-mini")

    if not api_key:
        raise LLMAuditError("OPENAI_API_KEY is not configured")
```

## Impact

- **Information disclosure:** Other users on the machine can read the API key or audit reports.
- **Secret theft:** If the machine is compromised, the attacker has immediate access to a valid API key.
- **Compliance:** Fails basic security hygiene expectations for a health-data application.

## Mitigation

1. **`.env` permission check:** On startup, check `.env` permissions. If world-readable or group-readable, warn or abort:
   ```python
   if os.stat(".env").st_mode & 0o077:
       raise SecurityError(".env file is readable by others. Run: chmod 600 .env")
   ```
2. **Output directory permissions:** Set `output_dir.mkdir(..., mode=0o700)` or validate existing directory permissions.
3. **Report file permissions:** Apply `0o600` to all generated files (PDF, JSON, log).
4. **Key format validation:** Ensure the API key matches the expected prefix and length for the provider.
5. **Umask:** Set a restrictive umask (`0o077`) at application startup.

## Mitigated Code

File: `mitigated/main.py` and `mitigated/llm_audit.py`

Key changes:
- `_check_env_permissions()` called in `main()` before any processing.
- `_secure_makedirs()` creates directories with `0o700`.
- `write_json_report()` and `write_pdf_report()` set `0o600` on output files.
- `_validate_api_key_format()` checks `sk-` prefix and length.

## Test

```bash
pytest tests/test_permissions.py -v
```

The test:
1. Creates a `.env` file with `0o644` permissions and verifies the mitigated code aborts with a security error.
2. Verifies output directories are created with `0o700`.
3. Verifies report files are `0o600`.
