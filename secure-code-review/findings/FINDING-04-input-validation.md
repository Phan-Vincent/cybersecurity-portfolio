# FINDING-04: Input Validation — Path Traversal & Weak File Checks

**Severity:** High  
**OWASP:** A03 — Injection  
**CWE:** CWE-22 (Path Traversal), CWE-73 (External Control of File Name)

---

## Summary

The ingestion module accepts arbitrary file paths via CLI arguments. The only validation is:
1. `file_path.exists()`
2. `file_path.suffix.lower() != ".csv"`

This is insufficient. An attacker can pass:
- `--nutrition /etc/passwd` (blocked by suffix check, but what about `/etc/passwd.csv`?)
- `--nutrition ../../.env.csv` (information disclosure if the file exists and ends in `.csv`)
- `--nutrition /tmp/symlink_to_secret.csv` (symlink bypass)
- A file with embedded null bytes after the suffix check: `file.csv\x00.exe` — the null byte is stripped by `sanitize_csv_row()`, but the **suffix check runs before** that, on the `Path` object, so this specific attack is blocked. However, symlink attacks and directory traversal are not.

## Vulnerable Code

File: `vulnerable/ingestion.py` (lines 48–60)

```python
def read_csv_safely(
    file_path: Path,
    expected_columns: list[str] | None = None,
) -> list[dict[str, Any]]:
    if not file_path.exists() or not file_path.is_file():
        raise IngestionError(f"CSV file not found: {file_path}")
    # Reject non-CSV extensions
    if file_path.suffix.lower() != ".csv":
        raise IngestionError("Only .csv files are allowed")
    # ...
```

## Attack Scenario

1. Attacker knows the application is running in a shared environment.
2. Attacker creates a symlink: `ln -s /home/victim/.env /tmp/nutrition.csv`
3. Runs: `python main.py --nutrition /tmp/nutrition.csv --training data/synthetic_training.csv`
4. The app reads the `.env` file because it resolves the symlink and the suffix is `.csv`.
5. The `.env` file contains `OPENAI_API_KEY=sk-...`. This is an information disclosure.

## Impact

- **Information disclosure:** Read arbitrary files on the system if they can be renamed to `.csv` or symlinked.
- **Data poisoning:** A symlink to a malicious CSV could inject prompt-injection payloads.
- **Lateral movement:** If the `.env` file contains other secrets, they are exposed.

## Mitigation

1. **Path resolution and allowlist:** Resolve the path to absolute, then check it is within an allowed base directory (e.g., the working directory or a `--data-dir` argument).
2. **Symlink check:** `os.path.islink()` or `Path.resolve()` vs `Path.absolute()` — if they differ, reject.
3. **File size limits:** Reject files > 10MB to prevent CSV bomb DoS.
4. **Row count limits:** Reject files with > 10,000 rows.
5. **Strict extension check:** `file_path.suffix.lower() == ".csv" and file_path.name.lower().endswith(".csv")` — prevents `file.csv.exe` (though the suffix check alone catches this).

## Mitigated Code

File: `mitigated/ingestion.py`

Key changes:
- `_validate_path()` resolves to absolute, checks `islink()`, and ensures the path is within the working directory.
- `_validate_file_size()` rejects files > 10MB.
- `_validate_row_count()` reads the first 10,001 lines to cap input size.

## Test

```bash
pytest tests/test_input_validation.py -v
```

The test:
1. Creates a symlink to a sensitive file and attempts to read it — mitigated code rejects it.
2. Attempts path traversal (`../../`) — rejected.
3. Attempts a 50MB CSV — rejected.
