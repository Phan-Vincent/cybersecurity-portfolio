# FINDING-07: Cost Overrun — Post-Hoc Token Budget

**Severity:** Medium  
**OWASP:** LLM06 — Excessive Agency  
**CWE:** CWE-770 (Allocation of Resources Without Limits), CWE-400 (Uncontrolled Resource Consumption)

---

## Summary

The application defines a token budget (`MAX_TOKEN_LIMIT = 2000`) but checks it **after** the API call completes. This is a **post-hoc** guard, not a **preventive** guard. The cost is already incurred.

Additionally, there is no `max_tokens` parameter passed to the API call. The LLM could generate an arbitrarily long response, consuming unlimited tokens and budget.

## Vulnerable Code

File: `vulnerable/llm_audit.py` (lines 115–125)

```python
    completion = client.responses.create(
        model=model_name,
        input=_build_prompt_messages(safe_payload),
        temperature=0,
        response_format={"type": "json_object"},
    )
    # ...
    usage = getattr(completion, "usage", None)
    input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
    output_tokens = int(getattr(usage, "output_tokens", 0) or 0)
    total_tokens = input_tokens + output_tokens

    # Check token budget
    if total_tokens > MAX_TOKEN_LIMIT:
        raise TokenBudgetExceededError(
            f"Token usage {total_tokens} exceeds limit {MAX_TOKEN_LIMIT}"
        )
```

## Attack Scenario

1. Attacker provides a CSV with 500 rows of legitimate-looking data.
2. The `processed_metrics` payload becomes very large (high input tokens).
3. The LLM generates a very long JSON response (high output tokens).
4. The API call succeeds. The user is charged for, say, 5,000 tokens.
5. **After** the call, the app raises `TokenBudgetExceededError`. The user has already paid.
6. If the attacker can repeatedly trigger this (e.g., via an automated script), the API bill grows indefinitely.

## Impact

- **Financial:** Unexpected API charges. At $0.005/1K input + $0.015/1K output, a 5,000 token call costs ~$0.10. A thousand calls = $100. An automated attack could cost hundreds or thousands.
- **Denial of service:** If the API key has a spending limit, the app stops working for legitimate users once the budget is exhausted.

## Mitigation

1. **Pre-flight estimation:** Count input tokens before the call (using `tiktoken` or a simple heuristic). If the estimated input exceeds a threshold, abort before sending.
2. **max_tokens parameter:** Pass `max_tokens=MAX_TOKEN_LIMIT` (or a reasonable subset) to the API call. This caps the output size.
3. **Hard input size limit:** Cap the number of CSV rows or the size of the processed metrics payload.
4. **Daily budget:** Track daily spend in a local file and abort if it exceeds a configurable limit.

## Mitigated Code

File: `mitigated/llm_audit.py`

Key changes:
- `_estimate_input_tokens()` uses `tiktoken` to count tokens before the API call.
- `max_tokens` is passed to `client.responses.create()`.
- `_check_daily_budget()` reads a local `daily_spend.json` and aborts if the daily limit is exceeded.
- `MAX_INPUT_TOKENS = 1500` and `MAX_OUTPUT_TOKENS = 500` are enforced separately.

## Test

```bash
pytest tests/test_cost_guards.py -v
```

The test:
1. Creates a payload that exceeds the input token limit and verifies the mitigated code aborts **before** the API call.
2. Verifies `max_tokens` is passed to the API call (mocked).
3. Verifies daily budget enforcement.
