# Threat Model — The Assessment Toolkit Itself

A gap assessment concentrates exactly the information an attacker wants: a ranked list of an organization's weakest controls, who owns them, and when they will (or will not) be fixed. This document treats the toolkit and its outputs as a sensitive system in their own right.

## Assets

| Asset | Why it matters |
|-------|----------------|
| Completed assessment CSV | Describes real control weaknesses; equivalent to a vulnerability report |
| Generated roadmap / risk register | Ranked attack plan if leaked; names accountable staff |
| Controls catalog (`controls/`) | Integrity matters — a tampered catalog silently changes every score |
| Assessor workstation | Where the above are created and stored |

## Threats (STRIDE)

| STRIDE | Threat | Mitigation in this toolkit |
|--------|--------|----------------------------|
| **S**poofing | Someone submits a doctored assessment to make the org look compliant | Out of scope for code; reports carry the source filename and as-of date so reviewers can trace provenance |
| **T**ampering | Edited catalog lowers PHI exposure ratings to shrink scores | Catalog lives in Git (history is the audit trail); `tests/test_docs.py` and catalog tests fail if fields go missing or drift from the published reference |
| **T**ampering | Spreadsheet formula injection via free-text cells (`=HYPERLINK(...)`) when the register is opened in Excel | `score_assessment.py` prefixes cells starting with `= + - @` with `'` before writing CSV |
| **R**epudiation | Owner claims a gap was never assigned | Register records owner, target date, and an overdue flag; unassigned gaps are reported as warnings |
| **I**nformation disclosure | Assessment or report committed to a public repo | `output/` and `reports/` are git-ignored; only synthetic sample data is committed; README warns never to populate with production data |
| **I**nformation disclosure | Real PHI pasted into `finding_notes` | Assessment template asks for control evidence, not patient data; reviewers should reject notes containing identifiers |
| **D**enial of service | Huge or malformed CSV hangs the scorer | 5 MB input cap; strict validation (unknown/duplicate control IDs, invalid statuses, out-of-range overrides) fails fast with a clear error |
| **E**levation of privilege | Script run with more access than needed | Pure local file I/O: no network calls, no credentials, no shell execution; runs as an unprivileged user |

## Data Handling Rules

1. **Synthetic only in this repository.** `data/sample_pharmacy_assessment.csv` describes a fictional pharmacy.
2. **Real assessments stay off shared drives and out of Git.** Store them encrypted (FileVault/BitLocker) with access limited to the Security Officer and assessor.
3. **Minimum necessary.** Findings describe control gaps, never individual patients.
4. **Retention.** HIPAA requires security documentation to be retained for six years (§164.316(b)(2)(i)); delete working copies once the final report is filed.

## Known Limitations

- No digital signing of reports; integrity relies on Git history and process.
- Single-assessor model: no RBAC or approval workflow.
- Scores are a prioritization aid, not a substitute for the documented risk analysis required by §164.308(a)(1)(ii)(A).
