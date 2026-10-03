"""
AWS IAM Least-Privilege Auditor - Report Generation

Renders the consolidated list of `Finding` objects produced by `auditor.py`
into the three output formats supported by the CLI (see `scripts/run_audit.py`):

  * Console - color-coded, human-readable report for someone reading a terminal
  * JSON    - machine-readable, for CI/CD gating and SIEM/ticket ingestion
  * CSV     - spreadsheet-friendly, for triage in Excel/Sheets

Design notes:

  * Every formatter is a pure function of the findings list. Findings are
    always ordered most-severe-first, so a reader sees the critical issues
    before the informational ones regardless of which check produced them.
  * Output is deterministic: no timestamps, no random ordering, no network
    calls. That keeps `--mock` mode reproducible for regression tests and
    demo screenshots, and matches the "synthetic data only" safety posture
    documented in THREAT_MODEL.md.
  * Nothing here ever writes to AWS - the tool is audit-only.
"""

import csv
import io
import json
import sys
from typing import Any, Iterable

from .checks import Finding, SEVERITY_ORDER


__all__ = [
    "generate_console_report",
    "generate_json_report",
    "generate_csv_report",
    "write_json_report",
    "write_csv_report",
]


# Header text asserted on by tests and used as the console banner.
TITLE = "AWS IAM LEAST-PRIVILEGE AUDIT REPORT"

# Fixed CSV header - stable column order matters to downstream spreadsheet
# formulas and to anyone diffing two CSV reports.
CSV_COLUMNS = [
    "severity",
    "check_id",
    "resource_type",
    "resource_name",
    "message",
    "remediation",
]

_RULE_WIDTH = 78
_MAX_DETAILS_WIDTH = 160

_RESET = "\033[0m"
_SEVERITY_COLORS = {
    "critical": "\033[1;31m",  # bold red
    "high": "\033[31m",  # red
    "medium": "\033[33m",  # yellow
    "low": "\033[36m",  # cyan
    "info": "\033[37m",  # white
}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _get(finding: Any, attribute: str) -> Any:
    """Read an attribute from a Finding (or a dict with the same shape)."""
    if isinstance(finding, dict):
        return finding.get(attribute)
    return getattr(finding, attribute, None)


def _severity(finding: Any) -> str:
    """Return the finding's severity, lowercased, or 'unknown' if absent."""
    severity = _get(finding, "severity")
    return str(severity).strip().lower() if severity else "unknown"


def _severity_rank(finding: Any) -> int:
    """Sort key: higher rank == more severe == printed first."""
    return SEVERITY_ORDER.get(_severity(finding), -1)


def _sorted_findings(findings: Iterable[Any]) -> list[Any]:
    """Order findings most-severe-first (stable within a severity level)."""
    return sorted(findings, key=_severity_rank, reverse=True)


def _to_dict(finding: Any) -> dict:
    """Normalize a finding to a plain dict for JSON serialization."""
    if isinstance(finding, dict):
        return dict(finding)
    return {
        "check_id": _get(finding, "check_id"),
        "severity": _severity(finding),
        "resource_type": _get(finding, "resource_type"),
        "resource_name": _get(finding, "resource_name"),
        "message": _get(finding, "message"),
        "details": _get(finding, "details"),
        "remediation": _get(finding, "remediation"),
    }


def _build_summary(findings: list[Any]) -> dict:
    """Build the summary block shared by the JSON and console reports."""
    breakdown = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        severity = _severity(finding)
        breakdown[severity] = breakdown.get(severity, 0) + 1

    return {
        "total_findings": len(findings),
        "severity_breakdown": breakdown,
    }


def _colorize(text: str, severity: str, use_color: bool) -> str:
    """Wrap text in the ANSI color for a severity, when color is enabled."""
    if not use_color:
        return text
    color = _SEVERITY_COLORS.get(severity)
    return f"{color}{text}{_RESET}" if color else text


def _format_details(details: Any, max_width: int = _MAX_DETAILS_WIDTH) -> str:
    """Render a finding's details dict as a single compact `key=value` line.

    Scalars print inline; nested structures (policy statements, attached
    policy lists) are rendered as compact JSON and truncated so one verbose
    finding cannot swamp the console. The untruncated form is always
    available in the JSON report.
    """
    if not isinstance(details, dict) or not details:
        return ""

    parts = []
    for key, value in details.items():
        if value is None or isinstance(value, (str, int, float, bool)):
            parts.append(f"{key}={value}")
        else:
            rendered = json.dumps(value, sort_keys=True, separators=(",", ":"))
            parts.append(f"{key}={rendered}")

    line = ", ".join(parts)
    if len(line) > max_width:
        line = line[: max_width - 1] + "…"
    return line


# ── Console report ────────────────────────────────────────────────────────────

def generate_console_report(
    findings: Iterable[Finding],
    output=None,
    use_color: bool = True,
) -> None:
    """Write a human-readable audit report to `output` (default: stdout).

    Args:
        findings: Findings returned by `Auditor.run_audit()`.
        output: Any file-like object with `write()`; defaults to stdout.
        use_color: When False, emit plain ASCII (for log ingestion systems).
    """
    stream = output if output is not None else sys.stdout
    findings = list(findings)
    summary = _build_summary(findings)

    def emit(line: str = "") -> None:
        print(line, file=stream)

    emit("=" * _RULE_WIDTH)
    emit(TITLE.center(_RULE_WIDTH))
    emit("=" * _RULE_WIDTH)

    if not findings:
        emit()
        emit("No findings detected.")
        emit("Your IAM posture looks clean — no wildcard actions, stale access")
        emit("keys, missing MFA, or over-permissioned roles were found.")
        emit()
        emit(f"Total findings: {summary['total_findings']}")
        emit("=" * _RULE_WIDTH)
        return

    emit()
    emit(f"Total findings: {summary['total_findings']}")
    emit()
    emit("Severity breakdown:")
    for severity, count in summary["severity_breakdown"].items():
        label = _colorize(f"{severity.upper():<10}", severity, use_color)
        emit(f"  {label} {count}")

    for index, finding in enumerate(_sorted_findings(findings), start=1):
        severity = _severity(finding)
        resource_type = _get(finding, "resource_type")
        resource_name = _get(finding, "resource_name")
        check_id = _get(finding, "check_id")

        emit()
        emit("-" * _RULE_WIDTH)
        heading = f"[{index}] {severity.upper()} — {check_id} ({resource_type}/{resource_name})"
        emit(_colorize(heading, severity, use_color))
        emit("-" * _RULE_WIDTH)
        emit(f"  Message     : {_get(finding, 'message')}")

        details = _format_details(_get(finding, "details"))
        if details:
            emit(f"  Details     : {details}")

        emit(f"  Remediation : {_get(finding, 'remediation')}")

    emit()
    emit("=" * _RULE_WIDTH)
    emit(f"Total findings: {summary['total_findings']}")
    emit("=" * _RULE_WIDTH)


# ── JSON report ───────────────────────────────────────────────────────────────

def generate_json_report(findings: Iterable[Finding], pretty: bool = True) -> str:
    """Return the audit report as a JSON string.

    The payload is `{"summary": {...}, "findings": [...]}` so consumers can
    gate on `summary.severity_breakdown.critical` without walking the array.
    """
    findings = list(findings)
    payload = {
        "summary": _build_summary(findings),
        "findings": [_to_dict(finding) for finding in _sorted_findings(findings)],
    }

    if pretty:
        return json.dumps(payload, indent=2)
    return json.dumps(payload, separators=(",", ":"))


def write_json_report(findings: Iterable[Finding], path, pretty: bool = True) -> str:
    """Write the JSON report to `path`. Returns the path as a string."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(generate_json_report(findings, pretty=pretty))
        handle.write("\n")
    return str(path)


# ── CSV report ────────────────────────────────────────────────────────────────

def generate_csv_report(findings: Iterable[Finding]) -> str:
    """Return the audit report as CSV text (header row always present)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)

    for finding in _sorted_findings(list(findings)):
        writer.writerow([
            _severity(finding),
            _get(finding, "check_id"),
            _get(finding, "resource_type"),
            _get(finding, "resource_name"),
            _get(finding, "message"),
            _get(finding, "remediation"),
        ])

    return buffer.getvalue()


def write_csv_report(findings: Iterable[Finding], path) -> str:
    """Write the CSV report to `path`. Returns the path as a string."""
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(generate_csv_report(findings))
    return str(path)
