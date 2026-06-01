"""
Unit tests for AWS IAM Least-Privilege Auditor - Report Generation

Tests JSON, CSV, and console output formatting.
"""

from io import StringIO

from aws_iam_auditor.checks import Finding
from aws_iam_auditor.report import (
    generate_console_report,
    generate_json_report,
    generate_csv_report,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

def _sample_findings():
    """Return a small list of sample findings for testing."""
    return [
        Finding(
            check_id="wildcard_actions",
            severity="critical",
            resource_type="policy",
            resource_name="AdminPolicy",
            message="Policy grants unrestricted access.",
            details={"policy_arn": "arn:aws:iam::123:policy/AdminPolicy", "action": "*"},
            remediation="Scope to specific actions.",
        ),
        Finding(
            check_id="users_without_mfa",
            severity="high",
            resource_type="user",
            resource_name="alice",
            message="User has no MFA.",
            details={"username": "alice"},
            remediation="Enable MFA.",
        ),
    ]


# ── Test: Console Output ─────────────────────────────────────────────────────

def test_console_report_basic():
    """Console report should include finding details and summary."""
    findings = _sample_findings()
    buf = StringIO()
    generate_console_report(findings, output=buf, use_color=False)
    output = buf.getvalue()

    assert "AWS IAM LEAST-PRIVILEGE AUDIT REPORT" in output
    assert "Total findings: 2" in output
    assert "CRITICAL" in output
    assert "HIGH" in output
    assert "AdminPolicy" in output
    assert "alice" in output
    assert "Scope to specific actions." in output
    assert "Enable MFA." in output


def test_console_report_empty():
    """Console report with no findings should show a clean message."""
    buf = StringIO()
    generate_console_report([], output=buf, use_color=False)
    output = buf.getvalue()

    assert "No findings detected" in output
    assert "Your IAM posture looks clean" in output


# ── Test: JSON Output ────────────────────────────────────────────────────────

def test_json_report_structure():
    """JSON report should contain summary and findings array."""
    findings = _sample_findings()
    json_str = generate_json_report(findings, pretty=True)

    import json
    data = json.loads(json_str)

    assert "summary" in data
    assert "findings" in data
    assert data["summary"]["total_findings"] == 2
    assert data["summary"]["severity_breakdown"]["critical"] == 1
    assert data["summary"]["severity_breakdown"]["high"] == 1
    assert len(data["findings"]) == 2

    # Verify first finding structure
    f0 = data["findings"][0]
    assert f0["check_id"] == "wildcard_actions"
    assert f0["severity"] == "critical"
    assert f0["resource_type"] == "policy"
    assert f0["resource_name"] == "AdminPolicy"
    assert "remediation" in f0
    assert "details" in f0


def test_json_report_empty():
    """JSON report with no findings should still have valid structure."""
    json_str = generate_json_report([], pretty=True)
    import json
    data = json.loads(json_str)

    assert data["summary"]["total_findings"] == 0
    assert data["findings"] == []


# ── Test: CSV Output ───────────────────────────────────────────────────────────

def test_csv_report_basic():
    """CSV report should have header and one row per finding."""
    findings = _sample_findings()
    csv_str = generate_csv_report(findings)
    lines = [line.strip() for line in csv_str.strip().splitlines()]

    assert len(lines) == 3  # header + 2 data rows
    assert lines[0] == "severity,check_id,resource_type,resource_name,message,remediation"
    assert "critical" in lines[1]
    assert "high" in lines[2]
    assert "AdminPolicy" in lines[1]
    assert "alice" in lines[2]


def test_csv_report_empty():
    """CSV report with no findings should still have a header."""
    csv_str = generate_csv_report([])
    lines = csv_str.strip().split("\n")

    assert len(lines) == 1
    assert "severity" in lines[0]
