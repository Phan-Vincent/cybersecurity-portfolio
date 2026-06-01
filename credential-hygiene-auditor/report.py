#!/usr/bin/env python3
"""Report generator for credential hygiene audits.

Produces human-readable Markdown reports and machine-parseable JSON reports
from structured audit results.
"""

import json
from typing import Any


def generate_markdown_report(result: dict[str, Any]) -> str:
    """Generate a Markdown-formatted audit report.

    Args:
        result: The audit result dictionary from auditor.audit_credentials().

    Returns:
        A Markdown string containing the full audit report.
    """
    lines: list[str] = []

    lines.append("# Credential Hygiene Audit Report")
    lines.append("")
    lines.append(f"**Audit Timestamp:** {result['audit_timestamp']}")
    lines.append(f"**Total Credentials Audited:** {result['total_credentials']}")
    lines.append("")

    # Overall Risk Score
    score = result["overall_risk_score"]
    risk_label = _risk_label(score)
    lines.append(f"## Overall Risk Score: {score}/100 ({risk_label})")
    lines.append("")
    lines.append(_risk_description(score))
    lines.append("")

    # NIST Compliance Summary
    nist = result["nist_compliance_summary"]
    lines.append("## NIST SP 800-63B Compliance Summary")
    lines.append("")
    lines.append(f"- **Standard:** {nist['nist_standard']}")
    lines.append(f"- **Compliant:** {nist['nist_compliant']} / {nist['total_credentials']}")
    lines.append(f"- **Non-Compliant:** {nist['nist_non_compliant']}")
    lines.append(f"- **Compliance Rate:** {nist['compliance_rate_percent']}%")
    lines.append("")

    # Reuse Table
    lines.append("## Password Reuse Detection")
    lines.append("")
    if result["reused_passwords"]:
        lines.append("| Password Hash Prefix | Reuse Count | Affected Services |")
        lines.append("| --- | --- | --- |")
        for reuse in result["reused_passwords"]:
            services = ", ".join(
                f"{s['username']}@{s['service']}" for s in reuse["services_affected"]
            )
            lines.append(
                f"| `{reuse['password_hash_prefix']}...` | {reuse['reuse_count']} | {services} |"
            )
        lines.append("")
        lines.append(
            f"**⚠️ Found {len(result['reused_passwords'])} reused password(s) across "
            f"{sum(r['reuse_count'] for r in result['reused_passwords'])} service accounts.**"
        )
    else:
        lines.append("✅ No password reuse detected across services.")
    lines.append("")

    # Per-Credential Findings
    lines.append("## Per-Credential Findings")
    lines.append("")
    for finding in result["per_credential_findings"]:
        username = finding["username"]
        service = finding["service"]
        policy = finding["policy"]
        weak = finding["weak_hash_check"]
        hibp = finding["hibp_check"]
        age = finding["age_days"]
        age_warn = finding["age_warning"]

        lines.append(f"### {username} @ {service}")
        lines.append("")
        lines.append(f"- **Last Changed:** {finding['last_changed'] or 'unknown'} ({age} days ago)")
        lines.append(f"- **NIST Compliant:** {'✅ Yes' if policy['nist_compliant'] else '❌ No'}")
        lines.append(f"- **Strength Score:** {policy['score']}/4")
        lines.append(f"- **Entropy:** {policy['entropy_bits']} bits")
        lines.append(f"- **Length:** {'✅ 8+' if policy['length_ok'] else '❌ <8'} ({'12+ recommended ✅' if policy['length_recommended'] else 'consider 12+ ❌'})")
        lines.append(f"- **Character Variety:** upper={policy['has_upper']} lower={policy['has_lower']} digit={policy['has_digit']} special={policy['has_special']}")
        lines.append("")

        if weak["breached"]:
            lines.append(f"- **🚨 Local Breach Check:** FAILED — {weak['reason']}")
        else:
            lines.append(f"- **Local Breach Check:** Passed — {weak['reason']}")

        lines.append(
            f"- **HIBP Mock Check:** Simulated breach count = {hibp['simulated_breach_count']:,}"
        )
        if age_warn:
            lines.append(f"- **⚠️ Age Warning:** Password is over 1 year old. Consider rotation.")
        lines.append("")

        if policy["feedback"]:
            lines.append("**Feedback:**")
            for fb in policy["feedback"]:
                lines.append(f"- {fb}")
            lines.append("")

    # Footer
    lines.append("---")
    lines.append("")
    lines.append(
        "*This report was generated using synthetic data for demonstration purposes. "
        "No real credentials were used in this audit.*"
    )
    lines.append("")
    lines.append(
        "*HIBP k-anonymity API: In production, integrate with "
        "https://api.pwnedpasswords.com/range/{prefix} for real breach data.*"
    )
    lines.append("")

    return "\n".join(lines)


def generate_json_report(result: dict[str, Any]) -> str:
    """Generate a JSON-formatted audit report.

    Args:
        result: The audit result dictionary from auditor.audit_credentials().

    Returns:
        A pretty-printed JSON string.
    """
    return json.dumps(result, indent=2, default=str)


def save_report(content: str, path: str) -> None:
    """Save a report string to a file.

    Args:
        content: The report content to write.
        path: The file path to write to.

    Raises:
        OSError: If the file cannot be written.
    """
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _risk_label(score: int) -> str:
    """Return a risk label for a given score.

    Args:
        score: Risk score from 0-100.

    Returns:
        A human-readable risk label.
    """
    if score < 20:
        return "Low Risk"
    if score < 40:
        return "Moderate Risk"
    if score < 60:
        return "Elevated Risk"
    if score < 80:
        return "High Risk"
    return "Critical Risk"


def _risk_description(score: int) -> str:
    """Return a risk description for a given score.

    Args:
        score: Risk score from 0-100.

    Returns:
        A human-readable risk description paragraph.
    """
    if score < 20:
        return (
            "The overall credential posture is strong. Most passwords meet NIST guidelines, "
            "show no signs of breach exposure, and are not reused across services."
        )
    if score < 40:
        return (
            "Some credentials have minor weaknesses. A few passwords may be approaching age limits "
            "or have moderate entropy. Review feedback for improvement opportunities."
        )
    if score < 60:
        return (
            "Multiple credentials show significant weaknesses. Password reuse, weak passwords, "
            "or breach exposure has been detected. Immediate remediation is recommended."
        )
    if score < 80:
        return (
            "The credential posture is poor. Several passwords are weak, breached, or reused "
            "across multiple services. Prioritize password changes and enable MFA where possible."
        )
    return (
        "CRITICAL: The majority of credentials are severely compromised. Widespread password reuse, "
        "known weak passwords, and/or confirmed breach exposure detected. Immediate action required."
    )
