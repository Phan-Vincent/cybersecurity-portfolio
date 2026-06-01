#!/usr/bin/env python3
"""Core credential hygiene audit engine.

Orchestrates password policy evaluation, breach detection, and cross-service
reuse analysis. Computes an overall risk score and produces a structured audit
result suitable for report generation.
"""

import hashlib
from datetime import datetime, timezone
from typing import Any

from policy import evaluate_password
from breach import check_weak_password, check_hibp_mock


def audit_credentials(
    credentials: list[dict[str, Any]], weak_hashes: set[str]
) -> dict[str, Any]:
    """Run a full credential hygiene audit on a list of credentials.

    For each credential, evaluates:
    - Password policy compliance (NIST 800-63B)
    - Breach status (local weak hash database + HIBP mock)
    - Password age

    Across all credentials, detects:
    - Cross-service password reuse
    - Overall risk posture

    Args:
        credentials: List of credential dicts with keys:
            username (str), password (str), service (str), last_changed (str).
        weak_hashes: Set of SHA-1 hex hashes of known weak passwords.

    Returns:
        A dictionary containing:
            - total_credentials (int)
            - per_credential_findings (list[dict])
            - reused_passwords (list[dict])
            - overall_risk_score (int): 0-100 (higher = more risk)
            - nist_compliance_summary (dict)
            - audit_timestamp (str): ISO 8601 timestamp
    """
    if not isinstance(credentials, list):
        raise TypeError("credentials must be a list")

    findings: list[dict[str, Any]] = []
    password_hash_map: dict[str, list[dict[str, str]]] = {}

    nist_compliant_count = 0
    total_breach_count = 0
    total_reuse_instances = 0
    total_score_sum = 0

    for cred in credentials:
        username = cred.get("username", "unknown")
        password = cred.get("password", "")
        service = cred.get("service", "unknown")
        last_changed = cred.get("last_changed", "")

        # Policy evaluation
        policy_result = evaluate_password(password)

        # Breach checks
        weak_check = check_weak_password(password, weak_hashes)
        hibp_result = check_hibp_mock(password)

        # Password age
        age_days = _calculate_age_days(last_changed)
        age_warning = age_days is not None and age_days > 365

        # Track for reuse detection
        pw_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if pw_hash not in password_hash_map:
            password_hash_map[pw_hash] = []
        password_hash_map[pw_hash].append({
            "username": username,
            "service": service,
        })

        # Update compliance counters
        if policy_result["nist_compliant"]:
            nist_compliant_count += 1
        if weak_check["breached"] or hibp_result["simulated_breach_count"] > 1000:
            total_breach_count += 1
        total_score_sum += policy_result["score"]

        cred_finding = {
            "username": username,
            "service": service,
            "last_changed": last_changed,
            "age_days": age_days,
            "age_warning": age_warning,
            "policy": policy_result,
            "weak_hash_check": weak_check,
            "hibp_check": hibp_result,
        }
        findings.append(cred_finding)

    # Reuse detection
    reused_passwords: list[dict[str, Any]] = []
    for pw_hash, services in password_hash_map.items():
        if len(services) > 1:
            total_reuse_instances += len(services)
            reused_passwords.append({
                "password_hash_prefix": pw_hash[:16],
                "services_affected": services,
                "reuse_count": len(services),
            })

    # Overall risk score: 0-100
    # Factors: weak passwords, breaches, reuse, NIST non-compliance, age
    total = len(credentials)
    if total == 0:
        overall_risk_score = 0
    else:
        weak_ratio = (total - nist_compliant_count) / total
        breach_ratio = total_breach_count / total
        reuse_ratio = total_reuse_instances / total if total > 0 else 0
        avg_score = total_score_sum / total  # 0-4
        score_factor = (4 - avg_score) / 4  # invert so lower score = higher risk

        # Weighted risk calculation
        overall_risk_score = int(
            (weak_ratio * 25)
            + (breach_ratio * 30)
            + (reuse_ratio * 25)
            + (score_factor * 20)
        )
        overall_risk_score = min(100, max(0, overall_risk_score))

    nist_compliance_summary = {
        "total_credentials": total,
        "nist_compliant": nist_compliant_count,
        "nist_non_compliant": total - nist_compliant_count,
        "compliance_rate_percent": round((nist_compliant_count / total) * 100, 1) if total else 0,
        "nist_standard": "NIST SP 800-63B (Digital Identity Guidelines)",
    }

    return {
        "total_credentials": total,
        "per_credential_findings": findings,
        "reused_passwords": reused_passwords,
        "overall_risk_score": overall_risk_score,
        "nist_compliance_summary": nist_compliance_summary,
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _calculate_age_days(last_changed: str) -> int | None:
    """Calculate the number of days since the password was last changed.

    Args:
        last_changed: Date string in YYYY-MM-DD format.

    Returns:
        Number of days since last change, or None if parsing fails.
    """
    if not last_changed:
        return None

    try:
        changed_date = datetime.strptime(last_changed, "%Y-%m-%d")
        changed_date = changed_date.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return (now - changed_date).days
    except ValueError:
        return None
