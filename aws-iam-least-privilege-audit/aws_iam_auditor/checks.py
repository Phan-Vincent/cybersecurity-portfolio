"""
AWS IAM Least-Privilege Auditor - Core Checks

Implements four security checks:
  1. Wildcard actions in IAM policies (overly permissive permissions)
  2. Unused access keys (stale credentials that increase attack surface)
  3. Users without MFA enabled (weak authentication posture)
  4. Over-permissioned roles (roles with broad trust policies or excessive policy attachments)

Each check returns a list of Finding objects with severity scoring and
remediation guidance.
"""

from datetime import datetime, timezone
from typing import Any


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class Finding:
    """Represents a single security finding from an IAM audit check."""

    def __init__(
        self,
        check_id: str,
        severity: str,
        resource_type: str,
        resource_name: str,
        message: str,
        details: dict,
        remediation: str,
    ):
        self.check_id = check_id
        self.severity = severity
        self.resource_type = resource_type
        self.resource_name = resource_name
        self.message = message
        self.details = details
        self.remediation = remediation

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "message": self.message,
            "details": self.details,
            "remediation": self.remediation,
        }


# ── Check 1: Wildcard Actions in Policies ─────────────────────────────────────

def check_wildcard_actions(policies: list[dict]) -> list[Finding]:
    """
    Scans IAM policy documents for overly permissive wildcard actions.

    Flags:
      - "*" (all actions across all services) — CRITICAL
      - "service:*" (all actions within a service) — HIGH

    In healthcare environments (HIPAA), wildcard permissions are especially
    dangerous because they can grant unintended access to PHI-containing
    resources (S3 buckets with patient data, DynamoDB tables with health records).
    """
    findings = []

    for policy in policies:
        policy_name = policy.get("PolicyName", "unknown")
        policy_arn = policy.get("Arn", "inline")
        doc = policy.get("PolicyDocument", {})

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            for action in actions:
                action = action.strip()
                if action == "*":
                    findings.append(
                        Finding(
                            check_id="wildcard_actions",
                            severity="critical",
                            resource_type="policy",
                            resource_name=policy_name,
                            message=(
                                f"Policy '{policy_name}' grants unrestricted access "
                                f"with Action='*' (all actions, all services)."
                            ),
                            details={
                                "policy_arn": policy_arn,
                                "action": action,
                                "statement": stmt,
                            },
                            remediation=(
                                "Replace '*' with explicit actions required for each "
                                "principal's job function. Use AWS managed job-function "
                                "policies as a starting point, then scope down to specific "
                                "resource ARNs with Condition keys where possible."
                            ),
                        )
                    )
                elif action.endswith(":*") and ":*" in action:
                    # e.g., "s3:*", "dynamodb:*"
                    service = action.split(":")[0]
                    findings.append(
                        Finding(
                            check_id="wildcard_actions",
                            severity="high",
                            resource_type="policy",
                            resource_name=policy_name,
                            message=(
                                f"Policy '{policy_name}' grants all actions in the "
                                f"'{service}' service ('{action}')."
                            ),
                            details={
                                "policy_arn": policy_arn,
                                "action": action,
                                "service": service,
                                "statement": stmt,
                            },
                            remediation=(
                                f"Scope '{action}' to specific {service.upper()} actions "
                                f"required by the workload (e.g., 's3:GetObject', "
                                f"'s3:PutObject'). Avoid service-level wildcards in "
                                f"production, especially for services storing PHI or PII."
                            ),
                        )
                    )

    return findings


# ── Check 2: Unused Access Keys ───────────────────────────────────────────────

def check_unused_access_keys(users: list[dict], access_keys: list[dict]) -> list[Finding]:
    """
    Identifies IAM access keys that have been unused for >90 days.

    Stale credentials are a major attack vector — if a key is compromised
    but never monitored, an attacker can persist undetected. In HIPAA
    environments, unused keys represent an unnecessary exposure of
    credentials that could access ePHI.
    """
    findings = []
    now = datetime.now(timezone.utc)
    STALE_DAYS = 90

    # Build a lookup: username -> list of keys
    user_keys: dict[str, list[dict]] = {}
    for key in access_keys:
        username = key.get("UserName", "unknown")
        user_keys.setdefault(username, []).append(key)

    for user in users:
        username = user.get("UserName", "unknown")
        keys = user_keys.get(username, [])

        for key in keys:
            key_id = key.get("AccessKeyId", "unknown")
            create_date_str = key.get("CreateDate")
            if not create_date_str:
                continue

            try:
                create_date = datetime.fromisoformat(create_date_str.replace("Z", "+00:00"))
            except ValueError:
                continue

            age_days = (now - create_date).days
            if age_days < STALE_DAYS:
                continue

            last_used = key.get("LastUsed", {})
            last_used_date_str = last_used.get("LastUsedDate")
            last_used_service = last_used.get("ServiceName", "N/A")
            last_used_region = last_used.get("Region", "N/A")

            if last_used_date_str:
                try:
                    last_used_date = datetime.fromisoformat(
                        last_used_date_str.replace("Z", "+00:00")
                    )
                    unused_days = (now - last_used_date).days
                except ValueError:
                    unused_days = age_days
            else:
                unused_days = age_days

            if unused_days > STALE_DAYS:
                severity = "critical" if unused_days > 180 else "high"
                findings.append(
                    Finding(
                        check_id="unused_access_keys",
                        severity=severity,
                        resource_type="access_key",
                        resource_name=key_id,
                        message=(
                            f"Access key '{key_id}' for user '{username}' has been "
                            f"unused for {unused_days} days (created {age_days} days ago)."
                        ),
                        details={
                            "username": username,
                            "key_id": key_id,
                            "age_days": age_days,
                            "unused_days": unused_days,
                            "last_used_date": last_used_date_str,
                            "last_used_service": last_used_service,
                            "last_used_region": last_used_region,
                            "status": key.get("Status", "unknown"),
                        },
                        remediation=(
                            "Deactivate and delete the access key if no longer needed. "
                            "Rotate keys every 90 days maximum. For long-lived service "
                            "accounts, consider IAM Roles with temporary credentials "
                            "(STS) instead. Enable CloudTrail logging to monitor key usage."
                        ),
                    )
                )

    return findings


# ── Check 3: Users Without MFA ──────────────────────────────────────────────────

def check_users_without_mfa(users: list[dict], mfa_devices: list[dict]) -> list[Finding]:
    """
    Identifies IAM users who do not have any MFA device enabled.

    Password-only authentication is a single point of failure. In a healthcare
    SOC context, a compromised developer or admin password without MFA could
    lead to unauthorized PHI access, triggering a reportable breach under HIPAA.
    """
    findings = []

    # Build set of users with MFA
    users_with_mfa = set()
    for device in mfa_devices:
        user = device.get("UserName")
        if user:
            users_with_mfa.add(user)

    for user in users:
        username = user.get("UserName", "unknown")
        if username in users_with_mfa:
            continue

        # Root user (if detected) is always critical; regular users are high
        user_type = user.get("UserType", "regular")
        severity = "critical" if user_type == "root" or "root" in username.lower() else "high"

        findings.append(
            Finding(
                check_id="users_without_mfa",
                severity=severity,
                resource_type="user",
                resource_name=username,
                message=(
                    f"User '{username}' does not have MFA enabled. "
                    f"Password-only authentication is vulnerable to phishing and credential stuffing."
                ),
                details={
                    "username": username,
                    "user_type": user_type,
                    "create_date": user.get("CreateDate"),
                    "password_last_used": user.get("PasswordLastUsed"),
                },
                remediation=(
                    "Enforce MFA via IAM policy condition 'aws:MultiFactorAuthPresent': true. "
                    "Require virtual MFA (TOTP) or hardware MFA (YubiKey) for all "
                    "human users. For service accounts, use IAM Roles with STS instead "
                    "of long-term access keys. Consider AWS IAM Identity Center (SSO) "
                    "with MFA enforcement at the identity provider level."
                ),
            )
        )

    return findings


# ── Check 4: Over-Permissioned Roles ──────────────────────────────────────────

def check_over_permissioned_roles(roles: list[dict]) -> list[Finding]:
    """
    Identifies IAM roles with overly broad trust policies or excessive
    attached policies.

    Flags:
      - Trust policy with Principal = "*" (or overly broad AWS account "*")
      - Trust policy with no external ID for cross-account access
      - Roles with >5 attached policies (policy bloat indicator)
      - Roles with trust policy allowing any AWS service without conditions

    In multi-tenant or healthcare environments, a role with a broad trust
    policy could allow an attacker in a compromised account to assume the role
    and access PHI, or allow an unintended AWS service to escalate privileges.
    """
    findings = []
    MAX_POLICIES = 5

    for role in roles:
        role_name = role.get("RoleName", "unknown")
        role_arn = role.get("Arn", "unknown")
        trust_policy = role.get("AssumeRolePolicyDocument", {})
        attached_policies = role.get("AttachedPolicies", [])
        attached_count = len(attached_policies)

        statements = trust_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue

            principal = stmt.get("Principal", {})
            action = stmt.get("Action", "")
            if isinstance(action, list):
                action = ", ".join(action)

            # Check for overly broad principal
            if isinstance(principal, str) and principal == "*":
                findings.append(
                    Finding(
                        check_id="over_permissioned_roles",
                        severity="critical",
                        resource_type="role",
                        resource_name=role_name,
                        message=(
                            f"Role '{role_name}' has a trust policy with Principal='*' — "
                            f"any AWS principal (including outside your organization) can assume this role."
                        ),
                        details={
                            "role_arn": role_arn,
                            "statement": stmt,
                            "attached_policy_count": attached_count,
                        },
                        remediation=(
                            "Replace Principal='*' with specific AWS account IDs, IAM user/role "
                            "ARNs, or AWS service principals (e.g., 'lambda.amazonaws.com'). "
                            "For cross-account access, require ExternalId in the Condition block. "
                            "Enable AWS CloudTrail to log all AssumeRole calls."
                        ),
                    )
                )
            elif isinstance(principal, dict):
                aws_principal = principal.get("AWS", "")
                if isinstance(aws_principal, list):
                    aws_principal = ", ".join(aws_principal)
                if aws_principal == "*":
                    findings.append(
                        Finding(
                            check_id="over_permissioned_roles",
                            severity="critical",
                            resource_type="role",
                            resource_name=role_name,
                            message=(
                                f"Role '{role_name}' has a trust policy with Principal.AWS='*' — "
                                f"any AWS account can assume this role."
                            ),
                            details={
                                "role_arn": role_arn,
                                "statement": stmt,
                                "attached_policy_count": attached_count,
                            },
                            remediation=(
                                "Restrict Principal.AWS to specific account IDs or role ARNs. "
                                "Add ExternalId condition for third-party integrations. "
                                "Consider AWS Organizations SCPs to block cross-account role "
                                "assumption from untrusted accounts."
                            ),
                        )
                    )

                # Check for broad service principal without conditions
                service_principal = principal.get("Service", "")
                if isinstance(service_principal, list):
                    service_principal = ", ".join(service_principal)
                if service_principal == "*" or "*" in str(service_principal):
                    findings.append(
                        Finding(
                            check_id="over_permissioned_roles",
                            severity="high",
                            resource_type="role",
                            resource_name=role_name,
                            message=(
                                f"Role '{role_name}' allows any AWS service principal to assume it."
                            ),
                            details={
                                "role_arn": role_arn,
                                "statement": stmt,
                                "attached_policy_count": attached_count,
                            },
                            remediation=(
                                "Scope Service principal to specific AWS services "
                                "(e.g., 'ec2.amazonaws.com', 'lambda.amazonaws.com'). "
                                "Add Condition keys like 'aws:SourceAccount' or "
                                "'aws:SourceArn' to prevent confused-deputy attacks."
                            ),
                        )
                    )

                # Check for missing ExternalId on cross-account trust
                has_external_id = "Condition" in stmt and any(
                    "ExternalId" in str(cond)
                    for cond in (stmt.get("Condition", {}).values() if isinstance(stmt.get("Condition"), dict) else [])
                )
                if aws_principal and not has_external_id and ":" in str(aws_principal):
                    # Looks like a cross-account ARN but no ExternalId
                    findings.append(
                        Finding(
                            check_id="over_permissioned_roles",
                            severity="medium",
                            resource_type="role",
                            resource_name=role_name,
                            message=(
                                f"Role '{role_name}' has cross-account trust but no "
                                f"ExternalId condition — vulnerable to confused-deputy attacks."
                            ),
                            details={
                                "role_arn": role_arn,
                                "statement": stmt,
                                "attached_policy_count": attached_count,
                            },
                            remediation=(
                                "Add 'sts:ExternalId' condition to the trust policy for all "
                                "cross-account role assumptions. The ExternalId should be a "
                                "unique secret known only to the trusted third party."
                            ),
                        )
                    )

        # Check for policy bloat
        if attached_count > MAX_POLICIES:
            findings.append(
                Finding(
                    check_id="over_permissioned_roles",
                    severity="medium",
                    resource_type="role",
                    resource_name=role_name,
                    message=(
                        f"Role '{role_name}' has {attached_count} attached policies "
                        f"(threshold: {MAX_POLICIES}). Policy bloat increases the risk of "
                        f"unintended permissions through accumulation."
                    ),
                    details={
                        "role_arn": role_arn,
                        "attached_policy_count": attached_count,
                        "attached_policies": [
                            {"name": p.get("PolicyName"), "arn": p.get("PolicyArn")}
                            for p in attached_policies
                        ],
                    },
                    remediation=(
                        "Consolidate attached policies into fewer, purpose-specific policies. "
                        "Use AWS IAM Access Analyzer to identify unused permissions and "
                        "generate least-privilege policies. Remove unused policy attachments."
                    ),
                )
            )

    return findings
