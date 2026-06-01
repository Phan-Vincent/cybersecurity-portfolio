"""
Unit tests for AWS IAM Least-Privilege Auditor - Security Checks

Tests the four core checks with both positive cases (findings expected)
and negative cases (clean configurations that should produce no findings).
"""

from datetime import datetime, timezone, timedelta
from aws_iam_auditor.checks import (
    check_wildcard_actions,
    check_unused_access_keys,
    check_users_without_mfa,
    check_over_permissioned_roles,
)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _days_ago(days: int) -> str:
    """Return ISO timestamp for N days ago."""
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.isoformat().replace("+00:00", "Z")


# ── Test: Wildcard Actions ───────────────────────────────────────────────────

def test_wildcard_star_action():
    """A policy with Action='*' should produce a CRITICAL finding."""
    policies = [
        {
            "PolicyName": "AdminPolicy",
            "Arn": "arn:aws:iam::123456789012:policy/AdminPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }
        }
    ]
    findings = check_wildcard_actions(policies)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].check_id == "wildcard_actions"
    assert findings[0].resource_name == "AdminPolicy"


def test_wildcard_service_action():
    """A policy with Action='s3:*' should produce a HIGH finding."""
    policies = [
        {
            "PolicyName": "S3Broad",
            "Arn": "arn:aws:iam::123456789012:policy/S3Broad",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:*",
                        "Resource": "arn:aws:s3:::my-bucket/*"
                    }
                ]
            }
        }
    ]
    findings = check_wildcard_actions(policies)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "s3" in findings[0].message.lower()


def test_no_wildcard_clean_policy():
    """A precisely scoped policy should produce no findings."""
    policies = [
        {
            "PolicyName": "ScopedPolicy",
            "Arn": "arn:aws:iam::123456789012:policy/ScopedPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:ListBucket"
                        ],
                        "Resource": "arn:aws:s3:::my-bucket/*"
                    }
                ]
            }
        }
    ]
    findings = check_wildcard_actions(policies)
    assert len(findings) == 0


def test_deny_statements_ignored():
    """Deny statements should not be flagged as wildcard findings."""
    policies = [
        {
            "PolicyName": "DenyPolicy",
            "Arn": "arn:aws:iam::123456789012:policy/DenyPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }
        }
    ]
    findings = check_wildcard_actions(policies)
    assert len(findings) == 0


# ── Test: Unused Access Keys ───────────────────────────────────────────────────

def test_unused_key_over_90_days():
    """A key unused for >90 days should produce a HIGH finding."""
    users = [{"UserName": "test-user", "UserType": "regular"}]
    keys = [
        {
            "UserName": "test-user",
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "Status": "Active",
            "CreateDate": _days_ago(100),
            "LastUsed": {
                "LastUsedDate": _days_ago(120),
                "ServiceName": "s3",
                "Region": "us-west-2"
            }
        }
    ]
    findings = check_unused_access_keys(users, keys)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].check_id == "unused_access_keys"
    assert findings[0].resource_name == "AKIAIOSFODNN7EXAMPLE"


def test_unused_key_over_180_days_critical():
    """A key unused for >180 days should produce a CRITICAL finding."""
    users = [{"UserName": "test-user", "UserType": "regular"}]
    keys = [
        {
            "UserName": "test-user",
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "Status": "Active",
            "CreateDate": _days_ago(200),
            "LastUsed": {
                "LastUsedDate": _days_ago(200),
                "ServiceName": "N/A",
                "Region": "N/A"
            }
        }
    ]
    findings = check_unused_access_keys(users, keys)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_recently_used_key_no_finding():
    """A recently used key should produce no findings."""
    users = [{"UserName": "test-user", "UserType": "regular"}]
    keys = [
        {
            "UserName": "test-user",
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "Status": "Active",
            "CreateDate": _days_ago(10),
            "LastUsed": {
                "LastUsedDate": _days_ago(5),
                "ServiceName": "ec2",
                "Region": "us-east-1"
            }
        }
    ]
    findings = check_unused_access_keys(users, keys)
    assert len(findings) == 0


def test_never_used_key_finding():
    """A key that was never used (null LastUsedDate) but is old should be flagged."""
    users = [{"UserName": "test-user", "UserType": "regular"}]
    keys = [
        {
            "UserName": "test-user",
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "Status": "Active",
            "CreateDate": _days_ago(95),
            "LastUsed": {
                "LastUsedDate": None,
                "ServiceName": "N/A",
                "Region": "N/A"
            }
        }
    ]
    findings = check_unused_access_keys(users, keys)
    assert len(findings) == 1
    assert findings[0].severity == "high"


# ── Test: Users Without MFA ────────────────────────────────────────────────────

def test_user_without_mfa():
    """A user with no MFA device should produce a HIGH finding."""
    users = [{"UserName": "alice", "UserType": "regular", "CreateDate": _days_ago(30)}]
    devices = []
    findings = check_users_without_mfa(users, devices)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].resource_name == "alice"


def test_root_user_without_mfa():
    """Root user without MFA should produce a CRITICAL finding."""
    users = [{"UserName": "root", "UserType": "root", "CreateDate": _days_ago(100)}]
    devices = []
    findings = check_users_without_mfa(users, devices)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_user_with_mfa_no_finding():
    """A user with an MFA device should produce no findings."""
    users = [{"UserName": "bob", "UserType": "regular", "CreateDate": _days_ago(30)}]
    devices = [{"UserName": "bob", "SerialNumber": "arn:aws:iam::123:mfa/bob"}]
    findings = check_users_without_mfa(users, devices)
    assert len(findings) == 0


# ── Test: Over-Permissioned Roles ──────────────────────────────────────────────

def test_role_with_wildcard_principal_aws():
    """A role with Principal.AWS='*' should produce a CRITICAL finding."""
    roles = [
        {
            "RoleName": "OpenRole",
            "Arn": "arn:aws:iam::123456789012:role/OpenRole",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "AttachedPolicies": []
        }
    ]
    findings = check_over_permissioned_roles(roles)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].check_id == "over_permissioned_roles"


def test_role_with_principal_star():
    """A role with Principal='*' should produce a CRITICAL finding."""
    roles = [
        {
            "RoleName": "OpenRole",
            "Arn": "arn:aws:iam::123456789012:role/OpenRole",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "AttachedPolicies": []
        }
    ]
    findings = check_over_permissioned_roles(roles)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_role_with_service_wildcard():
    """A role with Principal.Service='*' should produce a HIGH finding."""
    roles = [
        {
            "RoleName": "AnyServiceRole",
            "Arn": "arn:aws:iam::123456789012:role/AnyServiceRole",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "*"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "AttachedPolicies": []
        }
    ]
    findings = check_over_permissioned_roles(roles)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_role_with_cross_account_no_external_id():
    """A role with cross-account trust but no ExternalId should be MEDIUM."""
    roles = [
        {
            "RoleName": "CrossAccountRole",
            "Arn": "arn:aws:iam::123456789012:role/CrossAccountRole",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "AttachedPolicies": []
        }
    ]
    findings = check_over_permissioned_roles(roles)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "ExternalId" in findings[0].message


def test_role_with_policy_bloat():
    """A role with >5 attached policies should produce a MEDIUM finding."""
    roles = [
        {
            "RoleName": "BloatedRole",
            "Arn": "arn:aws:iam::123456789012:role/BloatedRole",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "AttachedPolicies": [
                {"PolicyName": "p1", "PolicyArn": "arn:aws:iam::aws:policy/p1"},
                {"PolicyName": "p2", "PolicyArn": "arn:aws:iam::aws:policy/p2"},
                {"PolicyName": "p3", "PolicyArn": "arn:aws:iam::aws:policy/p3"},
                {"PolicyName": "p4", "PolicyArn": "arn:aws:iam::aws:policy/p4"},
                {"PolicyName": "p5", "PolicyArn": "arn:aws:iam::aws:policy/p5"},
                {"PolicyName": "p6", "PolicyArn": "arn:aws:iam::aws:policy/p6"},
            ]
        }
    ]
    findings = check_over_permissioned_roles(roles)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "6" in findings[0].message


def test_clean_role_no_findings():
    """A properly scoped role with few policies should produce no findings."""
    roles = [
        {
            "RoleName": "GoodRole",
            "Arn": "arn:aws:iam::123456789012:role/GoodRole",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "AttachedPolicies": [
                {"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
            ]
        }
    ]
    findings = check_over_permissioned_roles(roles)
    assert len(findings) == 0
