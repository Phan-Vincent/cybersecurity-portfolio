"""
AWS IAM Least-Privilege Auditor - Core Orchestrator

Coordinates data collection (live AWS via boto3 or mock JSON) and runs
all security checks. Returns a consolidated list of findings.

Designed to be called programmatically or via the CLI entry point.
"""

# NOTE: boto3/botocore are imported lazily inside __init__ ONLY when running
# in live AWS mode. This keeps --mock mode fully runnable on a clean machine
# with zero AWS dependencies installed (and zero risk of touching a real
# account), which is exactly how a reviewer should be able to try this tool.
from . import checks
from .mock_loader import MockLoader


class Auditor:
    """
    Orchestrates the IAM audit process.

    Supports two modes:
      - Live AWS: uses boto3 with read-only IAM permissions
      - Mock mode: uses bundled synthetic JSON data
    """

    def __init__(self, mock: bool = False, data_dir: str | None = None):
        """
        Initialize the auditor.

        Args:
            mock: If True, use synthetic JSON data instead of live AWS.
            data_dir: Optional path to mock data directory (default: ../data/).
        """
        self.mock = mock
        self._mock_loader = MockLoader(data_dir) if mock else None
        self._iam_client = None

        if not mock:
            try:
                import boto3
                from botocore.exceptions import NoCredentialsError
            except ImportError:
                raise RuntimeError(
                    "boto3 is required for live AWS mode. Install it with "
                    "'pip install -r requirements.txt', or use --mock for offline testing."
                )
            try:
                self._iam_client = boto3.client("iam")
            except NoCredentialsError:
                raise RuntimeError(
                    "AWS credentials not found. Configure credentials via environment "
                    "variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) or the AWS CLI. "
                    "Alternatively, use --mock mode for offline testing."
                )

    # ── Live AWS Data Collection ──────────────────────────────────────────────

    def _fetch_users(self) -> list[dict]:
        """Fetch IAM users from live AWS."""
        paginator = self._iam_client.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            for user in page.get("Users", []):
                users.append({
                    "UserName": user.get("UserName"),
                    "UserId": user.get("UserId"),
                    "Arn": user.get("Arn"),
                    "CreateDate": user.get("CreateDate").isoformat() if user.get("CreateDate") else None,
                    "PasswordLastUsed": user.get("PasswordLastUsed").isoformat() if user.get("PasswordLastUsed") else None,
                    "UserType": "regular",
                })
        return users

    def _fetch_roles(self) -> list[dict]:
        """Fetch IAM roles from live AWS."""
        paginator = self._iam_client.get_paginator("list_roles")
        roles = []
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role.get("RoleName")
                # Fetch attached policies for each role
                attached = []
                try:
                    policy_resp = self._iam_client.list_attached_role_policies(
                        RoleName=role_name
                    )
                    for p in policy_resp.get("AttachedPolicies", []):
                        attached.append({
                            "PolicyName": p.get("PolicyName"),
                            "PolicyArn": p.get("PolicyArn"),
                        })
                except Exception:
                    pass  # Skip if we can't read attached policies

                roles.append({
                    "RoleName": role_name,
                    "Arn": role.get("Arn"),
                    "AssumeRolePolicyDocument": role.get("AssumeRolePolicyDocument", {}),
                    "AttachedPolicies": attached,
                    "CreateDate": role.get("CreateDate").isoformat() if role.get("CreateDate") else None,
                })
        return roles

    def _fetch_policies(self) -> list[dict]:
        """Fetch IAM policies (managed) from live AWS."""
        paginator = self._iam_client.get_paginator("list_policies")
        policies = []
        for page in paginator.paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                policy_name = policy.get("PolicyName")
                policy_arn = policy.get("Arn")
                # Fetch the default policy version document
                doc = {}
                try:
                    version_resp = self._iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy.get("DefaultVersionId", "v1"),
                    )
                    doc = version_resp.get("PolicyVersion", {}).get("Document", {})
                except Exception:
                    pass

                policies.append({
                    "PolicyName": policy_name,
                    "Arn": policy_arn,
                    "PolicyDocument": doc,
                })
        return policies

    def _fetch_access_keys(self) -> list[dict]:
        """Fetch access keys for all users from live AWS."""
        users = self._fetch_users()
        keys = []
        for user in users:
            username = user.get("UserName")
            try:
                key_resp = self._iam_client.list_access_keys(UserName=username)
                for key in key_resp.get("AccessKeyMetadata", []):
                    key_id = key.get("AccessKeyId")
                    # Get last used info
                    last_used = {}
                    try:
                        lu_resp = self._iam_client.get_access_key_last_used(
                            AccessKeyId=key_id
                        )
                        lu = lu_resp.get("AccessKeyLastUsed", {})
                        last_used = {
                            "LastUsedDate": lu.get("LastUsedDate").isoformat() if lu.get("LastUsedDate") else None,
                            "ServiceName": lu.get("ServiceName"),
                            "Region": lu.get("Region"),
                        }
                    except Exception:
                        pass

                    keys.append({
                        "UserName": username,
                        "AccessKeyId": key_id,
                        "Status": key.get("Status"),
                        "CreateDate": key.get("CreateDate").isoformat() if key.get("CreateDate") else None,
                        "LastUsed": last_used,
                    })
            except Exception:
                pass
        return keys

    def _fetch_mfa_devices(self) -> list[dict]:
        """Fetch MFA devices from live AWS."""
        paginator = self._iam_client.get_paginator("list_virtual_mfa_devices")
        devices = []
        for page in paginator.paginate():
            for device in page.get("VirtualMFADevices", []):
                user = device.get("User")
                if user:
                    devices.append({
                        "UserName": user.get("UserName"),
                        "SerialNumber": device.get("SerialNumber"),
                        "EnableDate": device.get("EnableDate").isoformat() if device.get("EnableDate") else None,
                    })
        return devices

    # ── Mock Data Collection ────────────────────────────────────────────────────

    def _load_mock_data(self) -> tuple[list[dict], list[dict], list[dict], list[dict], list[dict]]:
        """Load all synthetic data from JSON files."""
        loader = self._mock_loader
        return (
            loader.load_users(),
            loader.load_roles(),
            loader.load_policies(),
            loader.load_access_keys(),
            loader.load_mfa_devices(),
        )

    # ── Main Audit Entry Point ─────────────────────────────────────────────────

    def run_audit(self) -> list:
        """
        Execute all IAM security checks and return a consolidated list of findings.

        Returns:
            List of Finding objects from all checks.
        """
        if self.mock:
            users, roles, policies, access_keys, mfa_devices = self._load_mock_data()
        else:
            users = self._fetch_users()
            roles = self._fetch_roles()
            policies = self._fetch_policies()
            access_keys = self._fetch_access_keys()
            mfa_devices = self._fetch_mfa_devices()

        all_findings = []

        all_findings.extend(checks.check_wildcard_actions(policies))
        all_findings.extend(checks.check_unused_access_keys(users, access_keys))
        all_findings.extend(checks.check_users_without_mfa(users, mfa_devices))
        all_findings.extend(checks.check_over_permissioned_roles(roles))

        return all_findings
