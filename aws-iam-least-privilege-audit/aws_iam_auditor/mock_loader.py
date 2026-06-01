"""
AWS IAM Least-Privilege Auditor - Mock Data Loader

Provides offline test data for safe demonstration and CI/CD testing.
No AWS credentials or network access required.

All data is synthetic — no real AWS account information, no PHI, no secrets.
This is the same principle used in healthcare security training: use realistic
but fictional data to teach detection without exposing production systems.
"""

import json
import os
from pathlib import Path


def _load_json(filename: str) -> list[dict] | dict:
    """Load a JSON file from the data directory."""
    # Resolve relative to this file's location (aws_iam_auditor/)
    base = Path(__file__).parent.parent / "data"
    filepath = base / filename

    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


class MockLoader:
    """Loads synthetic IAM data from JSON files for --mock mode."""

    def __init__(self, data_dir: str | None = None):
        """
        Initialize the mock loader.

        Args:
            data_dir: Optional override path to the data directory.
                      Defaults to ../data/ relative to this package.
        """
        if data_dir:
            self._base = Path(data_dir)
        else:
            self._base = Path(__file__).parent.parent / "data"

    def _load(self, filename: str) -> list[dict] | dict:
        filepath = self._base / filename
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def load_users(self) -> list[dict]:
        """Return synthetic IAM users."""
        return self._load("users.json")

    def load_roles(self) -> list[dict]:
        """Return synthetic IAM roles."""
        return self._load("roles.json")

    def load_policies(self) -> list[dict]:
        """Return synthetic IAM policies (managed and inline)."""
        return self._load("policies.json")

    def load_access_keys(self) -> list[dict]:
        """Return synthetic access key metadata."""
        return self._load("access_keys.json")

    def load_mfa_devices(self) -> list[dict]:
        """Return synthetic MFA device registrations."""
        return self._load("mfa_devices.json")
