#!/usr/bin/env python3
"""Breach detection module for credential hygiene auditing.

Provides offline weak-password checking against a bundled hash list and
a mock implementation of the Have I Been Pwned (HIBP) k-anonymity API.

The HIBP k-anonymity protocol works by:
1. Client SHA-1 hashes the password.
2. Client sends the first 5 hex characters (prefix) to the HIBP API.
3. Server returns all suffixes (remaining 35 hex chars) that match the prefix,
   along with breach counts.
4. Client checks locally if the full hash suffix is in the response.

This prevents the server from ever seeing the full hash, protecting
user passwords even if the API is compromised or logging requests.
"""

import hashlib
from typing import Any


def load_weak_hashes(path: str) -> set[str]:
    """Load a set of weak password hashes from a file.

    Args:
        path: Path to the hash file. Lines starting with '#' are treated as
            comments and skipped. Empty lines are ignored.

    Returns:
        A set of hexadecimal hash strings.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    weak_hashes: set[str] = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                weak_hashes.add(line.lower())
    return weak_hashes


def check_weak_password(password: str, weak_hashes: set[str]) -> dict[str, Any]:
    """Check if a password matches a known weak hash.

    Args:
        password: The password to check.
        weak_hashes: A set of hexadecimal SHA-1 hashes of known weak passwords.

    Returns:
        A dictionary containing:
            - breached (bool): True if the password hash is in the weak set.
            - reason (str): Human-readable explanation.
            - hash_prefix (str): First 5 characters of the SHA-1 hash (for logging).
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().lower()
    hash_prefix = sha1_hash[:5]

    if sha1_hash in weak_hashes:
        return {
            "breached": True,
            "reason": (
                "Password matches a known weak password hash in the local database. "
                "This password is commonly used and easily guessed by attackers."
            ),
            "hash_prefix": hash_prefix,
        }

    return {
        "breached": False,
        "reason": "Password not found in the local weak hash database.",
        "hash_prefix": hash_prefix,
    }


def check_hibp_mock(password: str) -> dict[str, Any]:
    """Simulate a Have I Been Pwned (HIBP) k-anonymity API check.

    In a production environment, this would:
    1. Compute the SHA-1 hash of the password.
    2. Send the first 5 characters (prefix) to https://api.pwnedpasswords.com/range/{prefix}
    3. Receive a list of hash suffixes and breach counts.
    4. Check locally if the remaining 35 characters of the hash are in the response.

    This mock simulates a moderate breach count for demonstration purposes.

    Args:
        password: The password to check.

    Returns:
        A dictionary containing:
            - simulated_breach_count (int): Mock breach count.
            - checked (bool): True if the check was performed.
            - note (str): Explanation of real API usage and k-anonymity.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    # Deterministic mock: shorter / simpler passwords get higher breach counts
    length_factor = max(0, 20 - len(password))
    variety = sum([
        any(c.isupper() for c in password),
        any(c.islower() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    variety_penalty = max(0, 4 - variety)

    simulated_count = (length_factor * 500) + (variety_penalty * 300)
    if simulated_count == 0:
        simulated_count = 1  # Even strong passwords may appear in breach data

    return {
        "simulated_breach_count": simulated_count,
        "checked": True,
        "note": (
            "HIBP k-anonymity API: The client sends only the first 5 characters "
            "of the SHA-1 hash to the server. The server responds with suffixes "
            "and breach counts. The client checks locally — the full hash is never "
            "transmitted. This protects passwords even if the API endpoint is compromised. "
            "In production, use https://api.pwnedpasswords.com/range/{prefix}."
        ),
    }
