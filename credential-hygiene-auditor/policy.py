#!/usr/bin/env python3
"""NIST SP 800-63B password policy evaluator.

Provides password strength assessment aligned with NIST Special Publication
800-63B (Digital Identity Guidelines: Authentication and Lifecycle Management).

Key NIST principles implemented:
- Minimum length of 8 characters (memorized secrets)
- No maximum length restrictions (allow any Unicode)
- No arbitrary character-composition requirements
- No forced periodic rotation (not evaluated here but acknowledged)
- Focus on length and memorability over complexity
"""

import math
import re
from typing import Any


def evaluate_password(password: str) -> dict[str, Any]:
    """Evaluate a password against NIST SP 800-63B guidelines.

    Args:
        password: The password string to evaluate.

    Returns:
        A dictionary containing:
            - length_ok (bool): Meets minimum 8-character requirement.
            - length_recommended (bool): Meets 12+ character recommendation.
            - has_upper (bool): Contains uppercase ASCII letters.
            - has_lower (bool): Contains lowercase ASCII letters.
            - has_digit (bool): Contains digit characters.
            - has_special (bool): Contains non-alphanumeric characters.
            - entropy_bits (float): Approximate Shannon entropy in bits.
            - nist_compliant (bool): Passes NIST 800-63B minimum requirements.
            - score (int): 0-4 strength score (zxcvbn-style buckets).
            - feedback (list[str]): Human-readable improvement suggestions.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    length = len(password)
    length_ok = length >= 8
    length_recommended = length >= 12

    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    entropy_bits = _calculate_entropy(password)

    # NIST 800-63B compliance: minimum 8 chars, no blank passwords
    nist_compliant = length_ok and length > 0

    # Score 0-4 based on length, entropy, and character variety
    score = _calculate_score(
        length=length,
        entropy_bits=entropy_bits,
        has_upper=has_upper,
        has_lower=has_lower,
        has_digit=has_digit,
        has_special=has_special,
    )

    feedback = _generate_feedback(
        length=length,
        length_ok=length_ok,
        length_recommended=length_recommended,
        has_upper=has_upper,
        has_lower=has_lower,
        has_digit=has_digit,
        has_special=has_special,
        entropy_bits=entropy_bits,
        score=score,
    )

    return {
        "length_ok": length_ok,
        "length_recommended": length_recommended,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_special": has_special,
        "entropy_bits": round(entropy_bits, 2),
        "nist_compliant": nist_compliant,
        "score": score,
        "feedback": feedback,
    }


def _calculate_entropy(password: str) -> float:
    """Calculate approximate Shannon entropy of a password.

    Uses character pool size based on observed character classes.
    This is a simplified estimate; true password entropy depends on
generation method, not just observed characters.

    Args:
        password: The password string.

    Returns:
        Estimated entropy in bits.
    """
    if not password:
        return 0.0

    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool_size += 33  # Common printable ASCII special chars

    if pool_size == 0:
        return 0.0

    # Shannon entropy approximation: log2(pool_size) * length
    return math.log2(pool_size) * len(password)


def _calculate_score(
    length: int,
    entropy_bits: float,
    has_upper: bool,
    has_lower: bool,
    has_digit: bool,
    has_special: bool,
) -> int:
    """Calculate a 0-4 strength score.

    Args:
        length: Password length.
        entropy_bits: Estimated entropy in bits.
        has_upper: Contains uppercase letters.
        has_lower: Contains lowercase letters.
        has_digit: Contains digits.
        has_special: Contains special characters.

    Returns:
        Integer score from 0 (very weak) to 4 (very strong).
    """
    variety_count = sum([has_upper, has_lower, has_digit, has_special])

    if length < 6:
        return 0
    if length < 8 or entropy_bits < 30:
        return 1
    if length < 12 and variety_count < 3:
        return 2
    if length >= 12 and variety_count >= 3 and entropy_bits >= 50:
        return 4
    if length >= 8 and variety_count >= 2 and entropy_bits >= 40:
        return 3
    return 2


def _generate_feedback(
    length: int,
    length_ok: bool,
    length_recommended: bool,
    has_upper: bool,
    has_lower: bool,
    has_digit: bool,
    has_special: bool,
    entropy_bits: float,
    score: int,
) -> list[str]:
    """Generate human-readable feedback for password improvement.

    Args:
        length: Password length.
        length_ok: Meets minimum 8 characters.
        length_recommended: Meets 12+ characters.
        has_upper: Contains uppercase letters.
        has_lower: Contains lowercase letters.
        has_digit: Contains digits.
        has_special: Contains special characters.
        entropy_bits: Estimated entropy in bits.
        score: Current strength score.

    Returns:
        List of suggestion strings.
    """
    feedback: list[str] = []

    if not length_ok:
        feedback.append("Increase password length to at least 8 characters.")
    elif not length_recommended:
        feedback.append(
            "Consider using 12+ characters for stronger security (NIST recommendation)."
        )

    if score < 3:
        if not has_lower:
            feedback.append("Add lowercase letters for variety.")
        if not has_upper:
            feedback.append("Add uppercase letters for variety.")
        if not has_digit:
            feedback.append("Add digits for variety.")
        if not has_special:
            feedback.append("Add special characters for variety.")

    if entropy_bits < 40:
        feedback.append(
            "Password entropy is low; consider a longer passphrase or random generation."
        )

    if not feedback:
        feedback.append("Password meets strong criteria. Good job!")

    return feedback
