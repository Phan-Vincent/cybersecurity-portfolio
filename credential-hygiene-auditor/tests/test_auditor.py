#!/usr/bin/env python3
"""pytest suite for the credential hygiene auditor.

Tests policy evaluation, breach detection, reuse detection, and report generation
using synthetic data only.
"""

import json
import pytest

from policy import evaluate_password
from breach import check_weak_password, check_hibp_mock, load_weak_hashes
from auditor import audit_credentials, _calculate_age_days
from report import generate_markdown_report, generate_json_report, _risk_label


class TestPolicyEvaluation:
    """Tests for policy.py password evaluation."""

    def test_empty_password(self):
        """Empty password should have zero entropy and fail compliance."""
        result = evaluate_password("")
        assert result["length_ok"] is False
        assert result["entropy_bits"] == 0.0
        assert result["nist_compliant"] is False
        assert result["score"] == 0

    def test_short_password(self):
        """7-character password should fail minimum length."""
        result = evaluate_password("abc1234")
        assert result["length_ok"] is False
        assert result["length_recommended"] is False
        assert result["nist_compliant"] is False
        assert result["score"] == 1

    def test_minimum_length_password(self):
        """8-character password should pass minimum but not recommended."""
        result = evaluate_password("Password1")
        assert result["length_ok"] is True
        assert result["length_recommended"] is False
        assert result["nist_compliant"] is True

    def test_strong_password(self):
        """Long password with all character classes should score 4."""
        result = evaluate_password("Correct-Horse-Battery-Staple!99")
        assert result["length_ok"] is True
        assert result["length_recommended"] is True
        assert result["has_upper"] is True
        assert result["has_lower"] is True
        assert result["has_digit"] is True
        assert result["has_special"] is True
        assert result["score"] == 4
        assert result["nist_compliant"] is True

    def test_unicode_password(self):
        """Unicode password should be accepted (NIST allows any Unicode)."""
        result = evaluate_password("🐎🔋📎correct")
        assert result["length_ok"] is True
        assert result["nist_compliant"] is True
        assert result["has_special"] is True  # Emoji counts as non-alphanumeric

    def test_entropy_calculation(self):
        """Entropy should increase with length and variety."""
        short = evaluate_password("abc")
        long = evaluate_password("abcdefghijklmnopqrstuvwxyz")
        assert long["entropy_bits"] > short["entropy_bits"]

    def test_feedback_generation(self):
        """Feedback should suggest improvements for weak passwords."""
        result = evaluate_password("123")
        assert len(result["feedback"]) > 0
        assert any("length" in fb.lower() for fb in result["feedback"])

    def test_type_error(self):
        """Non-string input should raise TypeError."""
        with pytest.raises(TypeError):
            evaluate_password(12345)  # type: ignore[arg-type]


class TestBreachDetection:
    """Tests for breach.py breach detection."""

    def test_known_weak_password(self):
        """Known weak password should be flagged as breached."""
        weak_hashes = {"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"}  # SHA-1 of "password"
        result = check_weak_password("password", weak_hashes)
        assert result["breached"] is True
        assert "hash_prefix" in result

    def test_unknown_password(self):
        """Unknown password should not be flagged as breached."""
        weak_hashes = {"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"}
        result = check_weak_password("this_is_not_a_weak_password_12345!", weak_hashes)
        assert result["breached"] is False

    def test_hibp_mock(self):
        """HIBP mock should return a simulated breach count and explanation."""
        result = check_hibp_mock("testpassword")
        assert result["checked"] is True
        assert result["simulated_breach_count"] >= 1
        assert "k-anonymity" in result["note"].lower()

    def test_hibp_mock_strong_password(self):
        """Strong password should have lower mock breach count."""
        weak = check_hibp_mock("123")
        strong = check_hibp_mock("Correct-Horse-Battery-Staple!99")
        assert strong["simulated_breach_count"] <= weak["simulated_breach_count"]

    def test_load_weak_hashes(self, tmp_path):
        """Loading weak hashes from file should skip comments and empty lines."""
        hash_file = tmp_path / "weak_hashes.txt"
        hash_file.write_text(
            "# Comment line\n"
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\n"
            "\n"
            "e38ad214943daad1d64c102faec29de4afe9da3b\n"
        )
        hashes = load_weak_hashes(str(hash_file))
        assert len(hashes) == 2
        assert "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8" in hashes

    def test_type_error_password(self):
        """Non-string input should raise TypeError."""
        with pytest.raises(TypeError):
            check_weak_password(123, set())  # type: ignore[arg-type]


class TestAuditor:
    """Tests for auditor.py core engine."""

    def test_audit_credentials_basic(self):
        """Basic audit should return expected structure."""
        credentials = [
            {
                "username": "testuser",
                "password": "P@ssw0rd!2024",
                "service": "test-service",
                "last_changed": "2024-01-01",
            }
        ]
        weak_hashes = set()
        result = audit_credentials(credentials, weak_hashes)

        assert result["total_credentials"] == 1
        assert "overall_risk_score" in result
        assert 0 <= result["overall_risk_score"] <= 100
        assert len(result["per_credential_findings"]) == 1
        assert result["reused_passwords"] == []
        assert "nist_compliance_summary" in result

    def test_reuse_detection(self):
        """Same password across services should be detected as reuse."""
        credentials = [
            {"username": "user1", "password": "samepassword", "service": "email", "last_changed": "2024-01-01"},
            {"username": "user1", "password": "samepassword", "service": "bank", "last_changed": "2024-02-01"},
        ]
        weak_hashes = set()
        result = audit_credentials(credentials, weak_hashes)

        assert len(result["reused_passwords"]) == 1
        assert result["reused_passwords"][0]["reuse_count"] == 2

    def test_risk_score_scaling(self):
        """Weak credentials should produce higher risk score."""
        weak_creds = [
            {"username": "u1", "password": "password", "service": "s1", "last_changed": "2023-01-01"},
            {"username": "u2", "password": "123456", "service": "s2", "last_changed": "2023-01-01"},
        ]
        strong_creds = [
            {"username": "u1", "password": "Correct-Horse-Battery-Staple!99", "service": "s1", "last_changed": "2024-01-01"},
        ]
        weak_hashes = {
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",  # password
            "e38ad214943daad1d64c102faec29de4afe9da3b",  # 123456
        }

        weak_result = audit_credentials(weak_creds, weak_hashes)
        strong_result = audit_credentials(strong_creds, weak_hashes)

        assert weak_result["overall_risk_score"] > strong_result["overall_risk_score"]

    def test_calculate_age_days(self):
        """Age calculation should work for valid dates and return None for invalid."""
        from datetime import datetime, timezone
        days = _calculate_age_days("2024-01-01")
        assert isinstance(days, int)
        assert days > 0

        assert _calculate_age_days("") is None
        assert _calculate_age_days("invalid") is None

    def test_empty_credentials(self):
        """Empty credentials list should return zero risk."""
        result = audit_credentials([], set())
        assert result["total_credentials"] == 0
        assert result["overall_risk_score"] == 0

    def test_type_error(self):
        """Non-list input should raise TypeError."""
        with pytest.raises(TypeError):
            audit_credentials("not a list", set())  # type: ignore[arg-type]


class TestReportGeneration:
    """Tests for report.py output generation."""

    def test_markdown_contains_sections(self):
        """Markdown report should contain expected sections."""
        mock_result = {
            "audit_timestamp": "2024-01-01T00:00:00+00:00",
            "total_credentials": 2,
            "overall_risk_score": 45,
            "per_credential_findings": [],
            "reused_passwords": [],
            "nist_compliance_summary": {
                "total_credentials": 2,
                "nist_compliant": 1,
                "nist_non_compliant": 1,
                "compliance_rate_percent": 50.0,
                "nist_standard": "NIST SP 800-63B",
            },
        }
        md = generate_markdown_report(mock_result)
        assert "# Credential Hygiene Audit Report" in md
        assert "Overall Risk Score" in md
        assert "NIST SP 800-63B" in md
        assert "synthetic data" in md.lower()

    def test_markdown_reuse_table(self):
        """Markdown should include reuse table when reuse is present."""
        mock_result = {
            "audit_timestamp": "2024-01-01T00:00:00+00:00",
            "total_credentials": 2,
            "overall_risk_score": 75,
            "per_credential_findings": [],
            "reused_passwords": [
                {
                    "password_hash_prefix": "abc123",
                    "services_affected": [
                        {"username": "user1", "service": "email"},
                        {"username": "user1", "service": "bank"},
                    ],
                    "reuse_count": 2,
                }
            ],
            "nist_compliance_summary": {
                "total_credentials": 2,
                "nist_compliant": 0,
                "nist_non_compliant": 2,
                "compliance_rate_percent": 0.0,
                "nist_standard": "NIST SP 800-63B",
            },
        }
        md = generate_markdown_report(mock_result)
        assert "Password Reuse Detection" in md
        assert "user1@email" in md
        assert "user1@bank" in md

    def test_json_valid(self):
        """JSON output should be valid JSON."""
        mock_result = {
            "audit_timestamp": "2024-01-01T00:00:00+00:00",
            "total_credentials": 1,
            "overall_risk_score": 10,
            "per_credential_findings": [],
            "reused_passwords": [],
            "nist_compliance_summary": {
                "total_credentials": 1,
                "nist_compliant": 1,
                "nist_non_compliant": 0,
                "compliance_rate_percent": 100.0,
                "nist_standard": "NIST SP 800-63B",
            },
        }
        json_str = generate_json_report(mock_result)
        parsed = json.loads(json_str)
        assert parsed["total_credentials"] == 1

    def test_risk_labels(self):
        """Risk labels should cover all score ranges."""
        assert _risk_label(10) == "Low Risk"
        assert _risk_label(30) == "Moderate Risk"
        assert _risk_label(50) == "Elevated Risk"
        assert _risk_label(70) == "High Risk"
        assert _risk_label(90) == "Critical Risk"
