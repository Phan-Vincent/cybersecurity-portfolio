"""Test output validation and insecure output handling."""

import pytest
from pathlib import Path
import json

import sys
import importlib.util

REPO_ROOT = Path(__file__).parent.parent

def _load_module(name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / rel_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

v_llm = _load_module("v_llm2", "vulnerable/llm_audit.py")
m_llm = _load_module("m_llm2", "mitigated/llm_audit.py")

class TestOutputValidation:
    def test_mitigated_schema_blocks_long_strings(self):
        """MITIGATED: maxLength and pattern constraints on recommendation strings."""
        bad_audit = {
            "overall_status": "On Track",
            "strength_trend": {"status": "Improving", "velocity_percent_change": 3.4},
            "nutrition_assessment": {"calorie_adherence_percent": 92.1, "protein_per_lb": 0.85, "consistency_score": 88.0},
            "recovery_risk_score": 0.45,
            "risk_flags": ["x"],
            "priority_recommendations": [
                {"priority": 1, "action": "x" * 300, "reason": "x" * 300}  # exceeds 256
            ],
        }
        from jsonschema import validate, ValidationError
        with pytest.raises(ValidationError) as exc_info:
            validate(instance=bad_audit, schema=m_llm.LLM_AUDIT_SCHEMA)
        assert "maxLength" in str(exc_info.value) or "is too long" in str(exc_info.value)

    def test_mitigated_schema_blocks_bad_reason_pattern(self):
        """MITIGATED: pattern on reason field rejects HTML-like content."""
        bad_audit = {
            "overall_status": "On Track",
            "strength_trend": {"status": "Improving", "velocity_percent_change": 3.4},
            "nutrition_assessment": {"calorie_adherence_percent": 92.1, "protein_per_lb": 0.85, "consistency_score": 88.0},
            "recovery_risk_score": 0.45,
            "risk_flags": ["x"],
            "priority_recommendations": [
                {"priority": 1, "action": "Click here", "reason": "<script>alert('xss')</script>"}
            ],
        }
        from jsonschema import validate, ValidationError
        with pytest.raises(ValidationError) as exc_info:
            validate(instance=bad_audit, schema=m_llm.LLM_AUDIT_SCHEMA)
        assert "pattern" in str(exc_info.value).lower() or "does not match" in str(exc_info.value).lower()

    def test_mitigated_audit_includes_non_repudiation_hash(self):
        """MITIGATED: generate_audit returns input/output hashes."""
        metrics = {"nutrition_metrics": {"weekly": [], "latest": None}, "training_metrics": {"weekly_volume_by_muscle_group": []}, "risk_flags": []}
        result = m_llm.generate_audit(metrics, allow_remote=False)
        assert "non_repudiation" in result
        assert "input_hash" in result["non_repudiation"]
        assert len(result["non_repudiation"]["input_hash"]) == 16
