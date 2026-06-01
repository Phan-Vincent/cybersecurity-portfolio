"""Test secret handling and data disclosure controls."""

import pytest
from pathlib import Path
import json
import os
import tempfile

import sys
import importlib.util

REPO_ROOT = Path(__file__).parent.parent

def _load_module(name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / rel_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

m_llm = _load_module("m_llm3", "mitigated/llm_audit.py")

class TestSecrets:
    def test_mitigated_default_is_mock_no_remote_call(self):
        """MITIGATED: default allow_remote=False means no network call."""
        metrics = {"nutrition_metrics": {"weekly": [], "latest": None}, "training_metrics": {"weekly_volume_by_muscle_group": []}, "risk_flags": []}
        result = m_llm.generate_audit(metrics, allow_remote=False)
        assert result["token_usage"]["total_tokens"] == 0
        assert result["non_repudiation"]["output_hash"] == "mock"

    def test_mitigated_rejects_malformed_api_key(self):
        """MITIGATED: malformed API key is rejected before any call."""
        import os as _os
        original = _os.environ.get("OPENAI_API_KEY")
        _os.environ["OPENAI_API_KEY"] = "not-a-valid-key"
        try:
            metrics = {"nutrition_metrics": {"weekly": [], "latest": None}, "training_metrics": {"weekly_volume_by_muscle_group": []}, "risk_flags": []}
            with pytest.raises(m_llm.LLMAuditError) as exc_info:
                m_llm.generate_audit(metrics, allow_remote=True)
            assert "malformed" in str(exc_info.value).lower() or "OPENAI_API_KEY" in str(exc_info.value)
        finally:
            if original is None:
                _os.environ.pop("OPENAI_API_KEY", None)
            else:
                _os.environ["OPENAI_API_KEY"] = original
