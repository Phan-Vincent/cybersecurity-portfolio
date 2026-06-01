"""Test cost overrun guards."""

import pytest
from pathlib import Path
import json
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

m_llm = _load_module("m_llm4", "mitigated/llm_audit.py")

class TestCostGuards:
    def test_mitigated_rejects_large_input_pre_flight(self):
        """MITIGATED: estimated input tokens > 1500 abort before call."""
        # Build a huge metrics payload to exceed MAX_INPUT_TOKENS
        huge = {"nutrition_metrics": {"weekly": [{"week_start": "2024-01-01", "avg_calories": 2500, "avg_protein_g": 150, "avg_bodyweight_lb": 150, "protein_per_lb": 1.0, "calorie_adherence_pct": 95.0}] * 500, "latest": None}, "training_metrics": {"weekly_volume_by_muscle_group": []}, "risk_flags": []}
        with pytest.raises(m_llm.TokenBudgetExceededError) as exc_info:
            m_llm.generate_audit(huge, allow_remote=False)
        assert "Estimated input tokens" in str(exc_info.value)

    def test_mitigated_daily_budget_enforced(self):
        """MITIGATED: daily budget exceeded triggers abort."""
        with tempfile.TemporaryDirectory() as tmp:
            import os as _os
            import datetime
            old_cwd = _os.getcwd()
            try:
                _os.chdir(tmp)
                today = datetime.datetime.now().strftime("%Y-%m-%d")
                # Seed the daily budget file with max spend for today
                budget_file = Path(tmp) / ".daily_spend.json"
                budget_file.write_text(json.dumps({"date": today, "spent_cents": 999.0}))
                metrics = {"nutrition_metrics": {"weekly": [], "latest": None}, "training_metrics": {"weekly_volume_by_muscle_group": []}, "risk_flags": []}
                with pytest.raises(m_llm.TokenBudgetExceededError) as exc_info:
                    m_llm.generate_audit(metrics, allow_remote=False)
                assert "Daily budget" in str(exc_info.value)
            finally:
                _os.chdir(old_cwd)
