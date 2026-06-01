"""Shared pytest fixtures and path setup.

Makes the ``mitigated/`` and ``vulnerable/`` packages importable as top-level
modules (they use sibling imports like ``from ingestion import ...``).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
# Allow `import ingestion` etc. to resolve against the mitigated/ tree by default,
# and against vulnerable/ when a test inserts it explicitly.
sys.path.insert(0, str(ROOT / "mitigated"))


@pytest.fixture()
def fake_api_key(monkeypatch):
    """A syntactically valid (but fake) OpenAI key for offline tests."""
    key = "sk-" + "x" * 40
    monkeypatch.setenv("OPENAI_API_KEY", key)
    return key


@pytest.fixture()
def sample_metrics():
    """A minimal, schema-clean processed-metrics payload."""
    return {
        "nutrition_metrics": {"latest": {"protein_per_lb": 0.95}},
        "training_metrics": {
            "weekly_volume_by_muscle_group": [
                {"muscle_group": "Chest", "total_volume": 4320.0}
            ]
        },
        "risk_flags": [],
    }
