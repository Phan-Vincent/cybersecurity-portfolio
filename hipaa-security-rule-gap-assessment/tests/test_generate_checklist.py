"""Tests for scripts/generate_checklist.py."""

import csv
import sys
from pathlib import Path

import generate_checklist as gc
import score_assessment as sa


def test_checklist_covers_catalog(tmp_path, monkeypatch):
    out = tmp_path / "checklist.csv"
    monkeypatch.setattr(sys, "argv", ["generate_checklist.py", "--output", str(out)])
    gc.main()
    rows = list(csv.DictReader(out.open()))
    assert len(rows) == 58
    assert list(rows[0].keys()) == gc.DEFAULT_OUTPUT_COLUMNS
    assert {r["assessment_status"] for r in rows} == {"Not Assessed"}


def test_blank_checklist_scores_everything_as_not_assessed(tmp_path, monkeypatch):
    out = tmp_path / "checklist.csv"
    monkeypatch.setattr(sys, "argv", ["generate_checklist.py", "--output", str(out)])
    gc.main()
    gaps, summary = sa.score_rows(sa.read_assessment(out), sa.load_catalog(sa.CONTROLS_PATH), sa.date(2026, 6, 15))
    assert len(gaps) == 58
    assert summary["status_counts"] == {"Not Assessed": 58}
