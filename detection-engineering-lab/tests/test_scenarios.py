"""
test_scenarios.py
End-to-end: each scenario raises exactly its expected detections, the benign baseline
raises none, removing an attack step removes its detection, and generated files
(datasets, coverage doc) are up to date.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "data"))

import generate  # noqa: E402
from run_lab import COVERAGE, RULES, coverage_markdown, load_scenarios, run  # noqa: E402
from sigma_lite import evaluate, load_rules  # noqa: E402

RULESET = load_rules(RULES)
SCENARIOS = load_scenarios()
RESULTS = {r["file"]: r for r in run(RULESET, SCENARIOS)}


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s["file"])
def test_scenario_raises_exactly_the_expected_detections(scenario):
    result = RESULTS[scenario["file"]]
    assert not result["missed"], f"missed detections: {result['missed']}"
    assert not result["unexpected"], f"false positives: {result['unexpected']}"


def test_benign_baseline_raises_nothing():
    assert RESULTS["benign_baseline.jsonl"]["alerts"] == []


@pytest.mark.parametrize("scenario", [s for s in SCENARIOS if s["expect"]], ids=lambda s: s["file"])
def test_each_detection_depends_on_its_evidence(scenario):
    """Removing the events an alert points to must remove that alert (no vacuous rules)."""
    for alert in RESULTS[scenario["file"]]["alerts"]:
        kept = [e for e in scenario["events"] if e["_id"] not in set(alert.event_ids)]
        still = {(a.rule_name, tuple(a.event_ids)) for a in evaluate(RULESET, kept)}
        assert (alert.rule_name, tuple(alert.event_ids)) not in still


def test_bruteforce_threshold_is_exact():
    events = [e for e in SCENARIOS[0]["events"] if e.get("outcome") == "failure"]
    names = lambda evs: {a.rule_name for a in evaluate(RULESET, evs)}
    assert "ssh_bruteforce" in names(events[:8])
    assert "ssh_bruteforce" not in names(events[:7])


def test_committed_datasets_match_the_generator():
    for name, text in generate.build().items():
        assert (ROOT / "data" / "scenarios" / name).read_text(encoding="utf-8") == text, \
            f"{name} is stale: run python data/generate.py"


def test_coverage_doc_is_up_to_date():
    expected = coverage_markdown(RULESET, list(RESULTS.values()))
    assert COVERAGE.read_text(encoding="utf-8") == expected, "run python src/run_lab.py --write-docs"
