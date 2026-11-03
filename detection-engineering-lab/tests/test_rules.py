"""
test_rules.py
Every rule is well-formed Sigma, compiles, is mapped to ATT&CK and is proven by a scenario.
"""

import re
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from run_lab import RULES, TACTICS, TECHNIQUE, run  # noqa: E402
from sigma_lite import compile_rule, load_rules  # noqa: E402

ALL = load_rules(RULES)
LEVELS = {"informational", "low", "medium", "high", "critical"}
REQUIRED = {"title", "id", "name", "status", "description", "author", "date", "level"}


@pytest.mark.parametrize("rule", ALL, ids=lambda r: r.name)
def test_required_fields_and_formats(rule):
    missing = REQUIRED - set(rule.data)
    assert not missing, f"{rule.path.name} is missing {sorted(missing)}"
    assert str(uuid.UUID(rule.id)) == rule.id, "id must be a lowercase UUID"
    assert rule.level in LEVELS
    assert re.fullmatch(r"[a-z0-9_]+", rule.name)
    assert rule.path.stem == rule.name, "file name should match the rule name"
    assert rule.is_correlation or {"logsource", "detection"} <= set(rule.data)


@pytest.mark.parametrize("rule", [r for r in ALL if r.level != "informational"], ids=lambda r: r.name)
def test_alerting_rules_map_to_attack(rule):
    techniques = [t for t in rule.tags if TECHNIQUE.match(t)]
    tactics = [t for t in rule.tags if t.split(".", 1)[1] in TACTICS]
    assert techniques and tactics, f"{rule.name} needs an ATT&CK tactic and technique tag"
    assert rule.data.get("falsepositives"), f"{rule.name} should document false positives"


def test_ids_and_names_are_unique():
    assert len({r.id for r in ALL}) == len(ALL)
    assert len({r.name for r in ALL}) == len(ALL)


@pytest.mark.parametrize("rule", [r for r in ALL if not r.is_correlation], ids=lambda r: r.name)
def test_every_detection_rule_compiles(rule):
    compile_rule(rule)


def test_correlations_reference_existing_rules():
    names = {r.name for r in ALL} | {r.id for r in ALL}
    for rule in (r for r in ALL if r.is_correlation):
        for ref in rule.data["correlation"]["rules"]:
            assert ref in names, f"{rule.name} references unknown rule {ref}"


def test_every_alerting_rule_is_proven_by_a_scenario():
    fired = {name for result in run(ALL) for name in result["fired"]}
    unproven = {r.name for r in ALL if r.level != "informational"} - fired
    assert not unproven, f"rules no scenario exercises: {sorted(unproven)}"
