"""
test_engine.py
Unit tests for the sigma_lite evaluator: value matching, modifiers, conditions and
correlation windows (including exact threshold boundaries).
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sigma_lite import Rule, RuleError, evaluate  # noqa: E402

SRC = {"product": "test"}


def rule(detection, name="r", **extra):
    return Rule({"title": name, "id": name, "name": name, "level": "high",
                 "logsource": SRC, "detection": detection, **extra})


def event(i=1, ts="2026-10-20T09:00:00Z", **fields):
    return {"_id": f"e{i}", "@timestamp": ts, "_logsource": SRC, **fields}


def fires(detection, **fields):
    return bool(evaluate([rule(detection)], [event(**fields)]))


@pytest.mark.parametrize("detection,fields,expected", [
    ({"s": {"cmd": "ls"}, "condition": "s"}, {"cmd": "LS"}, True),               # case-insensitive
    ({"s": {"cmd": "rm *"}, "condition": "s"}, {"cmd": "rm -rf /tmp"}, True),    # wildcard
    ({"s": {"cmd|contains": "tcp"}, "condition": "s"}, {"cmd": "/dev/TCP/x"}, True),
    ({"s": {"cmd|startswith": "curl"}, "condition": "s"}, {"cmd": "wget curl"}, False),
    ({"s": {"img|endswith": "\\cmd.exe"}, "condition": "s"}, {"img": "C:\\x\\CMD.EXE"}, True),
    ({"s": {"cmd|contains|all": ["a", "b"]}, "condition": "s"}, {"cmd": "a only"}, False),
    ({"s": {"cmd|contains": ["a", "zz"]}, "condition": "s"}, {"cmd": "a only"}, True),
    ({"s": {"cmd|re": "^x[0-9]+$"}, "condition": "s"}, {"cmd": "x42"}, True),
    ({"s": {"ip|cidr": "10.0.0.0/8"}, "condition": "s"}, {"ip": "10.9.8.7"}, True),
    ({"s": {"ip|cidr": "10.0.0.0/8"}, "condition": "s"}, {"ip": "not-an-ip"}, False),
    ({"s": {"n|gte": 5}, "condition": "s"}, {"n": 5}, True),
    ({"s": {"n|gt": 5}, "condition": "s"}, {"n": 5}, False),
    ({"s": {"reason": None}, "condition": "s"}, {}, True),                       # null = absent
    ({"s": {"reason": None}, "condition": "s"}, {"reason": "x"}, False),
    ({"s": {"a": 1, "b": 2}, "condition": "s"}, {"a": 1, "b": 3}, False),        # map = AND
    ({"s": [{"a": 1}, {"b": 2}], "condition": "s"}, {"b": 2}, True),             # list of maps = OR
])
def test_value_matching(detection, fields, expected):
    assert fires(detection, **fields) is expected


@pytest.mark.parametrize("condition,expected", [
    ("a and not b", True),
    ("a and b", False),
    ("not (a or b)", False),
    ("a and (b or c)", True),
    ("not a or c", True),
    ("1 of sel_*", True),
    ("all of sel_*", False),
    ("all of them", False),
    ("a and b or c", True),      # and binds tighter than or
])
def test_conditions(condition, expected):
    detection = {"a": {"x": 1}, "b": {"y": 1}, "c": {"z": 1},
                 "sel_1": {"x": 1}, "sel_2": {"y": 1}, "condition": condition}
    assert fires(detection, x=1, z=1) is expected


@pytest.mark.parametrize("detection", [
    {"s": {"x|base64": "a"}, "condition": "s"},
    {"s": {"x": 1}, "condition": "s and missing"},
    {"s": {"x": 1}, "condition": "(s"},
    {"s": ["keyword"], "condition": "s"},
])
def test_unsupported_or_broken_rules_raise(detection):
    with pytest.raises(RuleError):
        fires(detection, x=1)


def test_logsource_must_match():
    r = rule({"s": {"x": 1}, "condition": "s"})
    assert not evaluate([r], [{"_id": "e", "@timestamp": "2026-10-20T09:00:00Z",
                               "_logsource": {"product": "other"}, "x": 1}])


def _correlation(kind, condition, timespan="5m", group_by=("src",)):
    base = rule({"s": {"action": "fail"}, "condition": "s"}, name="base", level="informational")
    corr = Rule({"title": "c", "id": "c", "name": "c", "level": "high",
                 "correlation": {"type": kind, "rules": ["base"], "group-by": list(group_by),
                                 "timespan": timespan, "condition": condition}})
    return [base, corr]


def _fails(n, step_seconds, src="1.2.3.4", users=None):
    return [event(i, f"2026-10-20T09:{(i * step_seconds) // 60:02d}:{(i * step_seconds) % 60:02d}Z",
                  action="fail", src=src, user=(users[i % len(users)] if users else "u"))
            for i in range(n)]


def test_event_count_threshold_boundary():
    rules = _correlation("event_count", {"gte": 8})
    assert [a.rule_name for a in evaluate(rules, _fails(8, 10))] == ["c"]
    assert evaluate(rules, _fails(7, 10)) == []          # one below the threshold


def test_event_count_respects_timespan():
    rules = _correlation("event_count", {"gte": 8}, timespan="1m")
    assert evaluate(rules, _fails(8, 10)) == []          # 8 events span 70 s
    assert evaluate(rules, _fails(8, 8)) != []           # 8 events span 56 s


def test_event_count_groups_by_field():
    rules = _correlation("event_count", {"gte": 8})
    events = _fails(4, 10, src="1.1.1.1") + _fails(4, 10, src="2.2.2.2")
    assert evaluate(rules, events) == []


def test_value_count_counts_distinct_values():
    rules = _correlation("value_count", {"gte": 3, "field": "user"}, group_by=())
    assert evaluate(rules, _fails(10, 5, users=["a", "b"])) == []
    assert evaluate(rules, _fails(3, 5, users=["a", "b", "c"])) != []


def test_base_rule_is_suppressed_unless_generate_true():
    rules = _correlation("event_count", {"gte": 100})
    assert evaluate(rules, _fails(3, 10)) == []
    rules[1].data["correlation"]["generate"] = True
    assert {a.rule_name for a in evaluate(rules, _fails(3, 10))} == {"base"}
