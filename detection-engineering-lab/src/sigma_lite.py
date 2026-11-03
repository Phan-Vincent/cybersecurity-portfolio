"""
sigma_lite.py
A small, dependency-light evaluator for Sigma detection rules over JSON events.

Supported (a deliberate subset of the Sigma specification):
- logsource matching on product / category / service
- detection maps (AND of fields) and lists of maps (OR); value lists (OR)
- plain values with * and ? wildcards, case-insensitive
- modifiers: contains, startswith, endswith, re, all, cidr, gt, gte, lt, lte
- null values (field absent)
- conditions with and / or / not / parentheses, "1 of X*", "all of X*", "them"
- Sigma 2.0 correlation rules of type event_count and value_count, with group-by,
  timespan and a gte/gt/lte/lt/eq condition. Base rules referenced by a correlation
  do not alert on their own unless the correlation sets generate: true.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

import yaml

MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cidr", "gt", "gte", "lt", "lte"}
TIMESPAN = re.compile(r"^(\d+)([smhd])$")
UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


class RuleError(ValueError):
    """A rule uses syntax this evaluator does not support or is malformed."""


@dataclass
class Rule:
    data: dict
    path: Path | None = None

    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def name(self) -> str:
        return self.data.get("name", self.data["id"])

    @property
    def title(self) -> str:
        return self.data["title"]

    @property
    def level(self) -> str:
        return self.data.get("level", "medium")

    @property
    def tags(self) -> list[str]:
        return list(self.data.get("tags", []))

    @property
    def is_correlation(self) -> bool:
        return "correlation" in self.data


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    title: str
    level: str
    tags: list[str]
    event_ids: list[str] = field(default_factory=list)
    group: dict = field(default_factory=dict)


# ---------------------------------------------------------------- loading

def load_rules(directory: Path) -> list[Rule]:
    rules = []
    for path in sorted(Path(directory).rglob("*.yml")):
        with open(path, encoding="utf-8") as fh:
            rules.append(Rule(yaml.safe_load(fh), path))
    return rules


# ---------------------------------------------------------------- field matching

def _split_key(key: str) -> tuple[str, list[str]]:
    name, *mods = key.split("|")
    unknown = set(mods) - MODIFIERS
    if unknown:
        raise RuleError(f"unsupported modifier(s) {sorted(unknown)} in {key!r}")
    return name, mods


def _match_one(actual: Any, expected: Any, mods: list[str]) -> bool:
    if expected is None:
        return actual is None
    if actual is None:
        return False
    if any(m in mods for m in ("gt", "gte", "lt", "lte")):
        try:
            a, e = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return ((("gt" in mods) and a > e) or (("gte" in mods) and a >= e)
                or (("lt" in mods) and a < e) or (("lte" in mods) and a <= e))
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    a, e = str(actual), str(expected)
    if "re" in mods:
        return re.search(e, a) is not None
    a, e = a.lower(), e.lower()
    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)
    if "*" in e or "?" in e:
        return fnmatch.fnmatchcase(a, e)
    return a == e


def _match_field(event: dict, key: str, expected: Any) -> bool:
    name, mods = _split_key(key)
    actual = event.get(name)
    values = expected if isinstance(expected, list) else [expected]
    combine = all if "all" in mods else any
    return combine(_match_one(actual, v, mods) for v in values)


def _match_item(event: dict, item: Any) -> bool:
    """A detection item: a map (AND of fields) or a list of maps (OR)."""
    if isinstance(item, dict):
        return all(_match_field(event, k, v) for k, v in item.items())
    if isinstance(item, list) and all(isinstance(x, dict) for x in item):
        return any(_match_item(event, x) for x in item)
    raise RuleError(f"unsupported detection item {item!r} (keyword searches are not supported)")


# ---------------------------------------------------------------- conditions

_TOKEN = re.compile(r"\(|\)|[A-Za-z0-9_*]+")


class _Condition:
    """Recursive-descent parser: or < and < not < atom."""

    def __init__(self, text: str, items: dict):
        self.tokens = _TOKEN.findall(text)
        self.pos = 0
        self.items = items

    def parse(self):
        node = self._or()
        if self.pos != len(self.tokens):
            raise RuleError(f"unexpected token {self.tokens[self.pos]!r} in condition")
        return node

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self):
        token = self._peek()
        if token is None:
            raise RuleError("condition ended early")
        self.pos += 1
        return token

    def _or(self):
        node = self._and()
        while self._peek() == "or":
            self._take()
            left, right = node, self._and()
            node = lambda e, l=left, r=right: l(e) or r(e)
        return node

    def _and(self):
        node = self._not()
        while self._peek() == "and":
            self._take()
            left, right = node, self._not()
            node = lambda e, l=left, r=right: l(e) and r(e)
        return node

    def _not(self):
        if self._peek() == "not":
            self._take()
            inner = self._not()
            return lambda e, i=inner: not i(e)
        return self._atom()

    def _names(self, pattern: str) -> list[str]:
        names = [n for n in self.items if pattern == "them" or fnmatch.fnmatchcase(n, pattern)]
        if not names:
            raise RuleError(f"no detection items match {pattern!r}")
        return names

    def _atom(self):
        token = self._take()
        if token == "(":
            node = self._or()
            if self._take() != ")":
                raise RuleError("missing ')' in condition")
            return node
        if token in ("1", "all") and self._peek() == "of":
            self._take()
            names = self._names(self._take())
            combine = any if token == "1" else all
            return lambda e, ns=names, c=combine: c(_match_item(e, self.items[n]) for n in ns)
        if token not in self.items:
            raise RuleError(f"condition references unknown item {token!r}")
        return lambda e, t=token: _match_item(e, self.items[t])


def compile_rule(rule: Rule):
    detection = dict(rule.data["detection"])
    condition = detection.pop("condition")
    if not isinstance(condition, str):
        raise RuleError("only a single string condition is supported")
    matcher = _Condition(condition, detection).parse()
    logsource = rule.data.get("logsource", {})

    def matches(event: dict) -> bool:
        source = event.get("_logsource", {})
        if any(source.get(k) != v for k, v in logsource.items() if k in ("product", "category", "service")):
            return False
        return matcher(event)

    return matches


# ---------------------------------------------------------------- correlation

def _timespan(text: str) -> timedelta:
    m = TIMESPAN.match(str(text))
    if not m:
        raise RuleError(f"unsupported timespan {text!r}")
    return timedelta(**{UNITS[m.group(2)]: int(m.group(1))})


def _threshold_met(value: int, condition: dict) -> bool:
    ops = {"gte": value.__ge__, "gt": value.__gt__, "lte": value.__le__,
           "lt": value.__lt__, "eq": value.__eq__}
    checks = [ops[k](v) for k, v in condition.items() if k in ops]
    if not checks:
        raise RuleError(f"correlation condition needs gte/gt/lte/lt/eq: {condition!r}")
    return all(checks)


def _timestamp(event: dict) -> datetime:
    return datetime.fromisoformat(str(event["@timestamp"]).replace("Z", "+00:00"))


def _correlate(rule: Rule, base_hits: list[dict]) -> list[Alert]:
    spec = rule.data["correlation"]
    kind = spec["type"]
    if kind not in ("event_count", "value_count"):
        raise RuleError(f"unsupported correlation type {kind!r}")
    group_by = spec.get("group-by", [])
    span = _timespan(spec["timespan"])
    condition = dict(spec["condition"])
    value_field = condition.pop("field", None)
    if kind == "value_count" and not value_field:
        raise RuleError("value_count correlation needs condition.field")

    groups: dict[tuple, list[dict]] = {}
    for event in base_hits:
        groups.setdefault(tuple(event.get(g) for g in group_by), []).append(event)

    alerts = []
    for key, events in groups.items():
        events.sort(key=_timestamp)
        start = 0
        for end in range(len(events)):
            while _timestamp(events[end]) - _timestamp(events[start]) > span:
                start += 1
            window = events[start:end + 1]
            measure = (len(window) if kind == "event_count"
                       else len({e.get(value_field) for e in window}))
            if _threshold_met(measure, condition):
                alerts.append(Alert(rule.id, rule.name, rule.title, rule.level, rule.tags,
                                    [e["_id"] for e in window], dict(zip(group_by, key))))
                break  # one alert per group
    return alerts


# ---------------------------------------------------------------- engine

def evaluate(rules: Iterable[Rule], events: list[dict]) -> list[Alert]:
    rules = list(rules)
    by_ref = {}
    for r in rules:
        by_ref[r.id] = r
        by_ref[r.name] = r

    suppressed = set()
    for r in rules:
        if r.is_correlation and not r.data["correlation"].get("generate", False):
            suppressed.update(by_ref[ref].id for ref in r.data["correlation"]["rules"])

    hits: dict[str, list[dict]] = {}
    alerts = []
    for r in rules:
        if r.is_correlation:
            continue
        matcher = compile_rule(r)
        hits[r.id] = [e for e in events if matcher(e)]
        if r.id not in suppressed and hits[r.id]:
            alerts.extend(Alert(r.id, r.name, r.title, r.level, r.tags, [e["_id"]]) for e in hits[r.id])

    for r in rules:
        if r.is_correlation:
            refs = r.data["correlation"]["rules"]
            base = [e for ref in refs for e in hits[by_ref[ref].id]]
            alerts.extend(_correlate(r, base))
    return alerts
