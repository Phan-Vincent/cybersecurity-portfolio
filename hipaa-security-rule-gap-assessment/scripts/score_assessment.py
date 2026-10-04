#!/usr/bin/env python3
"""
score_assessment.py

Ingests a completed HIPAA Security Rule assessment CSV, scores every gap by
likelihood x impact x PHI exposure, and writes a prioritized remediation
roadmap (Markdown) plus a machine-readable risk register (CSV or JSON).

Usage:
    python scripts/score_assessment.py \
        --assessment data/sample_pharmacy_assessment.csv \
        --output output/gap_report.md \
        --register output/risk_register.csv

Scoring (see README "Risk Scoring Methodology"):
    Risk Score = Likelihood (1-5) x Impact (1-5) x PHI Exposure Multiplier

    Likelihood defaults from assessment_status, Impact from whether the
    implementation specification is Required or Addressable. Either can be
    overridden per row with optional `likelihood` / `impact` CSV columns when
    the assessor has better information.
"""

import argparse
import csv
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import date, datetime
from pathlib import Path

CONTROLS_PATH = Path(__file__).parent.parent / "controls" / "hipaa_security_controls.json"

# Refuse absurdly large inputs: a full assessment is ~60 rows / ~50 KB.
MAX_INPUT_BYTES = 5 * 1024 * 1024

VALID_STATUSES = ("Compliant", "Partial", "Non-Compliant", "Not Assessed", "Not Applicable")
GAP_STATUSES = ("Partial", "Non-Compliant", "Not Assessed")

# An unassessed control is treated as more likely deficient than a known partial:
# you cannot defend a control you have never looked at.
DEFAULT_LIKELIHOOD = {"Non-Compliant": 5, "Not Assessed": 4, "Partial": 3}
DEFAULT_IMPACT = {"Required": 4, "Addressable": 3}
PHI_MULTIPLIER = {"High": 1.5, "Medium": 1.25, "Low": 1.0}

# (severity, minimum score, remediation window)
SEVERITY_BANDS = (
    ("Critical", 30.0, "0-30 days"),
    ("High", 20.0, "31-90 days"),
    ("Medium", 10.0, "91-180 days"),
    ("Low", 0.0, "Next annual review"),
)
SEVERITY_ORDER = [b[0] for b in SEVERITY_BANDS]

# Characters that make spreadsheet apps evaluate a cell as a formula
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


class AssessmentError(ValueError):
    """Raised when the assessment input cannot be trusted."""


@dataclass
class Gap:
    control_id: str
    safeguard_category: str
    standard: str
    implementation_specification: str
    cfr_reference: str
    assessment_status: str
    phi_exposure: str
    likelihood: int
    impact: int
    risk_score: float
    severity: str
    remediation_window: str
    finding_notes: str
    remediation_owner: str
    target_date: str
    overdue: bool


def load_catalog(path: Path) -> dict[str, dict]:
    with open(path, "r", encoding="utf-8") as fh:
        catalog = json.load(fh)
    return {c["id"]: c for c in catalog.get("safeguards", [])}


def severity_for(score: float) -> tuple[str, str]:
    for name, floor, window in SEVERITY_BANDS:
        if score >= floor:
            return name, window
    return SEVERITY_BANDS[-1][0], SEVERITY_BANDS[-1][2]


def _bounded_int(value: str, field: str, control_id: str) -> int | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        n = int(value)
    except ValueError:
        raise AssessmentError(f"{control_id}: {field} must be an integer 1-5, got {value!r}")
    if not 1 <= n <= 5:
        raise AssessmentError(f"{control_id}: {field} must be between 1 and 5, got {n}")
    return n


def _parse_date(value: str) -> date | None:
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except (ValueError, AttributeError):
        return None


def read_assessment(path: Path) -> list[dict]:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise AssessmentError(f"{path} is larger than {MAX_INPUT_BYTES} bytes; refusing to parse")
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        missing = {"control_id", "assessment_status"} - set(reader.fieldnames or [])
        if missing:
            raise AssessmentError(f"{path} is missing required column(s): {', '.join(sorted(missing))}")
        return list(reader)


def score_rows(rows: list[dict], catalog: dict[str, dict], as_of: date) -> tuple[list[Gap], dict]:
    """Validate and score assessment rows. Returns (gaps, summary)."""
    seen: set[str] = set()
    status_counts: Counter = Counter()
    by_category: dict[str, Counter] = {}
    warnings: list[str] = []
    gaps: list[Gap] = []

    # Controls missing from the CSV entirely are unassessed gaps too
    present = {(r.get("control_id") or "").strip() for r in rows}
    for cid in sorted(set(catalog) - present):
        warnings.append(f"{cid}: not present in assessment; treated as Not Assessed")
    rows = rows + [{"control_id": cid, "assessment_status": "Not Assessed"} for cid in sorted(set(catalog) - present)]

    for row in rows:
        cid = (row.get("control_id") or "").strip()
        if cid not in catalog:
            raise AssessmentError(f"Unknown control_id {cid!r} (not in controls catalog)")
        if cid in seen:
            raise AssessmentError(f"Duplicate control_id {cid!r}")
        seen.add(cid)

        status = (row.get("assessment_status") or "").strip() or "Not Assessed"
        if status not in VALID_STATUSES:
            raise AssessmentError(f"{cid}: invalid assessment_status {status!r}; expected one of {VALID_STATUSES}")

        ctrl = catalog[cid]
        category = ctrl["safeguard_category"]
        status_counts[status] += 1
        by_category.setdefault(category, Counter())[status] += 1

        if status not in GAP_STATUSES:
            continue

        spec = ctrl["implementation_specification"]
        phi = ctrl.get("phi_exposure", "Medium")
        likelihood = _bounded_int(row.get("likelihood", ""), "likelihood", cid) or DEFAULT_LIKELIHOOD[status]
        impact = _bounded_int(row.get("impact", ""), "impact", cid) or DEFAULT_IMPACT.get(spec, 3)
        score = round(likelihood * impact * PHI_MULTIPLIER.get(phi, 1.25), 2)
        severity, window = severity_for(score)

        target = (row.get("target_date") or "").strip()
        target_d = _parse_date(target)
        if target and target_d is None:
            warnings.append(f"{cid}: unparseable target_date {target!r} (expected YYYY-MM-DD)")
        if not (row.get("remediation_owner") or "").strip():
            warnings.append(f"{cid}: {severity} gap has no remediation_owner")

        gaps.append(Gap(
            control_id=cid,
            safeguard_category=category,
            standard=ctrl["standard"],
            implementation_specification=spec,
            cfr_reference=ctrl["cfr_reference"],
            assessment_status=status,
            phi_exposure=phi,
            likelihood=likelihood,
            impact=impact,
            risk_score=score,
            severity=severity,
            remediation_window=window,
            finding_notes=(row.get("finding_notes") or "").strip(),
            remediation_owner=(row.get("remediation_owner") or "").strip(),
            target_date=target,
            overdue=bool(target_d and target_d < as_of),
        ))

    gaps.sort(key=lambda g: (-g.risk_score, g.control_id))

    applicable = sum(n for s, n in status_counts.items() if s != "Not Applicable")
    summary = {
        "as_of": as_of.isoformat(),
        "controls_total": sum(status_counts.values()),
        "status_counts": dict(status_counts),
        "by_category": {k: dict(v) for k, v in sorted(by_category.items())},
        "compliance_pct": round(100.0 * status_counts["Compliant"] / applicable, 1) if applicable else 0.0,
        "severity_counts": {s: sum(1 for g in gaps if g.severity == s) for s in SEVERITY_ORDER},
        "overdue": sum(1 for g in gaps if g.overdue),
        "warnings": warnings,
    }
    return gaps, summary


def _md_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(gaps: list[Gap], summary: dict, source: str) -> str:
    lines = [
        "# HIPAA Security Rule Gap Assessment — Remediation Roadmap",
        "",
        f"**Assessment source:** `{source}`  ",
        f"**Scored as of:** {summary['as_of']}  ",
        "**Data classification:** Synthetic demo data — no real PHI",
        "",
        "## Executive Summary",
        "",
        f"- **Controls assessed:** {summary['controls_total']}",
        f"- **Fully compliant:** {summary['status_counts'].get('Compliant', 0)} "
        f"({summary['compliance_pct']}% of applicable controls)",
        f"- **Open gaps:** {len(gaps)} — "
        + ", ".join(f"{summary['severity_counts'][s]} {s}" for s in SEVERITY_ORDER),
        f"- **Gaps past their target date:** {summary['overdue']}",
        "",
        "| Safeguard | " + " | ".join(VALID_STATUSES) + " |",
        "|---|" + "---|" * len(VALID_STATUSES),
    ]
    for cat, counts in summary["by_category"].items():
        lines.append(f"| {cat} | " + " | ".join(str(counts.get(s, 0)) for s in VALID_STATUSES) + " |")
    lines += [
        "",
        "## Prioritized Risk Register",
        "",
        "Risk Score = Likelihood × Impact × PHI Exposure Multiplier (High 1.5 / Medium 1.25 / Low 1.0).",
        "",
        "| Rank | Control | CFR | Status | PHI | L | I | Score | Severity | Owner | Target |",
        "|---:|---|---|---|---|---:|---:|---:|---|---|---|",
    ]
    for i, g in enumerate(gaps, 1):
        target = g.target_date or "—"
        if g.overdue:
            target += " ⚠ overdue"
        lines.append(
            f"| {i} | {g.control_id} — {_md_cell(g.standard)} | {g.cfr_reference} | {g.assessment_status} | "
            f"{g.phi_exposure} | {g.likelihood} | {g.impact} | {g.risk_score:g} | {g.severity} | "
            f"{_md_cell(g.remediation_owner) or 'UNASSIGNED'} | {target} |"
        )
    lines += ["", "## Remediation Roadmap", ""]
    for name, _, window in SEVERITY_BANDS:
        phase = [g for g in gaps if g.severity == name]
        if not phase:
            continue
        lines += [f"### {name} — remediate within {window} ({len(phase)})", ""]
        for g in phase:
            note = _md_cell(g.finding_notes) or "No finding notes recorded."
            lines.append(f"- [ ] **{g.control_id}** ({g.cfr_reference}, {g.implementation_specification}) — {note}")
        lines.append("")
    if summary["warnings"]:
        lines += ["## Data Quality Warnings", ""]
        lines += [f"- {_md_cell(w)}" for w in summary["warnings"]]
        lines.append("")
    lines += [
        "---",
        "",
        "*Generated by `scripts/score_assessment.py`. Scores support prioritization; they do not replace "
        "the documented risk analysis required by 45 CFR 164.308(a)(1)(ii)(A).*",
        "",
    ]
    return "\n".join(lines)


def _csv_safe(value):
    """Neutralise spreadsheet formula injection in free-text cells."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def write_register(gaps: list[Gap], summary: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".json":
        payload = {"summary": summary, "gaps": [asdict(g) for g in gaps]}
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return
    fields = list(Gap.__dataclass_fields__)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for g in gaps:
            writer.writerow({k: _csv_safe(v) for k, v in asdict(g).items()})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score a completed HIPAA Security Rule gap assessment.")
    parser.add_argument("--assessment", "-a", type=Path, required=True, help="Completed assessment CSV")
    parser.add_argument("--controls", "-c", type=Path, default=CONTROLS_PATH, help="Controls JSON catalog")
    parser.add_argument("--output", "-o", type=Path, default=Path("output/gap_report.md"), help="Markdown roadmap path")
    parser.add_argument("--register", "-r", type=Path, help="Optional risk register path (.csv or .json)")
    parser.add_argument("--as-of", type=lambda s: datetime.strptime(s, "%Y-%m-%d").date(),
                        default=date.today(), help="Date used for overdue checks (YYYY-MM-DD, default today)")
    args = parser.parse_args(argv)

    for p in (args.assessment, args.controls):
        if not p.exists():
            print(f"[ERROR] File not found: {p}", file=sys.stderr)
            return 1

    try:
        gaps, summary = score_rows(read_assessment(args.assessment), load_catalog(args.controls), args.as_of)
    except AssessmentError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_markdown(gaps, summary, args.assessment.name), encoding="utf-8")
    if args.register:
        write_register(gaps, summary, args.register)

    sev = ", ".join(f"{summary['severity_counts'][s]} {s}" for s in SEVERITY_ORDER)
    print(f"Scored {summary['controls_total']} controls: {len(gaps)} gaps ({sev}); "
          f"{summary['compliance_pct']}% compliant")
    print(f"  Roadmap:  {args.output}")
    if args.register:
        print(f"  Register: {args.register}")
    for w in summary["warnings"]:
        print(f"  [WARN] {w}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
