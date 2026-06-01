#!/usr/bin/env python3
"""
generate_checklist.py

Reads the master HIPAA Security Rule controls catalog and generates an empty
CSV assessment checklist ready for an assessor to fill in.

Usage:
    python generate_checklist.py --output my_assessment.csv
    python generate_checklist.py --output my_assessment.csv --controls ../controls/hipaa_security_controls.json
"""

import argparse
import csv
import json
import sys
from pathlib import Path


CONTROLS_PATH = Path(__file__).parent.parent / "controls" / "hipaa_security_controls.json"

DEFAULT_OUTPUT_COLUMNS = [
    "control_id",
    "safeguard_category",
    "standard",
    "implementation_specification",
    "cfr_reference",
    "control_description",
    "pharmacy_context",
    "assessment_question",
    "evidence_example",
    "assessment_status",          # Compliant / Partial / Non-Compliant / Not Assessed / Not Applicable
    "evidence_description",       # What evidence was reviewed
    "finding_notes",              # Narrative of the finding
    "remediation_owner",          # Who is responsible for fixing
    "target_date",                # When fix should be completed
]


def load_controls(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def flatten_control(ctrl: dict) -> dict:
    """Map a single control JSON object to CSV row dict."""
    return {
        "control_id": ctrl["id"],
        "safeguard_category": ctrl["safeguard_category"],
        "standard": ctrl["standard"],
        "implementation_specification": ctrl["implementation_specification"],
        "cfr_reference": ctrl["cfr_reference"],
        "control_description": ctrl["control_description"],
        "pharmacy_context": ctrl["pharmacy_context"],
        "assessment_question": ctrl["assessment_question"],
        "evidence_example": ctrl["evidence_example"],
        "assessment_status": "Not Assessed",
        "evidence_description": "",
        "finding_notes": "",
        "remediation_owner": "",
        "target_date": "",
    }


def write_csv(rows: list[dict], out_path: Path):
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=DEFAULT_OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description="Generate an empty HIPAA Security Rule gap-assessment checklist.")
    parser.add_argument("--output", "-o", required=True, help="Path for the output CSV file")
    parser.add_argument("--controls", "-c", type=Path, default=CONTROLS_PATH, help="Path to controls JSON catalog")
    args = parser.parse_args()

    if not args.controls.exists():
        print(f"[ERROR] Controls file not found: {args.controls}", file=sys.stderr)
        sys.exit(1)

    catalog = load_controls(args.controls)
    rows = [flatten_control(ctrl) for ctrl in catalog.get("safeguards", [])]

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_csv(rows, out)

    print(f"Generated empty checklist: {out}")
    print(f"  Controls: {len(rows)}")
    print(f"  Columns:  {len(DEFAULT_OUTPUT_COLUMNS)}")
    print("\nNext step: Open the CSV and fill in assessment_status, evidence_description,")
    print("finding_notes, remediation_owner, and target_date for each control.")


if __name__ == "__main__":
    main()
