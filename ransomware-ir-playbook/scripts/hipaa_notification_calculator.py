#!/usr/bin/env python3
"""
hipaa_notification_calculator.py
Calculate all HIPAA breach notification deadlines for a pharmacy/healthcare incident.

Purpose:
    Given the discovery date, number of affected individuals, and state, this script
    computes all required notification deadlines under HIPAA (45 CFR 164.400-414) and
    common state pharmacy board requirements. It also generates a markdown checklist
    for incident responders.

    Key deadlines:
    - 60 days: Individual notice (first-class mail or email if authorized)
    - 60 days: Media notice (if >500 individuals affected in a single state)
    - Immediately (no later than 60 days): HHS Secretary notice if 500 or more individuals
    - 60 days after end of calendar year: HHS Secretary notice if fewer than 500 individuals
    - State pharmacy board: varies (typically 24-72 hours for significant incidents)
    - Business associates: 60 days (or per BAA)

    Synthetic data only. No real patient information.

Output:
    - JSON schedule with all deadlines
    - Markdown checklist for incident commander

Author: Vincent Phan (CPhT, Entry-level IT/Cybersecurity student)
License: MIT
"""

import json
import sys
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional


# ──────────────────────────────────────────────────────────────────────────────
# Federal thresholds — note the regulations use different comparisons:
#   164.408(b): breaches involving 500 OR MORE individuals -> HHS within 60 days
#   164.406(a): MORE THAN 500 residents of a State/jurisdiction -> media notice
# ──────────────────────────────────────────────────────────────────────────────
HHS_IMMEDIATE_THRESHOLD = 500   # affected_count >= this
MEDIA_NOTICE_THRESHOLD = 500    # affected_count > this


def hhs_notice_is_immediate(affected_count: int) -> bool:
    return affected_count >= HHS_IMMEDIATE_THRESHOLD


# ──────────────────────────────────────────────────────────────────────────────
# State Law Lookup Table (abbreviated for CA, TX, NY, FL as examples)
# ──────────────────────────────────────────────────────────────────────────────
STATE_LAWS = {
    "CA": {
        "name": "California",
        "pharmacy_board": "California State Board of Pharmacy",
        "board_notice_hours": 72,
        "board_notice_desc": "Notify CA Board of Pharmacy within 72 hours if ePHI or controlled substance data compromised.",
        "additional_law": "California Civil Code 1798.82 (CMIA)",
        "additional_deadline_days": None,  # HIPAA controls, but CA AG may require additional reporting
        "notes": "California requires breach notification to affected residents without unreasonable delay. "
                 "For pharmacies, CA BOP may also require incident reporting if controlled substance data is involved.",
        "contact_url": "https://www.pharmacy.ca.gov/",
    },
    "TX": {
        "name": "Texas",
        "pharmacy_board": "Texas State Board of Pharmacy",
        "board_notice_hours": 24,
        "board_notice_desc": "Notify TX Board of Pharmacy within 24 hours for significant incidents affecting pharmacy operations or ePHI.",
        "additional_law": "Texas Business and Commerce Code 521.053 (TIDITA)",
        "additional_deadline_days": 60,
        "notes": "Texas requires notification to AG if >10,000 residents affected. "
                 "Pharmacy-specific: TX BOP may require immediate notification for data breaches involving prescription data.",
        "contact_url": "https://www.pharmacy.texas.gov/",
    },
    "NY": {
        "name": "New York",
        "pharmacy_board": "New York State Board of Pharmacy",
        "board_notice_hours": 72,
        "board_notice_desc": "Notify NY Board of Pharmacy within 72 hours if ePHI or patient data compromised.",
        "additional_law": "General Business Law 899-aa (SHIELD Act)",
        "additional_deadline_days": None,
        "notes": "NY requires reasonable promptness (no specific max, but case law suggests ~60 days). "
                 "SHIELD Act applies if private information (not just PHI) is involved. NY BOP may require separate reporting.",
        "contact_url": "https://www.op.nysed.gov/professions/pharmacy/",
    },
    "FL": {
        "name": "Florida",
        "pharmacy_board": "Florida Board of Pharmacy",
        "board_notice_hours": 72,
        "board_notice_desc": "Notify FL Board of Pharmacy within 72 hours if ePHI or patient data compromised.",
        "additional_law": "Florida Statute 501.171 (FIPA)",
        "additional_deadline_days": 30,
        "notes": "Florida requires notification to the Department of Legal Affairs within 30 days if 500 or more residents are affected. "
                 "FL BOP may require incident report for breaches involving pharmacy operations or ePHI.",
        "contact_url": "https://floridaspharmacy.gov/",
    },
    "DEFAULT": {
        "name": "Unknown / Other",
        "pharmacy_board": "State Board of Pharmacy (verify for your state)",
        "board_notice_hours": 72,
        "board_notice_desc": "Most states require notification to the Board of Pharmacy within 24-72 hours for significant incidents.",
        "additional_law": "Varies by state",
        "additional_deadline_days": None,
        "notes": "Always verify your specific state's requirements. Defaulting to 72 hours for pharmacy board notice.",
        "contact_url": "https://nabp.pharmacy/",
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# Core Calculation Logic
# ──────────────────────────────────────────────────────────────────────────────
def calculate_hipaa_deadlines(
    discovery_date_str: str,
    affected_count: int,
    state: str,
    breach_type: str = "unauthorized_access",
) -> Dict[str, Any]:
    """
    Calculate all HIPAA and state notification deadlines.

    Args:
        discovery_date_str: Discovery date in ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS).
        affected_count: Number of individuals affected.
        state: Two-letter state code (e.g., 'CA', 'TX').
        breach_type: Category of breach (e.g., 'unauthorized_access', 'ransomware', 'theft').

    Returns:
        Dictionary with full deadline schedule and metadata.
    """
    # Parse discovery date
    try:
        discovery = datetime.strptime(discovery_date_str, "%Y-%m-%d")
    except ValueError:
        try:
            discovery = datetime.strptime(discovery_date_str, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            try:
                discovery = datetime.strptime(discovery_date_str, "%Y-%m-%dT%H:%M:%S.%f")
            except ValueError:
                raise ValueError(f"Invalid date format: {discovery_date_str}. Expected YYYY-MM-DD or ISO datetime.")

    # Normalize state
    state_upper = state.upper().strip()
    state_info = STATE_LAWS.get(state_upper, STATE_LAWS["DEFAULT"])

    # HIPAA deadlines (45 CFR 164.400-414)
    # Individual notice: without unreasonable delay, not later than 60 days
    individual_notice_deadline = discovery + timedelta(days=60)

    # HHS Secretary notice
    if hhs_notice_is_immediate(affected_count):
        hhs_notice_deadline = discovery + timedelta(days=60)
        hhs_notice_immediate = True
    else:
        # Fewer than 500: within 60 days after end of calendar year (164.408(c))
        year_end = datetime(discovery.year, 12, 31)
        hhs_notice_deadline = year_end + timedelta(days=60)
        hhs_notice_immediate = False

    # Media notice (if >500 individuals in a single state or jurisdiction)
    media_notice_required = affected_count > MEDIA_NOTICE_THRESHOLD
    media_notice_deadline = discovery + timedelta(days=60) if media_notice_required else None

    # State pharmacy board notice
    board_notice_hours = state_info["board_notice_hours"]
    board_notice_deadline = discovery + timedelta(hours=board_notice_hours)

    # Business associate timeline (typically 60 days per BAA, but can vary)
    ba_notice_deadline = discovery + timedelta(days=60)

    # Additional state deadlines
    additional_deadlines = []
    if state_info.get("additional_deadline_days"):
        additional_deadlines.append({
            "name": f"{state_info['name']} Attorney General / Additional State Notification",
            "deadline": (discovery + timedelta(days=state_info["additional_deadline_days"])).strftime("%Y-%m-%d"),
            "days_from_discovery": state_info["additional_deadline_days"],
            "law": state_info["additional_law"],
        })

    # Ransomware-specific considerations
    ransomware_notes = []
    if breach_type.lower() in ("ransomware", "encryption", "malware"):
        ransomware_notes = [
            "Ransomware is presumed to be a reportable breach under HIPAA (unauthorized acquisition).",
            "Document encryption status: if ePHI was encrypted at rest (AES-256) and encryption keys were not compromised, "
            "risk assessment may determine low probability of compromise (164.402(2)(i)).",
            "If ePHI was NOT encrypted at rest, breach is reportable. Individual + HHS + media (if >500) notices required.",
            "If ransom was paid, document as business decision. Payment does NOT guarantee data recovery or confidentiality.",
            "FBI IC3 report should be filed regardless of ransom payment.",
        ]

    return {
        "metadata": {
            "tool": "hipaa_notification_calculator.py",
            "version": "1.0.0",
            "generated_at": datetime.now().isoformat(),
            "author": "Vincent Phan (CPhT, CSUSB-bound IT/Cybersecurity student)",
            "disclaimer": "Synthetic calculation for portfolio. Not legal advice. Consult HIPAA counsel.",
            "discovery_date": discovery.strftime("%Y-%m-%d"),
            "affected_individuals": affected_count,
            "state": state_upper,
            "breach_type": breach_type,
        },
        "state_info": state_info,
        "deadlines": {
            "individual_notice": {
                "description": "Notify affected individuals via first-class mail (or email if authorized per 164.522).",
                "deadline": individual_notice_deadline.strftime("%Y-%m-%d"),
                "days_from_discovery": 60,
                "regulation": "45 CFR 164.404(b)",
                "required": True,
                "urgency": "high",
            },
            "hhs_secretary_notice": {
                "description": "Notify HHS Secretary via breach portal (https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf).",
                "deadline": hhs_notice_deadline.strftime("%Y-%m-%d"),
                "days_from_discovery": 60 if hhs_notice_immediate else f"60 days after end of {discovery.year}",
                "regulation": "45 CFR 164.408",
                "required": True,
                "immediate": hhs_notice_immediate,
                "urgency": "critical" if hhs_notice_immediate else "high",
            },
            "media_notice": {
                "description": "Notify prominent media outlets in the state/jurisdiction if >500 individuals affected.",
                "deadline": media_notice_deadline.strftime("%Y-%m-%d") if media_notice_deadline else None,
                "days_from_discovery": 60 if media_notice_required else None,
                "regulation": "45 CFR 164.406",
                "required": media_notice_required,
                "urgency": "high" if media_notice_required else "none",
            },
            "state_pharmacy_board_notice": {
                "description": state_info["board_notice_desc"],
                "deadline": board_notice_deadline.strftime("%Y-%m-%d %H:%M:%S"),
                "hours_from_discovery": board_notice_hours,
                "regulation": f"State Board of Pharmacy rules ({state_info['name']})",
                "required": True,
                "urgency": "critical",
                "contact_url": state_info.get("contact_url", ""),
            },
            "business_associate_notice": {
                "description": "Business associates must report the breach to the pharmacy (covered entity) without unreasonable delay and within 60 days of their discovery (164.410(b)); confirm BAA terms, which are often shorter.",
                "deadline": ba_notice_deadline.strftime("%Y-%m-%d"),
                "days_from_discovery": 60,
                "regulation": "45 CFR 164.410 + Business Associate Agreement",
                "required": True,
                "urgency": "high",
            },
            "additional_state_notices": additional_deadlines,
        },
        "ransomware_specific_notes": ransomware_notes,
        "checklist_items": generate_checklist_items(
            discovery, affected_count, state_upper, state_info, media_notice_required, breach_type
        ),
    }


def generate_checklist_items(
    discovery: datetime,
    affected_count: int,
    state: str,
    state_info: Dict[str, Any],
    media_required: bool,
    breach_type: str,
) -> List[Dict[str, Any]]:
    """
    Generate a structured checklist of notification tasks.

    Returns:
        List of checklist item dictionaries with done/urgent flags.
    """
    items = [
        {
            "task": "Contain the breach and preserve evidence (memory dumps, disk images, logs).",
            "done": False,
            "urgent": True,
            "assigned_to": "Incident Response Team",
            "deadline": "Immediate",
            "category": "containment",
        },
        {
            "task": "Conduct risk assessment per 164.402(2): determine probability of compromise.",
            "done": False,
            "urgent": True,
            "assigned_to": "Privacy Officer / Security Officer",
            "deadline": (discovery + timedelta(days=5)).strftime("%Y-%m-%d"),
            "category": "assessment",
        },
        {
            "task": "Document all affected individuals, data types, and systems involved.",
            "done": False,
            "urgent": True,
            "assigned_to": "HIPAA Compliance Officer",
            "deadline": (discovery + timedelta(days=7)).strftime("%Y-%m-%d"),
            "category": "documentation",
        },
        {
            "task": f"Notify {state_info['name']} State Board of Pharmacy within {state_info['board_notice_hours']} hours.",
            "done": False,
            "urgent": True,
            "assigned_to": "Pharmacy Manager / Compliance Officer",
            "deadline": (discovery + timedelta(hours=state_info["board_notice_hours"])).strftime("%Y-%m-%d %H:%M:%S"),
            "category": "state_notification",
        },
        {
            "task": "Notify affected individuals via first-class mail (or email if authorized).",
            "done": False,
            "urgent": True,
            "assigned_to": "Compliance / Communications Team",
            "deadline": (discovery + timedelta(days=60)).strftime("%Y-%m-%d"),
            "category": "individual_notification",
        },
        {
            "task": "Notify HHS Secretary via OCR Breach Portal.",
            "done": False,
            "urgent": hhs_notice_is_immediate(affected_count),
            "assigned_to": "HIPAA Compliance Officer",
            "deadline": (discovery + timedelta(days=60)).strftime("%Y-%m-%d") if hhs_notice_is_immediate(affected_count) else (datetime(discovery.year, 12, 31) + timedelta(days=60)).strftime("%Y-%m-%d"),
            "category": "hhs_notification",
        },
    ]

    if media_required:
        items.append({
            "task": "Notify prominent media outlets in the affected state/jurisdiction.",
            "done": False,
            "urgent": True,
            "assigned_to": "Communications / PR Team",
            "deadline": (discovery + timedelta(days=60)).strftime("%Y-%m-%d"),
            "category": "media_notification",
        })

    items.append({
        "task": "Notify all Business Associates (BAs) per BAA terms.",
        "done": False,
        "urgent": True,
        "assigned_to": "Compliance Officer / Legal",
        "deadline": (discovery + timedelta(days=60)).strftime("%Y-%m-%d"),
        "category": "ba_notification",
    })

    items.append({
        "task": "Offer credit monitoring / identity theft protection if warranted.",
        "done": False,
        "urgent": False,
        "assigned_to": "Compliance / Legal",
        "deadline": "As part of individual notice",
        "category": "remediation",
    })

    items.append({
        "task": "File FBI IC3 report (Internet Crime Complaint Center).",
        "done": False,
        "urgent": True,
        "assigned_to": "Security Officer / Legal",
        "deadline": "Immediate",
        "category": "law_enforcement",
    })

    items.append({
        "task": "Update policies and procedures to prevent recurrence.",
        "done": False,
        "urgent": False,
        "assigned_to": "Security / Compliance",
        "deadline": (discovery + timedelta(days=90)).strftime("%Y-%m-%d"),
        "category": "remediation",
    })

    return items


# ──────────────────────────────────────────────────────────────────────────────
# Report Generators
# ──────────────────────────────────────────────────────────────────────────────
def generate_json_report(schedule: Dict[str, Any], output_path: str) -> None:
    """Write JSON schedule report."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(schedule, f, indent=2, ensure_ascii=False)
    print(f"[+] JSON schedule: {output_path}")


def generate_markdown_report(schedule: Dict[str, Any], output_path: str) -> None:
    """Write Markdown checklist report."""
    meta = schedule["metadata"]
    deadlines = schedule["deadlines"]
    state_info = schedule["state_info"]
    checklist = schedule["checklist_items"]
    ransomware_notes = schedule["ransomware_specific_notes"]

    lines = [
        "# HIPAA Breach Notification Calculator",
        "",
        f"> **Tool:** `hipaa_notification_calculator.py` v1.0.0  ",
        f"> **Analyst:** Vincent Phan (CPhT, CSUSB-bound IT/Cybersecurity student)  ",
        f"> **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"> **Disclaimer:** Synthetic calculation for portfolio. Not legal advice. Consult HIPAA counsel.  ",
        "",
        "---",
        "",
        "## Incident Details",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Discovery Date | {meta['discovery_date']} |",
        f"| Affected Individuals | {meta['affected_individuals']:,} |",
        f"| State | {state_info['name']} ({meta['state']}) |",
        f"| Breach Type | {meta['breach_type']} |",
        "",
    ]

    if ransomware_notes:
        lines += [
            "## Ransomware-Specific Notes",
            "",
        ]
        for note in ransomware_notes:
            lines.append(f"- {note}")
        lines.append("")

    lines += [
        "---",
        "",
        "## Notification Deadlines",
        "",
    ]

    for key, deadline in deadlines.items():
        if key == "additional_state_notices":
            continue
        if not deadline.get("required"):
            continue

        lines += [
            f"### {key.replace('_', ' ').title()}",
            "",
            f"- **Description:** {deadline['description']}",
            f"- **Deadline:** {deadline['deadline']}",
            f"- **Regulation:** {deadline['regulation']}",
            f"- **Urgency:** {deadline['urgency'].upper()}",
            "",
        ]
        if deadline.get("contact_url"):
            lines.append(f"- **Contact:** {deadline['contact_url']}")
            lines.append("")

    if deadlines.get("additional_state_notices"):
        lines += [
            "### Additional State Deadlines",
            "",
        ]
        for ad in deadlines["additional_state_notices"]:
            lines += [
                f"- **{ad['name']}**",
                f"  - Deadline: {ad['deadline']}",
                f"  - Law: {ad['law']}",
                "",
            ]

    lines += [
        "---",
        "",
        "## Action Checklist",
        "",
        "| # | Task | Category | Assigned To | Deadline | Urgent | Done |",
        "|---|------|----------|-------------|----------|--------|------|",
    ]

    for idx, item in enumerate(checklist, 1):
        urgent = "YES" if item["urgent"] else "No"
        done = "YES" if item["done"] else "No"
        lines.append(f"| {idx} | {item['task']} | {item['category']} | {item['assigned_to']} | {item['deadline']} | {urgent} | {done} |")

    lines += [
        "",
        "---",
        "",
        "## State-Specific Notes",
        "",
        f"**State:** {state_info['name']}",
        "",
        f"- **Pharmacy Board:** {state_info['pharmacy_board']}",
        f"- **Board Notice:** {state_info['board_notice_desc']}",
        f"- **Additional Laws:** {state_info['additional_law']}",
        "",
        f"{state_info['notes']}",
        "",
        "---",
        "",
        "*End of Report*",
    ]

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[+] Markdown checklist: {output_path}")


# ──────────────────────────────────────────────────────────────────────────────
# CLI & Main
# ──────────────────────────────────────────────────────────────────────────────
def main() -> int:
    """
    CLI entry point for hipaa_notification_calculator.py.

    Returns:
        0 on success, 1 on error.
    """
    parser = argparse.ArgumentParser(
        description="Calculate HIPAA breach notification deadlines for pharmacy/healthcare incidents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Ransomware breach, 1,200 affected, discovered 2026-05-15, California
  python3 hipaa_notification_calculator.py --date 2026-05-15 --count 1200 --state CA --type ransomware

  # Smaller breach, 250 affected, Texas
  python3 hipaa_notification_calculator.py --date 2026-05-15 --count 250 --state TX

Author: Vincent Phan (CPhT, IT/Cybersecurity student)
        """,
    )
    parser.add_argument("--date", required=True, help="Discovery date (YYYY-MM-DD)")
    parser.add_argument("--count", type=int, required=True, help="Number of affected individuals")
    parser.add_argument("--state", required=True, help="Two-letter state code (e.g., CA, TX, NY, FL)")
    parser.add_argument("--type", default="unauthorized_access", help="Breach type (e.g., ransomware, theft, unauthorized_access)")
    parser.add_argument("--json-out", default="hipaa_schedule.json", help="Output JSON path")
    parser.add_argument("--md-out", default="hipaa_checklist.md", help="Output Markdown path")
    args = parser.parse_args()

    print("=" * 60)
    print("HIPAA BREACH NOTIFICATION CALCULATOR")
    print("Pharmacy / Healthcare Incident Response Playbook")
    print("=" * 60)
    print(f"[*] Discovery: {args.date}")
    print(f"[*] Affected:  {args.count:,}")
    print(f"[*] State:     {args.state.upper()}")
    print(f"[*] Type:      {args.type}")
    print("-" * 60)

    try:
        schedule = calculate_hipaa_deadlines(args.date, args.count, args.state, args.type)
    except ValueError as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1

    # Print summary to console
    deadlines = schedule["deadlines"]
    print(f"\n[+] Individual Notice Deadline:     {deadlines['individual_notice']['deadline']}")
    print(f"[+] HHS Secretary Notice Deadline:  {deadlines['hhs_secretary_notice']['deadline']}")
    if deadlines['media_notice']['required']:
        print(f"[+] Media Notice Deadline:          {deadlines['media_notice']['deadline']}")
    print(f"[+] State Board Notice Deadline:    {deadlines['state_pharmacy_board_notice']['deadline']}")
    print(f"[+] BA Notice Deadline:             {deadlines['business_associate_notice']['deadline']}")
    print(f"[+] Checklist Items:                {len(schedule['checklist_items'])}")

    generate_json_report(schedule, args.json_out)
    generate_markdown_report(schedule, args.md_out)

    print("\n" + "=" * 60)
    print("CALCULATION COMPLETE")
    print(f"    JSON: {args.json_out}")
    print(f"    Markdown: {args.md_out}")
    print("=" * 60)
    print("\n[!] DISCLAIMER: This is a student portfolio tool. Not legal advice.")
    print("    Always consult a HIPAA attorney and your state's pharmacy board.")
    return 0


# ──────────────────────────────────────────────────────────────────────────────
# Embedded assertions for self-test
# ──────────────────────────────────────────────────────────────────────────────
# Test: >500 affected triggers media notice
#   python3 -c "import hipaa_notification_calculator as h; s = h.calculate_hipaa_deadlines('2026-05-15', 600, 'CA'); assert s['deadlines']['media_notice']['required'] == True; print('PASS: media_notice >500')"
#
# Test: <500 affected does NOT trigger media notice
#   python3 -c "import hipaa_notification_calculator as h; s = h.calculate_hipaa_deadlines('2026-05-15', 400, 'CA'); assert s['deadlines']['media_notice']['required'] == False; print('PASS: media_notice <500')"
#
# Test: CA board notice is 72 hours
#   python3 -c "import hipaa_notification_calculator as h; s = h.calculate_hipaa_deadlines('2026-05-15', 100, 'CA'); assert s['state_info']['board_notice_hours'] == 72; print('PASS: CA board_notice_hours')"
#
# Test: TX board notice is 24 hours
#   python3 -c "import hipaa_notification_calculator as h; s = h.calculate_hipaa_deadlines('2026-05-15', 100, 'TX'); assert s['state_info']['board_notice_hours'] == 24; print('PASS: TX board_notice_hours')"
#
# Test: Ransomware notes populated
#   python3 -c "import hipaa_notification_calculator as h; s = h.calculate_hipaa_deadlines('2026-05-15', 100, 'CA', 'ransomware'); assert len(s['ransomware_specific_notes']) > 0; print('PASS: ransomware_notes')"
#
# Test: checklist has 10+ items
#   python3 -c "import hipaa_notification_calculator as h; s = h.calculate_hipaa_deadlines('2026-05-15', 100, 'CA'); assert len(s['checklist_items']) >= 10; print('PASS: checklist_items count')"

if __name__ == "__main__":
    sys.exit(main())
