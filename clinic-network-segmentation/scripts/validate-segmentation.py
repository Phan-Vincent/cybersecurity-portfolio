#!/usr/bin/env python3
"""
validate-segmentation.py

Validates the clinic network segmentation design for consistency:
  - Detects overlapping IP subnets
  - Detects duplicate VLAN IDs
  - Detects firewall rules that reference non-existent VLANs
  - Detects rules with source == destination but no intra-VLAN justification
  - Reports high-level statistics

Usage:
    python3 scripts/validate-segmentation.py

Output: prints to stdout with color-coded PASS / WARN / FAIL lines.
"""

import csv
import ipaddress
import sys
from pathlib import Path

# Color codes for terminal output
PASS = "\033[92mPASS\033[0m"
WARN = "\033[93mWARN\033[0m"
FAIL = "\033[91mFAIL\033[0m"
INFO = "\033[94mINFO\033[0m"


def load_csv(path: Path) -> list[dict]:
    """Load a CSV file into a list of dicts."""
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def check_subnet_overlap(vlans: list[dict]) -> list[str]:
    """Detect overlapping subnets between VLANs."""
    issues = []
    networks = []
    for row in vlans:
        try:
            net = ipaddress.ip_network(f"{row['subnet']}/{row['cidr']}", strict=False)
            networks.append((row['vlan_id'], row['vlan_name'], net))
        except ValueError as e:
            issues.append(f"{FAIL}: VLAN {row['vlan_id']} ({row['vlan_name']}) has invalid subnet: {e}")

    for i, (vid_a, name_a, net_a) in enumerate(networks):
        for j, (vid_b, name_b, net_b) in enumerate(networks):
            if i >= j:
                continue
            if net_a.overlaps(net_b):
                issues.append(
                    f"{FAIL}: Subnet overlap between VLAN {vid_a} ({name_a}) {net_a} "
                    f"and VLAN {vid_b} ({name_b}) {net_b}"
                )
    return issues


def check_duplicate_vlans(vlans: list[dict]) -> list[str]:
    """Detect duplicate VLAN IDs."""
    issues = []
    seen = {}
    for row in vlans:
        vid = row['vlan_id']
        if vid in seen:
            issues.append(
                f"{FAIL}: Duplicate VLAN ID {vid}: '{seen[vid]}' and '{row['vlan_name']}'"
            )
        else:
            seen[vid] = row['vlan_name']
    return issues


def check_firewall_vlan_consistency(rules: list[dict], vlans: list[dict]) -> list[str]:
    """Detect firewall rules referencing non-existent VLANs."""
    issues = []
    valid_vlan_ids = {row['vlan_id'] for row in vlans}
    valid_vlan_names = {row['vlan_name'] for row in vlans}
    # Also allow "Any" and "Internet" as pseudo-VLANs
    valid_names = valid_vlan_names | {"Any", "Internet"}

    for row in rules:
        src = row.get('source_vlan', '').strip()
        dst = row.get('dest_vlan', '').strip()
        rule_id = row.get('rule_id', '?')

        # Check source
        if src and src not in valid_names and src not in valid_vlan_ids:
            issues.append(f"{FAIL}: Rule {rule_id} references unknown source VLAN '{src}'")

        # Check destination
        if dst and dst not in valid_names and dst not in valid_vlan_ids:
            issues.append(f"{FAIL}: Rule {rule_id} references unknown destination VLAN '{dst}'")
    return issues


def check_intra_vlan_rules(rules: list[dict]) -> list[str]:
    """Flag rules where source == destination VLAN (intra-VLAN) but action is Deny.
    Intra-VLAN denies are usually handled by the switch L2 ACL, not L3 firewall.
    This is a WARN, not a FAIL — some designs do use L3 for intra-VLAN."""
    issues = []
    for row in rules:
        src = row.get('source_vlan', '').strip()
        dst = row.get('dest_vlan', '').strip()
        action = row.get('action', '').strip()
        if src == dst and action == 'Deny':
            issues.append(
                f"{WARN}: Rule {row['rule_id']} denies intra-VLAN traffic ({src}). "
                f"Consider using L2 port ACLs instead."
            )
    return issues


def check_global_deny_rules(rules: list[dict]) -> list[str]:
    """Verify that there is a final default deny rule at the end."""
    issues = []
    if not rules:
        issues.append(f"{FAIL}: No firewall rules found")
        return issues

    last_rule = rules[-1]
    if last_rule.get('rule_id') != '999':
        issues.append(f"{WARN}: Last rule is {last_rule.get('rule_id')}, not 999. "
                      f"Ensure there is a final default deny rule.")
    else:
        if last_rule.get('action') != 'Deny':
            issues.append(f"{FAIL}: Rule 999 is not a Deny rule — this is a critical security flaw")
        else:
            issues.append(f"{PASS}: Final default deny rule (999) is present and correct")
    return issues


def print_stats(vlans: list[dict], rules: list[dict]) -> None:
    """Print summary statistics."""
    print(f"\n{INFO} === Design Statistics ===")
    print(f"  VLANs defined: {len(vlans)}")
    print(f"  Firewall rules: {len(rules)}")
    allow_rules = sum(1 for r in rules if r.get('action') == 'Allow')
    deny_rules = sum(1 for r in rules if r.get('action') == 'Deny')
    print(f"  Allow rules: {allow_rules}")
    print(f"  Deny rules: {deny_rules}")
    print(f"  Deny/Allow ratio: {deny_rules / max(allow_rules, 1):.1f}:1")

    # Count unique HIPAA references
    hipaa_refs = {r.get('hipaa_ref', '') for r in rules if r.get('hipaa_ref')}
    print(f"  HIPAA requirements covered: {len(hipaa_refs)}")

    # VLAN security levels
    high_crit = sum(1 for v in vlans if v.get('security_level', '') in ('High', 'Critical'))
    print(f"  High/Critical security VLANs: {high_crit}")


def main() -> int:
    base = Path(__file__).parent.parent
    vlans_path = base / "config" / "vlan-segmentation.csv"
    rules_path = base / "config" / "firewall-rules.csv"

    if not vlans_path.exists():
        print(f"{FAIL}: VLAN config not found: {vlans_path}")
        return 1
    if not rules_path.exists():
        print(f"{FAIL}: Firewall rules not found: {rules_path}")
        return 1

    vlans = load_csv(vlans_path)
    rules = load_csv(rules_path)

    all_issues = []
    all_issues.extend(check_duplicate_vlans(vlans))
    all_issues.extend(check_subnet_overlap(vlans))
    all_issues.extend(check_firewall_vlan_consistency(rules, vlans))
    all_issues.extend(check_intra_vlan_rules(rules))
    all_issues.extend(check_global_deny_rules(rules))

    # Print results
    print(f"{INFO} === Clinic Network Segmentation Validation ===\n")

    if not all_issues:
        print(f"{PASS}: No issues found. Design is consistent.")
    else:
        for issue in all_issues:
            print(issue)

    print_stats(vlans, rules)

    # Return exit code based on failures
    failures = [i for i in all_issues if i.startswith(FAIL)]
    warnings = [i for i in all_issues if i.startswith(WARN)]

    print(f"\n{INFO} Summary: {len(failures)} failure(s), {len(warnings)} warning(s)")

    if failures:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
