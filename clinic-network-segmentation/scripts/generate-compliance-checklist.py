#!/usr/bin/env python3
"""
generate-compliance-checklist.py

Reads the HIPAA compliance mapping and generates a printable markdown checklist
for use during a HIPAA Security Risk Assessment (SRA).

Usage:
    python3 scripts/generate-compliance-checklist.py

Output: writes to output/hipaa-checklist.md
"""

import csv
import re
from pathlib import Path
from datetime import datetime, timezone


def load_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def extract_sections(text: str) -> list[tuple[str, list[str]]]:
    """
    Parse the hipaa-compliance.md file into sections.
    Returns list of (section_title, controls_list).
    """
    sections = []
    current_title = None
    current_controls = []

    lines = text.splitlines()
    for line in lines:
        # Match section headers like ## §164.312(a)(1) — Access Control
        m = re.match(r'^##\s+(§164\.\S+)\s+[-–]\s+(.+)$', line)
        if m:
            if current_title:
                sections.append((current_title, current_controls))
            current_title = f"{m.group(1)} — {m.group(2)}"
            current_controls = []
            continue

        # Match table rows with controls (| ... | ... |)
        if line.startswith('|') and 'Control' in line and 'Evidence' in line:
            continue  # skip header rows

        # Try to capture control descriptions from table rows
        if line.startswith('|') and not line.startswith('|---'):
            parts = [p.strip() for p in line.split('|')[1:-1]]
            if len(parts) >= 2 and parts[0] and parts[0] != 'Control':
                control_name = parts[0]
                evidence = parts[1] if len(parts) > 1 else ""
                current_controls.append((control_name, evidence))

    if current_title:
        sections.append((current_title, current_controls))

    return sections


def generate_checklist(vlans: list[dict], rules: list[dict], compliance_path: Path) -> str:
    """Generate a markdown checklist from the design artifacts."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append("# HIPAA Security Rule Compliance Checklist")
    lines.append("")
    lines.append(f"**Generated:** {now}")
    lines.append("**Clinic:** Westside Family Medical Clinic (synthetic)")
    lines.append("**Design:** Small Clinic Network Segmentation")
    lines.append("")
    lines.append("> **Note:** This checklist is generated from the design artifacts. During an SRA, verify each control is implemented as documented.")
    lines.append("")

    # --- Section 1: VLAN Segmentation ---
    lines.append("## 1. Network Segmentation (VLANs)")
    lines.append("")
    for v in vlans:
        secure = v.get('security_level', '')
        auth = v.get('802.1x', '')
        internet = v.get('internet_access', '')
        lines.append(f"- [ ] **VLAN {v['vlan_id']} ({v['vlan_name']})** — Subnet {v['subnet']}/{v['cidr']}")
        lines.append(f"  - Security level: {secure}")
        lines.append(f"  - 802.1X / NAC: {auth}")
        lines.append(f"  - Internet access: {internet}")
        lines.append(f"  - Notes: {v.get('notes', '')}")
        lines.append("")

    # --- Section 2: Firewall Rules ---
    lines.append("## 2. Firewall Rules (Default Deny)")
    lines.append("")
    lines.append(f"- [ ] **Total rules reviewed:** {len(rules)}")
    lines.append(f"- [ ] **Default deny rule present:** Rule 999")
    lines.append(f"- [ ] **All deny rules have logging enabled**")
    lines.append("")
    lines.append("### Critical Rules to Verify")
    lines.append("")
    critical_rules = [r for r in rules if r.get('source_vlan') in ('Clinical', 'Medical_IoT') or r.get('rule_id') in ('999', '800', '801', '802')]
    for r in critical_rules:
        lines.append(f"- [ ] **Rule {r['rule_id']}:** {r['source_vlan']} → {r['dest_vlan']} | {r['protocol']}/{r['port']} | {r['action']}")
        lines.append(f"  - Description: {r.get('description', '')}")
        lines.append(f"  - HIPAA: {r.get('hipaa_ref', '')}")
        lines.append("")

    # --- Section 3: HIPAA Requirements from markdown ---
    if compliance_path.exists():
        lines.append("## 3. HIPAA Security Rule §164.312 Controls")
        lines.append("")
        compliance_text = compliance_path.read_text(encoding="utf-8")
        sections = extract_sections(compliance_text)
        for title, controls in sections:
            if not controls:
                continue
            lines.append(f"### {title}")
            lines.append("")
            for control_name, evidence in controls:
                lines.append(f"- [ ] **{control_name}** — {evidence}")
            lines.append("")

    # --- Section 4: Operational Checks ---
    lines.append("## 4. Operational & Administrative Checks")
    lines.append("")
    lines.append("- [ ] **Business Associate Agreement (BAA)** signed with EHR vendor")
    lines.append("- [ ] **Incident Response Plan** includes ransomware playbook")
    lines.append("- [ ] **Access Review** conducted quarterly (last review: ___/___/____)")
    lines.append("- [ ] **Backup Test** — offline USB backup restored successfully (last test: ___/___/____)")
    lines.append("- [ ] **802.1X Certificate** renewal scheduled (expires: ___/___/____)")
    lines.append("- [ ] **Firewall Rule Audit** — no unauthorized rules added since last review")
    lines.append("- [ ] **SIEM Log Retention** — 6 years online + offline confirmed")
    lines.append("- [ ] **Penetration Test** conducted annually (last test: ___/___/____)")
    lines.append("")

    # --- Section 5: Documentation ---
    lines.append("## 5. Documentation Completeness")
    lines.append("")
    lines.append("- [ ] Network diagram (ASCII) printed and posted in server closet")
    lines.append("- [ ] Network diagram (Mermaid) stored in Git with version history")
    lines.append("- [ ] VLAN segmentation plan approved by clinic manager")
    lines.append("- [ ] Firewall rule set reviewed by IT contractor and clinic manager")
    lines.append("- [ ] Threat model reviewed and accepted")
    lines.append("- [ ] This checklist completed and signed off")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("**Sign-off:**")
    lines.append("")
    lines.append("| Role | Name | Signature | Date |")
    lines.append("|------|------|-----------|------|")
    lines.append("| Clinic Manager / Privacy Officer | | | |")
    lines.append("| IT Security Lead | | | |")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    base = Path(__file__).parent.parent
    vlans_path = base / "config" / "vlan-segmentation.csv"
    rules_path = base / "config" / "firewall-rules.csv"
    compliance_path = base / "docs" / "hipaa-compliance.md"
    output_dir = base / "output"
    output_path = output_dir / "hipaa-checklist.md"

    if not vlans_path.exists():
        print(f"Error: VLAN config not found: {vlans_path}")
        return 1
    if not rules_path.exists():
        print(f"Error: Firewall rules not found: {rules_path}")
        return 1

    vlans = load_csv(vlans_path)
    rules = load_csv(rules_path)

    checklist = generate_checklist(vlans, rules, compliance_path)

    output_dir.mkdir(exist_ok=True)
    output_path.write_text(checklist, encoding="utf-8")

    print(f"Generated HIPAA compliance checklist: {output_path}")
    print(f"  VLANs: {len(vlans)}")
    print(f"  Firewall rules: {len(rules)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
