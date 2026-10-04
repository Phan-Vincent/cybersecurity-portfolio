"""Tests for scripts/generate-compliance-checklist.py."""

from conftest import ROOT


def test_extract_sections_accepts_em_dash_headings(checklist):
    text = "\n".join([
        "## §164.312(b) — Audit Controls",
        "| Control | Evidence in Design | Location |",
        "|---------|-------------------|----------|",
        "| Firewall deny logging | Logged to syslog | config |",
        "## §164.312(c)(1) - Integrity",
        "| FIM | Wazuh | docs |",
    ])
    sections = checklist.extract_sections(text)
    assert [t for t, _ in sections] == ["§164.312(b) — Audit Controls", "§164.312(c)(1) — Integrity"]
    assert sections[0][1] == [("Firewall deny logging", "Logged to syslog")]


def test_every_312_standard_appears_in_checklist(checklist, design):
    md = checklist.generate_checklist(design["vlans"], design["rules"], ROOT / "docs" / "hipaa-compliance.md")
    for std in ("(a)(1)", "(b)", "(c)(1)", "(d)", "(e)(1)"):
        assert f"### §164.312{std}" in md


def test_every_vlan_and_default_deny_listed(checklist, design):
    md = checklist.generate_checklist(design["vlans"], design["rules"], ROOT / "docs" / "hipaa-compliance.md")
    for v in design["vlans"]:
        assert f"**VLAN {v['vlan_id']} ({v['vlan_name']})**" in md
    assert "**Rule 999:**" in md


def test_cli_output_flag(checklist, tmp_path):
    out = tmp_path / "nested" / "checklist.md"
    assert checklist.main(["--output", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("# HIPAA Security Rule Compliance Checklist")
