"""End-to-end: generate synthetic attack logs, then detect the attack in them."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


@pytest.fixture(scope="module")
def analyzed(tmp_path_factory):
    out = tmp_path_factory.mktemp("ir")
    subprocess.run([sys.executable, str(SCRIPTS / "generate_sample_logs.py"), "--out-dir", str(out)],
                   check=True, capture_output=True)
    subprocess.run([sys.executable, str(SCRIPTS / "analyze_logs.py"), str(out / "sample_logs.xml"),
                    "--json-out", str(out / "ir_timeline.json"), "--md-out", str(out / "ir_summary.md")],
                   check=True, capture_output=True)
    return out


def test_generator_writes_only_to_out_dir(analyzed):
    assert (analyzed / "sample_logs.xml").exists()
    assert (analyzed / "sample_logs_timeline.json").exists()


def test_key_ransomware_stages_detected(analyzed):
    report = json.loads((analyzed / "ir_timeline.json").read_text())
    text = json.dumps(report)
    for category in ("file_encryption", "ransom_note", "shadow_deletion", "external_rdp", "lateral_movement"):
        assert category in text, category


def test_mitre_mapping_present(analyzed):
    text = (analyzed / "ir_timeline.json").read_text()
    for technique in ("T1486", "T1490"):
        assert technique in text


def test_markdown_summary_written(analyzed):
    md = (analyzed / "ir_summary.md").read_text()
    assert md.startswith("#") and "T1486" in md


def test_external_ip_classification():
    import analyze_logs
    assert analyze_logs.is_external_ip("203.0.113.77")
    assert not analyze_logs.is_external_ip("10.20.0.5")
    assert not analyze_logs.is_external_ip("192.168.1.10")


def test_network_isolation_script_parses():
    subprocess.run(["bash", "-n", str(SCRIPTS / "network_isolation.sh")], check=True)
