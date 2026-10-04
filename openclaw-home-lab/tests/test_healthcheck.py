"""Tests for scripts/healthcheck.py (pure logic + demo mode; no live probing)."""

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "healthcheck.py"


def test_threshold_boundaries(healthcheck):
    t = healthcheck._threshold_status
    assert t(89.9, 90, 95) == "ok"
    assert t(90.0, 90, 95) == "warning"
    assert t(95.0, 90, 95) == "critical"


def test_recommendations(healthcheck):
    ok = {"status": "ok", "used_pct": 10}
    assert healthcheck._recommendations(ok, ok, {"listening": True}, []) == ["All checks nominal. No action required."]
    recs = healthcheck._recommendations({"status": "warning", "used_pct": 91}, ok, {"listening": False}, [{}])
    assert any("log-rotate" in r for r in recs)
    assert any("Gateway not listening" in r for r in recs)
    assert any("1 recent error" in r for r in recs)


def test_demo_mode_emits_report_and_status_exit_code(healthcheck):
    proc = subprocess.run([sys.executable, str(SCRIPT), "--demo"], capture_output=True, text=True)
    report = json.loads(proc.stdout)
    expected = {"critical": 2, "warning": 1}.get(report.get("overall_status"), 0)
    assert proc.returncode == expected
    assert report["recommendations"]


def test_shell_scripts_parse():
    for sh in SCRIPT.parent.glob("*.sh"):
        subprocess.run(["bash", "-n", str(sh)], check=True)
