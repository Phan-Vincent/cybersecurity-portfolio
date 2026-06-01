#!/usr/bin/env python3
"""
tests/test_vuln_db.py — Unit tests for vuln_db.py risk scoring.
"""

import tempfile
from pathlib import Path

import pytest

from vuln_db import VulnDatabase


SAMPLE_DB = """
services:
  ssh:
    base_risk: 20
    default_severity: low
    known_cves: []
    remediation: "Patch SSH."
    vulnerable_versions:
      - pattern: "7.4"
        score_boost: 30
        cves: ["CVE-2018-15473"]
        remediation: "Upgrade OpenSSH."
  telnet:
    base_risk: 95
    default_severity: critical
    known_cves: ["CVE-2020-10188"]
    remediation: "Disable telnet."
    vulnerable_versions: []
"""


def _make_db() -> VulnDatabase:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
        tmp.write(SAMPLE_DB)
        tmp.flush()
        return VulnDatabase(Path(tmp.name))


def test_lookup_known_service():
    db = _make_db()
    profile = db.lookup_service("ssh")
    assert profile is not None
    assert profile["base_risk"] == 20


def test_lookup_unknown_service():
    db = _make_db()
    assert db.lookup_service("unknown_service") is None


def test_score_finds_vulnerable_version():
    db = _make_db()
    findings = [
        {"service_name": "ssh", "service_version": "7.4p1", "banner": "OpenSSH 7.4p1", "host_ip": "1.1.1.1", "port": 22}
    ]
    scored = db.score_findings(findings)
    assert scored[0]["risk_score"] == 60  # base 20 + boost 30 + banner 10 = 60 (no OS discount since host_os absent)
    assert "CVE-2018-15473" in scored[0]["cves"]


def test_score_telnet_critical():
    db = _make_db()
    findings = [
        {"service_name": "telnet", "service_version": "1.0", "banner": "Linux telnetd", "host_ip": "1.1.1.1", "port": 23}
    ]
    scored = db.score_findings(findings)
    assert scored[0]["severity"] == "critical"
    assert scored[0]["risk_score"] == 100  # base 95 + banner 10, clamped to 100


def test_score_sorts_descending():
    db = _make_db()
    findings = [
        {"service_name": "ssh", "service_version": "8.9", "banner": "OpenSSH 8.9", "host_ip": "1.1.1.1", "port": 22},
        {"service_name": "telnet", "service_version": "1.0", "banner": "Linux telnetd", "host_ip": "1.1.1.1", "port": 23},
    ]
    scored = db.score_findings(findings)
    assert scored[0]["service_name"] == "telnet"
    assert scored[1]["service_name"] == "ssh"
