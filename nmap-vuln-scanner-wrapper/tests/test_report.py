#!/usr/bin/env python3
"""
tests/test_report.py — Unit tests for report_generator.py.
"""

from nmap_parser import ScanMetadata
from report_generator import ReportGenerator


def test_json_report_has_required_fields():
    meta = ScanMetadata(scanner="nmap", args="nmap -sS 1.1.1.1", nmap_version="7.94")
    findings = [
        {"host_ip": "1.1.1.1", "port": 22, "service_name": "ssh", "severity": "low", "risk_score": 20, "cves": []}
    ]
    gen = ReportGenerator(scope="Test scope", scan_meta=meta, findings=findings)
    report = gen.to_json()
    import json
    data = json.loads(report)
    assert data["report_version"] == "1.0.0"
    assert data["scope_authorization"] == "Test scope"
    assert data["summary"]["total_findings"] == 1
    assert data["findings"][0]["severity"] == "low"


def test_markdown_contains_summary_table():
    meta = ScanMetadata(scanner="nmap", args="nmap -sS 1.1.1.1", nmap_version="7.94")
    findings = [
        {"host_ip": "1.1.1.1", "port": 22, "service_name": "ssh", "severity": "low", "risk_score": 20, "cves": [], "remediation": "Patch"}
    ]
    gen = ReportGenerator(scope="Test scope", scan_meta=meta, findings=findings)
    md = gen.to_markdown()
    assert "# Network Reconnaissance Report" in md
    assert "| Severity | Count |" in md
    assert "Patch" in md


def test_summary_counts_by_severity():
    meta = ScanMetadata(scanner="nmap", args="nmap -sS 1.1.1.1", nmap_version="7.94")
    findings = [
        {"host_ip": "1.1.1.1", "port": 22, "service_name": "ssh", "severity": "low", "risk_score": 20, "cves": []},
        {"host_ip": "1.1.1.1", "port": 23, "service_name": "telnet", "severity": "critical", "risk_score": 95, "cves": []},
    ]
    gen = ReportGenerator(scope="Test scope", scan_meta=meta, findings=findings)
    import json
    data = json.loads(gen.to_json())
    assert data["summary"]["severity_counts"]["critical"] == 1
    assert data["summary"]["severity_counts"]["low"] == 1
    assert data["summary"]["total_findings"] == 2
