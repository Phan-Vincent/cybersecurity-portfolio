#!/usr/bin/env python3
"""
tests/test_parser.py — Unit tests for nmap_parser.py.
"""

import tempfile
from pathlib import Path

import pytest

from nmap_parser import NmapParser, ScanResult


MINIMAL_NMAP_XML = """<?xml version="1.0"?>
<nmaprun args="nmap -sS 192.168.1.1" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="test.local" type="PTR"/></hostnames>
    <os><osmatch name="Linux 5.15" accuracy="92"/></os>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https" product="nginx" version="1.24.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parser_extracts_metadata():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as tmp:
        tmp.write(MINIMAL_NMAP_XML)
        tmp.flush()
        parser = NmapParser(Path(tmp.name))
        result = parser.parse()
    assert result.metadata.nmap_version == "7.94"
    assert "-sS" in result.metadata.args


def test_parser_finds_open_ports_only():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as tmp:
        tmp.write(MINIMAL_NMAP_XML)
        tmp.flush()
        parser = NmapParser(Path(tmp.name))
        result = parser.parse()
    findings = result.findings
    assert len(findings) == 2  # 22 and 80 are open; 443 is closed
    ports = {f["port"] for f in findings}
    assert ports == {22, 80}


def test_parser_extracts_service_info():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as tmp:
        tmp.write(MINIMAL_NMAP_XML)
        tmp.flush()
        parser = NmapParser(Path(tmp.name))
        result = parser.parse()
    ssh = [f for f in result.findings if f["port"] == 22][0]
    assert ssh["service_name"] == "ssh"
    assert ssh["service_product"] == "OpenSSH"
    assert ssh["service_version"] == "8.9p1"
    assert ssh["banner"] == "OpenSSH 8.9p1"


def test_parser_extracts_host_info():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as tmp:
        tmp.write(MINIMAL_NMAP_XML)
        tmp.flush()
        parser = NmapParser(Path(tmp.name))
        result = parser.parse()
    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.ip == "192.168.1.1"
    assert host.hostname == "test.local"
    assert host.os_guess == "Linux 5.15"
    assert host.os_accuracy == 92


def test_parser_raises_on_missing_file():
    with pytest.raises(FileNotFoundError):
        NmapParser(Path("/nonexistent/scan.xml"))
