#!/usr/bin/env python3
"""
test_output.py - Unit tests for output formatters.

Validates STIX-lite JSON structure and Markdown brief generation.
"""

import json
from datetime import datetime, timezone

import pytest

from src.extractor import IOC
from src.output import to_brief, to_stix_lite


class TestSTIXLite:
    """Test STIX-lite bundle generation."""

    def test_bundle_structure(self) -> None:
        iocs = [
            IOC(ioc_type="ipv4", value="192.0.2.1", confidence=85.0),
            IOC(ioc_type="domain", value="evil.example.com", confidence=70.0),
        ]
        bundle = to_stix_lite(iocs, metadata={"article_count": 2, "source_feeds": ["test"]})

        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert "id" in bundle
        assert "created" in bundle
        assert bundle["metadata"]["iocs_extracted"] == 2
        assert len(bundle["objects"]) == 2

    def test_indicator_fields(self) -> None:
        ioc = IOC(ioc_type="ipv4", value="192.0.2.1", confidence=90.0, context="Beaconing C2")
        bundle = to_stix_lite([ioc])
        obj = bundle["objects"][0]

        assert obj["type"] == "indicator"
        assert obj["spec_version"] == "2.1"
        assert obj["pattern"] == "[ipv4-addr:value = '192.0.2.1']"
        assert obj["confidence"] == 90
        assert "automated-extraction" in obj["labels"]
        assert "high" in obj["labels"]

    def test_stix_patterns(self) -> None:
        iocs = [
            IOC(ioc_type="ipv6", value="2001:db8::1", confidence=80.0),
            IOC(ioc_type="domain", value="bad.com", confidence=80.0),
            IOC(ioc_type="md5", value="d41d8cd98f00b204e9800998ecf8427e", confidence=80.0),
            IOC(ioc_type="sha1", value="da39a3ee5e6b4b0d3255bfef95601890afd80709", confidence=80.0),
            IOC(ioc_type="sha256", value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", confidence=80.0),
            IOC(ioc_type="cve", value="CVE-2024-1234", confidence=80.0),
        ]
        bundle = to_stix_lite(iocs)
        patterns = [obj["pattern"] for obj in bundle["objects"]]
        assert "[ipv6-addr:value = '2001:db8::1']" in patterns
        assert "[domain-name:value = 'bad.com']" in patterns
        assert "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']" in patterns
        assert "[file:hashes.'SHA1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']" in patterns
        assert "[file:hashes.'SHA256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']" in patterns
        assert "[vulnerability:name = 'CVE-2024-1234']" in patterns

    def test_empty_iocs(self) -> None:
        bundle = to_stix_lite([], metadata={"article_count": 0})
        assert bundle["objects"] == []
        assert bundle["metadata"]["iocs_extracted"] == 0


class TestBrief:
    """Test Markdown brief generation."""

    def test_brief_structure(self) -> None:
        iocs = [
            IOC(ioc_type="ipv4", value="192.0.2.1", confidence=90.0),
            IOC(ioc_type="domain", value="evil.example.com", confidence=75.0),
        ]
        brief = to_brief(iocs, metadata={"article_count": 1, "source_feeds": ["test-feed"]})

        assert brief.startswith("# Threat Intel Daily Brief")
        assert "**Feeds:** test-feed" in brief
        assert "**Articles processed:** 1" in brief
        assert "**IOCs extracted:** 2" in brief

    def test_block_ips_section(self) -> None:
        iocs = [IOC(ioc_type="ipv4", value="192.0.2.1", confidence=90.0, is_private=False)]
        brief = to_brief(iocs)
        assert "## 🔒 Block These IPs" in brief
        assert "`192.0.2.1`" in brief

    def test_domains_section(self) -> None:
        iocs = [IOC(ioc_type="domain", value="evil.example.com", confidence=75.0)]
        brief = to_brief(iocs)
        assert "## 🌐 Monitor / Block These Domains" in brief
        assert "`evil.example.com`" in brief

    def test_hashes_section(self) -> None:
        iocs = [IOC(ioc_type="sha256", value="a" * 64, confidence=80.0)]
        brief = to_brief(iocs)
        assert "## 🔍 File Hashes for Hunting" in brief
        assert "`" + "a" * 64 + "`" in brief

    def test_cves_section(self) -> None:
        iocs = [IOC(ioc_type="cve", value="CVE-2024-1234", confidence=70.0)]
        brief = to_brief(iocs)
        assert "## ⚠️ CVEs to Track" in brief
        assert "`CVE-2024-1234`" in brief

    def test_private_ips_section(self) -> None:
        iocs = [IOC(ioc_type="ipv4", value="10.0.0.5", confidence=45.0, is_private=True)]
        brief = to_brief(iocs)
        assert "## 🏠 Internal / Private IPs (Informational)" in brief
        assert "`10.0.0.5`" in brief

    def test_low_confidence_section(self) -> None:
        iocs = [IOC(ioc_type="ipv4", value="192.0.2.2", confidence=42.0, is_private=False)]
        brief = to_brief(iocs)
        assert "## 📎 Low-Confidence IOCs" in brief
        assert "`192.0.2.2`" in brief

    def test_empty_iocs(self) -> None:
        brief = to_brief([], metadata={"article_count": 0})
        assert "**IOCs extracted:** 0" in brief
        assert "## 🔒 Block These IPs" not in brief
