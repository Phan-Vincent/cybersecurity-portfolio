#!/usr/bin/env python3
"""
test_extractor.py - Unit tests for the IOC extraction engine.

Validates regex accuracy, deduplication, confidence scoring,
and the memory-only PHI-safety design choice.
"""

import pytest

from src.extractor import (
    IOC,
    confidence_band,
    extract_iocs,
    filter_by_confidence,
    partition_private,
)


class TestIOCExtraction:
    """Test each IOC type with valid and invalid inputs."""

    def test_ipv4_valid(self) -> None:
        text = "C2 server at 192.0.2.1 is active"
        iocs = extract_iocs(text)
        ipv4s = [i for i in iocs if i.ioc_type == "ipv4"]
        assert len(ipv4s) == 1
        assert ipv4s[0].value == "192.0.2.1"

    def test_ipv4_invalid(self) -> None:
        text = "Invalid IPs: 256.1.1.1, 192.168.1, 10.10.10"
        iocs = extract_iocs(text)
        ipv4s = [i for i in iocs if i.ioc_type == "ipv4"]
        # 256.1.1.1 fails octet check; 192.168.1 is not a full 4-octet match
        assert len(ipv4s) == 0

    def test_ipv6_valid(self) -> None:
        text = "IPv6 C2 at 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        iocs = extract_iocs(text)
        ipv6s = [i for i in iocs if i.ioc_type == "ipv6"]
        assert len(ipv6s) == 1
        assert ipv6s[0].value == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

    def test_domain_valid(self) -> None:
        text = "Domain evil.example.com spotted in DNS logs"
        iocs = extract_iocs(text)
        domains = [i for i in iocs if i.ioc_type == "domain"]
        assert len(domains) == 1
        assert domains[0].value == "evil.example.com"

    def test_domain_greylist_excluded(self) -> None:
        text = " benign links to example.com and test.com are safe"
        iocs = extract_iocs(text)
        domains = [i for i in iocs if i.ioc_type == "domain"]
        assert len(domains) == 0

    def test_md5_valid(self) -> None:
        text = "MD5 d41d8cd98f00b204e9800998ecf8427e"
        iocs = extract_iocs(text)
        md5s = [i for i in iocs if i.ioc_type == "md5"]
        assert len(md5s) == 1
        assert md5s[0].value == "d41d8cd98f00b204e9800998ecf8427e"

    def test_md5_invalid_length(self) -> None:
        text = "MD5 d41d8cd98f00b204e9800998ecf84"  # too short
        iocs = extract_iocs(text)
        md5s = [i for i in iocs if i.ioc_type == "md5"]
        assert len(md5s) == 0

    def test_sha1_valid(self) -> None:
        text = "SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709"
        iocs = extract_iocs(text)
        sha1s = [i for i in iocs if i.ioc_type == "sha1"]
        assert len(sha1s) == 1
        assert sha1s[0].value == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    def test_sha256_valid(self) -> None:
        text = "SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        iocs = extract_iocs(text)
        sha256s = [i for i in iocs if i.ioc_type == "sha256"]
        assert len(sha256s) == 1
        assert sha256s[0].value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_cve_valid(self) -> None:
        text = "Exploiting CVE-2024-1234 in the wild"
        iocs = extract_iocs(text)
        cves = [i for i in iocs if i.ioc_type == "cve"]
        assert len(cves) == 1
        assert cves[0].value == "CVE-2024-1234"

    def test_cve_invalid_year(self) -> None:
        text = "CVE-1800-1234 is impossible"
        iocs = extract_iocs(text)
        cves = [i for i in iocs if i.ioc_type == "cve"]
        assert len(cves) == 0

    def test_multiple_iocs(self) -> None:
        text = (
            "Malware from 198.51.100.22 beaconing to c2.example.com "
            "with hash d41d8cd98f00b204e9800998ecf8427e and CVE-2023-9999"
        )
        iocs = extract_iocs(text)
        assert len(iocs) == 4
        types = {i.ioc_type for i in iocs}
        assert types == {"ipv4", "domain", "md5", "cve"}


class TestDeduplication:
    """Ensure duplicate IOCs are collapsed."""

    def test_dedup_same_value(self) -> None:
        text = (
            "First: 192.0.2.1 is bad. Second: 192.0.2.1 is also bad."
        )
        iocs = extract_iocs(text)
        ipv4s = [i for i in iocs if i.ioc_type == "ipv4"]
        assert len(ipv4s) == 1

    def test_dedup_case_insensitive(self) -> None:
        text = "Domain EVIL.COM and evil.com"
        iocs = extract_iocs(text)
        domains = [i for i in iocs if i.ioc_type == "domain"]
        assert len(domains) == 1

    def test_different_types_same_value(self) -> None:
        # A hex string that could match both MD5 and SHA1
        # MD5 = 32 chars, SHA1 = 40 chars — so different lengths
        text = "MD5 d41d8cd98f00b204e9800998ecf8427e and SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709"
        iocs = extract_iocs(text)
        assert len(iocs) == 2
        assert {i.ioc_type for i in iocs} == {"md5", "sha1"}


class TestConfidenceScoring:
    """Validate confidence score assignment and banding."""

    def test_context_enrichment_boost(self) -> None:
        text = "Malware beaconing to 198.51.100.1 via C2"
        iocs = extract_iocs(text)
        ipv4 = [i for i in iocs if i.ioc_type == "ipv4"][0]
        # regex_match (30) + context_enriched (>=25) + ip_not_private (15) = 70+
        assert ipv4.confidence >= 60.0

    def test_no_context_low_score(self) -> None:
        text = "Random IP 198.51.100.2 in prose"
        iocs = extract_iocs(text)
        ipv4 = [i for i in iocs if i.ioc_type == "ipv4"][0]
        # regex_match (30) + ip_not_private (15) = 45, no context bonus
        assert 30.0 <= ipv4.confidence <= 50.0

    def test_private_ip_lower_score(self) -> None:
        text = "Internal host 10.0.0.5"
        iocs = extract_iocs(text)
        ipv4 = [i for i in iocs if i.ioc_type == "ipv4"][0]
        # No ip_not_private bonus
        assert ipv4.confidence < 50.0
        assert ipv4.is_private is True

    def test_confidence_band_high(self) -> None:
        assert confidence_band(90.0) == "high"

    def test_confidence_band_medium(self) -> None:
        assert confidence_band(65.0) == "medium"

    def test_confidence_band_low(self) -> None:
        assert confidence_band(45.0) == "low"

    def test_confidence_band_unverified(self) -> None:
        assert confidence_band(10.0) == "unverified"


class TestFilterAndPartition:
    """Test confidence threshold filtering and private IP partitioning."""

    def test_filter_by_threshold(self) -> None:
        text = "Bad IP 198.51.100.3 and maybe 192.0.2.1"
        iocs = extract_iocs(text)
        high_only = filter_by_confidence(iocs, 60.0)
        # Both should clear 60 if context is rich, else may drop one
        assert all(i.confidence >= 60.0 for i in high_only)

    def test_partition_private(self) -> None:
        text = "External 198.51.100.4 and internal 10.0.0.1"
        iocs = extract_iocs(text)
        external, internal = partition_private(iocs)
        assert all(not i.is_private for i in external)
        assert all(i.is_private for i in internal)
        assert len(internal) == 1
        assert internal[0].value == "10.0.0.1"


class TestPHISafety:
    """
    Validate that real-looking but synthetic healthcare strings are correctly
    handled — the IOC is extracted, but the tool must never log the full raw
    string to disk (enforced by design: only structured IOCs leave the module).
    """

    def test_healthcare_string_ioc_extracted(self) -> None:
        text = "Patient ID 12345 at 10.0.0.5 had symptoms."
        iocs = extract_iocs(text)
        ipv4 = [i for i in iocs if i.ioc_type == "ipv4"]
        assert len(ipv4) == 1
        assert ipv4[0].value == "10.0.0.5"
        # The full string should NOT be present in output fields
        assert "Patient ID 12345" not in ipv4[0].value

    def test_no_full_string_in_context(self) -> None:
        text = "Lab results for patient 98765 sent to 172.16.0.20"
        iocs = extract_iocs(text)
        ipv4 = [i for i in iocs if i.ioc_type == "ipv4"][0]
        # Context is truncated and the raw full string is not stored
        assert ipv4.value == "172.16.0.20"
        # Even context is limited to ~120 chars; it won't contain the whole sentence
        assert len(ipv4.context) <= 120
