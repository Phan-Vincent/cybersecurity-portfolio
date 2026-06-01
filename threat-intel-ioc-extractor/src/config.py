#!/usr/bin/env python3
"""
config.py - Configuration and constants for the Threat Intel IOC Extractor.

Centralizes regex patterns, scoring weights, feed URLs, and whitelists.
All values are overridable via environment variables where noted.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Final

# ── IOC Regex Patterns ──────────────────────────────────────────────────────
# Each pattern includes a named group for easy extraction.

IPV4_PATTERN: Final[str] = (
    r"(?P<ipv4>\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)"
)

IPV6_PATTERN: Final[str] = (
    r"(?P<ipv6>\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|"
    r"\b[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})\b|"
    r"\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{1,4}\b)"
)

# Domain: must have at least one dot, TLD 2+ chars, not starting/ending with hyphen
DOMAIN_PATTERN: Final[str] = (
    r"(?P<domain>\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}\b)"
)

# MD5: exactly 32 hex chars
MD5_PATTERN: Final[str] = r"(?P<md5>\b[a-fA-F0-9]{32}\b)"

# SHA1: exactly 40 hex chars
SHA1_PATTERN: Final[str] = r"(?P<sha1>\b[a-fA-F0-9]{40}\b)"

# SHA256: exactly 64 hex chars
SHA256_PATTERN: Final[str] = r"(?P<sha256>\b[a-fA-F0-9]{64}\b)"

# CVE ID: CVE-YYYY-NNNNN (4-digit year, 4+ digit sequence)
CVE_PATTERN: Final[str] = r"(?P<cve>\bCVE-[0-9]{4}-[0-9]{4,}\b)"

# Combined master pattern for single-pass extraction
MASTER_PATTERN: Final[re.Pattern[str]] = re.compile(
    "|".join(
        [
            IPV4_PATTERN,
            IPV6_PATTERN,
            DOMAIN_PATTERN,
            MD5_PATTERN,
            SHA1_PATTERN,
            SHA256_PATTERN,
            CVE_PATTERN,
        ]
    )
)

# ── Validation Helpers ──────────────────────────────────────────────────────

# RFC 1918 private IPv4 ranges — reported separately, not as "external threats"
PRIVATE_IPV4_SUBNETS: Final[list[tuple[int, int]]] = [
    (int(ipaddress.IPv4Address("10.0.0.0")), int(ipaddress.IPv4Address("10.255.255.255"))),
    (int(ipaddress.IPv4Address("172.16.0.0")), int(ipaddress.IPv4Address("172.31.255.255"))),
    (int(ipaddress.IPv4Address("192.168.0.0")), int(ipaddress.IPv4Address("192.168.255.255"))),
    (int(ipaddress.IPv4Address("127.0.0.0")), int(ipaddress.IPv4Address("127.255.255.255"))),
    (int(ipaddress.IPv4Address("169.254.0.0")), int(ipaddress.IPv4Address("169.254.255.255"))),
    (int(ipaddress.IPv4Address("0.0.0.0")), int(ipaddress.IPv4Address("0.255.255.255"))),
]

# Common benign domains to greylist (reduce false positives)
DOMAIN_GREYLIST: Final[set[str]] = {
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "localhost",
    "domain.com",
    "site.com",
}

# ── Confidence Scoring ────────────────────────────────────────────────────
# Weights are additive. Base score starts at 0.

CONFIDENCE_RULES: Final[dict[str, float]] = {
    "regex_match": 30.0,            # Any regex hit
    "context_enriched": 25.0,        # Keywords like "malware", "c2", "phishing" nearby
    "hash_verified_length": 20.0,  # Hash length cross-checked
    "ip_not_private": 15.0,        # Public routable IP (not RFC1918)
    "domain_not_greylisted": 10.0,  # Not a known benign placeholder
    "cve_valid_year": 10.0,        # CVE year within reasonable range (1999–current+1)
}

# Thresholds for confidence bands
CONFIDENCE_LOW: Final[float] = 40.0
CONFIDENCE_MEDIUM: Final[float] = 60.0
CONFIDENCE_HIGH: Final[float] = 80.0

# ── Feed Defaults ─────────────────────────────────────────────────────────
# Public, well-known threat intel feeds.  Tool works offline via --samples.

DEFAULT_FEEDS: Final[list[str]] = [
    "https://feodotracker.abuse.ch/feodotracker.rss",
    "https://urlhaus.abuse.ch/rss/",
    "https://www.cisa.gov/uscert/ncas/current-activity.xml",
]

# ── Runtime Settings ──────────────────────────────────────────────────────

# User-Agent for polite crawling
USER_AGENT: Final[str] = (
    "Mozilla/5.0 (compatible; ThreatIntel-IOCEngine/1.0; "
    "+https://github.com/yourname/threat-intel-ioc-extractor)"
)

# Request timeout (seconds)
REQUEST_TIMEOUT: Final[int] = int(os.getenv("TI_REQUEST_TIMEOUT", "30"))

# Rate limit: minimum seconds between feed fetches
RATE_LIMIT_SECONDS: Final[int] = int(os.getenv("TI_RATE_LIMIT", "2"))

# ── Output Settings ───────────────────────────────────────────────────────

DEFAULT_OUTPUT_DIR: Final[str] = "./output"
DEFAULT_FORMAT: Final[str] = "both"  # stix | brief | both
