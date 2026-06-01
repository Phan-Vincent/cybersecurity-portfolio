#!/usr/bin/env python3
"""
extractor.py - Core IOC extraction engine.

Design principle: memory-only processing.  We never write raw input text to disk,
preventing accidental PHI leakage.  Only structured, deduplicated IOCs leave
this module.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from src.config import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_RULES,
    CVE_PATTERN,
    DOMAIN_GREYLIST,
    DOMAIN_PATTERN,
    IPV4_PATTERN,
    IPV6_PATTERN,
    MASTER_PATTERN,
    MD5_PATTERN,
    SHA1_PATTERN,
    SHA256_PATTERN,
)


@dataclass(frozen=True, slots=True)
class IOC:
    """Immutable indicator of compromise."""

    ioc_type: str  # ipv4, ipv6, domain, md5, sha1, sha256, cve
    value: str
    confidence: float = 0.0
    context: str = ""
    is_private: bool = False
    source_article: str = ""


def _validate_ipv4(addr: str) -> bool:
    """Return True if *addr* is a syntactically valid IPv4 address."""
    try:
        parts = addr.split(".")
        if len(parts) != 4:
            return False
        for p in parts:
            if not p.isdigit() or not 0 <= int(p) <= 255:
                return False
        return True
    except ValueError:
        return False


def _validate_ipv6(addr: str) -> bool:
    """Return True if *addr* is a syntactically valid IPv6 address."""
    try:
        ipaddress.IPv6Address(addr)
        return True
    except ValueError:
        return False


def _is_private_ipv4(addr: str) -> bool:
    """Return True if *addr* falls in an RFC 1918 (or loopback/link-local) range."""
    # NOTE: we deliberately do NOT use ipaddress.is_private wholesale, because it
    # also returns True for documentation/reserved ranges like 198.51.100.0/24
    # (TEST-NET-2). For SOC triage we only want true internal/non-routable space:
    # RFC 1918 + loopback + link-local. Everything else is treated as external.
    try:
        ip_obj = ipaddress.IPv4Address(addr)
    except ValueError:
        return False
    rfc1918 = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if any(ip_obj in net for net in rfc1918):
        return True
    return ip_obj.is_loopback or ip_obj.is_link_local


def _validate_hash(value: str, expected_len: int) -> bool:
    """Hex length check + character sanity."""
    if len(value) != expected_len:
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def _validate_domain(value: str) -> bool:
    """Basic structural validation for a domain."""
    if ".." in value or value.startswith(".") or value.endswith("."):
        return False
    if value.lower() in DOMAIN_GREYLIST:
        return False
    return True


def _validate_cve(value: str) -> bool:
    """CVE format sanity check."""
    import re as _re

    m = _re.match(r"CVE-(\d{4})-(\d{4,})", value, _re.I)
    if not m:
        return False
    year = int(m.group(1))
    current_year = datetime.now().year
    return 1999 <= year <= current_year + 1


def _score_context(text: str) -> float:
    """Return a context enrichment bonus if threat keywords appear near the IOC."""
    threat_keywords: Final[list[str]] = [
        "malware",
        "c2",
        "command and control",
        "phishing",
        "ransomware",
        "trojan",
        "backdoor",
        "exploit",
        "breach",
        "compromised",
        "apt",
        "actor",
        "threat",
        "ioc",
        "indicator",
    ]
    text_lower = text.lower()
    hits = sum(1 for kw in threat_keywords if kw in text_lower)
    # Each nearby threat keyword adds half the enrichment weight; cap at the
    # full ``context_enriched`` value so we don't over-weight noisy text.
    per_hit = CONFIDENCE_RULES["context_enriched"] / 2.0
    return min(hits * per_hit, CONFIDENCE_RULES["context_enriched"])


def extract_iocs(text: str, source_article: str = "") -> list[IOC]:
    """
    Extract IOCs from *text* and return deduplicated, scored IOC objects.

    Security note: *text* is processed in-memory only.  We never persist raw
    input strings.  Only the structured IOC dataclass fields leave this
    function.
    """
    seen: dict[str, IOC] = {}

    for match in MASTER_PATTERN.finditer(text):
        ioc_type: str | None = None
        value: str | None = None

        if match.group("ipv4"):
            ioc_type, value = "ipv4", match.group("ipv4")
        elif match.group("ipv6"):
            ioc_type, value = "ipv6", match.group("ipv6")
        elif match.group("domain"):
            ioc_type, value = "domain", match.group("domain")
        elif match.group("md5"):
            ioc_type, value = "md5", match.group("md5")
        elif match.group("sha1"):
            ioc_type, value = "sha1", match.group("sha1")
        elif match.group("sha256"):
            ioc_type, value = "sha256", match.group("sha256")
        elif match.group("cve"):
            ioc_type, value = "cve", match.group("cve")

        if ioc_type is None or value is None:
            continue

        # ── Validation ─────────────────────────────────────────────────────
        valid = False
        is_private = False
        if ioc_type == "ipv4":
            valid = _validate_ipv4(value)
            is_private = _is_private_ipv4(value) if valid else False
        elif ioc_type == "ipv6":
            valid = _validate_ipv6(value)
        elif ioc_type == "domain":
            valid = _validate_domain(value)
        elif ioc_type == "md5":
            valid = _validate_hash(value, 32)
        elif ioc_type == "sha1":
            valid = _validate_hash(value, 40)
        elif ioc_type == "sha256":
            valid = _validate_hash(value, 64)
        elif ioc_type == "cve":
            valid = _validate_cve(value)

        if not valid:
            continue

        # ── Confidence Scoring ─────────────────────────────────────────────
        score = CONFIDENCE_RULES["regex_match"]

        # Context enrichment (keywords in the surrounding ~200 chars)
        start = max(0, match.start() - 200)
        end = min(len(text), match.end() + 200)
        context_snippet = text[start:end]
        score += _score_context(context_snippet)

        if ioc_type in ("md5", "sha1", "sha256"):
            score += CONFIDENCE_RULES["hash_verified_length"]

        if ioc_type == "ipv4" and not is_private:
            score += CONFIDENCE_RULES["ip_not_private"]

        if ioc_type == "domain" and value.lower() not in DOMAIN_GREYLIST:
            score += CONFIDENCE_RULES["domain_not_greylisted"]

        if ioc_type == "cve":
            score += CONFIDENCE_RULES["cve_valid_year"]

        score = min(score, 100.0)

        # ── Deduplication ────────────────────────────────────────────────
        key = f"{ioc_type}:{value.lower()}"
        if key not in seen:
            seen[key] = IOC(
                ioc_type=ioc_type,
                value=value,
                confidence=round(score, 2),
                context=context_snippet[:120].replace("\n", " "),
                is_private=is_private,
                source_article=source_article,
            )
        else:
            # Merge: keep higher confidence, update context if richer
            existing = seen[key]
            if score > existing.confidence:
                seen[key] = IOC(
                    ioc_type=ioc_type,
                    value=value,
                    confidence=round(score, 2),
                    context=existing.context or context_snippet[:120].replace("\n", " "),
                    is_private=is_private,
                    source_article=source_article or existing.source_article,
                )

    return list(seen.values())


def _group_iocs(iocs: list[IOC]) -> dict[str, list[str]]:
    """Group IOC objects into the {type: [values]} dict expected by STIX/brief modules."""
    groups: dict[str, list[str]] = {
        "ipv4": [],
        "ipv6": [],
        "domains": [],
        "hashes": [],
        "cves": [],
    }
    for ioc in iocs:
        if ioc.ioc_type == "ipv4":
            groups["ipv4"].append(ioc.value)
        elif ioc.ioc_type == "ipv6":
            groups["ipv6"].append(ioc.value)
        elif ioc.ioc_type == "domain":
            groups["domains"].append(ioc.value)
        elif ioc.ioc_type in ("md5", "sha1", "sha256"):
            groups["hashes"].append(ioc.value)
        elif ioc.ioc_type == "cve":
            groups["cves"].append(ioc.value)
    # Remove empty lists for cleaner output.
    return {k: v for k, v in groups.items() if v}


def parse_local_article(path: str) -> dict[str, Any]:
    """Read a local markdown article, extract IOCs, and return a structured dict."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()

    # Extract title from first markdown H1 heading.
    title = "Untitled Article"
    for line in text.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            break

    iocs = extract_iocs(text, source_article=path)
    return {
        "title": title,
        "iocs": _group_iocs(iocs),
    }


def parse_rss_feed(target: str) -> list[dict[str, Any]]:
    """Parse a local RSS/Atom XML file and extract IOCs from each entry.

    Returns a list of entry dicts shaped like:
        {"title": ..., "published": ..., "iocs": {type: [values]}}
    """
    import xml.etree.ElementTree as ET

    tree = ET.parse(target)
    root = tree.getroot()

    # Handle both RSS 2.0 (<channel><item>) and Atom (<feed><entry>)
    items = root.findall(".//item")
    if not items:
        items = root.findall(".//{http://www.w3.org/2005/Atom}entry")
        if not items:
            # Try without namespace
            items = root.findall(".//entry")

    entries: list[dict[str, Any]] = []
    for item in items:
        title_elem = item.find("title")
        title = title_elem.text if title_elem is not None else "Untitled"

        # Try various date/pubDate fields
        pub = ""
        for tag in ("pubDate", "published", "updated", "date"):
            elem = item.find(tag)
            if elem is not None and elem.text:
                pub = elem.text
                break

        # Concatenate all text content for IOC extraction
        content_parts = []
        for tag in ("description", "content", "summary", "{http://www.w3.org/2005/Atom}content"):
            elem = item.find(tag)
            if elem is not None and elem.text:
                content_parts.append(elem.text)
        body = "\n".join(content_parts)

        iocs = extract_iocs(body, source_article=target)
        entries.append(
            {
                "title": title,
                "published": pub,
                "iocs": _group_iocs(iocs),
            }
        )

    return entries


def confidence_band(score: float) -> str:
    """Return human-readable confidence band."""
    if score >= CONFIDENCE_HIGH:
        return "high"
    if score >= CONFIDENCE_MEDIUM:
        return "medium"
    if score >= CONFIDENCE_LOW:
        return "low"
    return "unverified"


def filter_by_confidence(iocs: list[IOC], threshold: float) -> list[IOC]:
    """Return IOCs whose confidence meets or exceeds *threshold*."""
    return [ioc for ioc in iocs if ioc.confidence >= threshold]


def partition_private(iocs: list[IOC]) -> tuple[list[IOC], list[IOC]]:
    """Return (external_threats, internal_observations)."""
    external = [ioc for ioc in iocs if ioc.ioc_type not in ("ipv4",) or not ioc.is_private]
    internal = [ioc for ioc in iocs if ioc.ioc_type == "ipv4" and ioc.is_private]
    return external, internal
