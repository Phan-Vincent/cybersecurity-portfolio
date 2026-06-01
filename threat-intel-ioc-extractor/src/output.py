#!/usr/bin/env python3
"""
output.py - Output formatters for structured IOC data.

STIX-lite: simplified STIX 2.1-style indicator JSON.
Brief: Markdown SOC daily brief.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from src.config import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
)
from src.extractor import IOC, confidence_band


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def to_stix_lite(iocs: list[IOC], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Produce a simplified STIX 2.1 bundle with indicator objects.

    Spec-inspired but deliberately lite: only includes fields a SOC analyst
    needs for triage.  No full relationship graph, no malware object refs.
    """
    meta = metadata or {}
    indicators: list[dict[str, Any]] = []

    for idx, ioc in enumerate(iocs, start=1):
        pattern = _stix_pattern(ioc)
        confidence_str = confidence_band(ioc.confidence)

        indicators.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{idx:04d}",
                "created": _now_iso(),
                "modified": _now_iso(),
                "name": f"{ioc.ioc_type.upper()}:{ioc.value}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": _now_iso(),
                "labels": ["automated-extraction", ioc.ioc_type, confidence_str],
                "confidence": int(ioc.confidence),
                "description": ioc.context[:200] if ioc.context else "",
                "object_marking_refs": [],
            }
        )

    bundle: dict[str, Any] = {
        "type": "bundle",
        "id": f"bundle--{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "spec_version": "2.1",
        "created": _now_iso(),
        "metadata": {
            "tool": "ThreatIntel-IOCEngine/1.0",
            "article_count": meta.get("article_count", 0),
            "source_feeds": meta.get("source_feeds", []),
            "iocs_extracted": len(iocs),
        },
        "objects": indicators,
    }
    return bundle


def _stix_pattern(ioc: IOC) -> str:
    """Map IOC type to a STIX pattern string."""
    if ioc.ioc_type == "ipv4":
        return f"[ipv4-addr:value = '{ioc.value}']"
    if ioc.ioc_type == "ipv6":
        return f"[ipv6-addr:value = '{ioc.value}']"
    if ioc.ioc_type == "domain":
        return f"[domain-name:value = '{ioc.value}']"
    if ioc.ioc_type in ("md5", "sha1", "sha256"):
        return f"[file:hashes.'{ioc.ioc_type.upper()}' = '{ioc.value}']"
    if ioc.ioc_type == "cve":
        return f"[vulnerability:name = '{ioc.value}']"
    return f"[x-custom:value = '{ioc.value}']"


def to_brief(iocs: list[IOC], metadata: dict[str, Any] | None = None) -> str:
    """
    Produce a Markdown daily brief for SOC analysts.

    Sections: summary stats, block lists, monitor lists, CVE watch.
    """
    meta = metadata or {}
    lines: list[str] = []
    lines.append("# Threat Intel Daily Brief")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Feeds:** {', '.join(meta.get('source_feeds', ['--samples--']))}")
    lines.append(f"**Articles processed:** {meta.get('article_count', 0)}")
    lines.append(f"**IOCs extracted:** {len(iocs)}")
    lines.append("")

    # Partition by confidence
    high = [i for i in iocs if i.confidence >= CONFIDENCE_HIGH]
    med = [i for i in iocs if CONFIDENCE_MEDIUM <= i.confidence < CONFIDENCE_HIGH]
    low = [i for i in iocs if CONFIDENCE_LOW <= i.confidence < CONFIDENCE_MEDIUM]

    # IPs to block (public, high confidence)
    block_ips = [i for i in high if i.ioc_type in ("ipv4", "ipv6") and not i.is_private]
    if block_ips:
        lines.append("## 🔒 Block These IPs")
        lines.append("")
        for i in block_ips:
            lines.append(f"- `{i.value}` — confidence **{confidence_band(i.confidence)}** ({i.confidence})")
            if i.context:
                lines.append(f"  - context: *{i.context[:80]}...*")
        lines.append("")

    # Domains to monitor
    domains = [i for i in high + med if i.ioc_type == "domain"]
    if domains:
        lines.append("## 🌐 Monitor / Block These Domains")
        lines.append("")
        for i in domains:
            lines.append(f"- `{i.value}` — confidence **{confidence_band(i.confidence)}** ({i.confidence})")
        lines.append("")

    # Hashes for file/hash hunting
    hashes = [i for i in high + med if i.ioc_type in ("md5", "sha1", "sha256")]
    if hashes:
        lines.append("## 🔍 File Hashes for Hunting")
        lines.append("")
        for i in hashes:
            lines.append(f"- `{i.value}` ({i.ioc_type.upper()})")
        lines.append("")

    # CVEs to patch-track
    cves = [i for i in high + med + low if i.ioc_type == "cve"]
    if cves:
        lines.append("## ⚠️ CVEs to Track")
        lines.append("")
        for i in cves:
            lines.append(f"- `{i.value}` — confidence **{confidence_band(i.confidence)}** ({i.confidence})")
        lines.append("")

    # Private/internal IPs (informational only)
    priv = [i for i in iocs if i.is_private]
    if priv:
        lines.append("## 🏠 Internal / Private IPs (Informational)")
        lines.append("*These appeared in articles but are RFC 1918 / loopback. Review for lateral-movement narratives.*")
        lines.append("")
        for i in priv:
            lines.append(f"- `{i.value}`")
        lines.append("")

    # Low confidence
    if low:
        lines.append("## 📎 Low-Confidence IOCs (Manual Review Recommended)")
        lines.append("")
        for i in low:
            lines.append(f"- `{i.value}` ({i.ioc_type}) — {i.confidence}")
        lines.append("")

    lines.append("---")
    lines.append("*This brief was auto-generated. Validate IOCs in your SIEM before blocking.*")
    return "\n".join(lines)


def write_json(bundle: dict[str, Any], path: str) -> None:
    """Pretty-print JSON bundle to disk."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2, ensure_ascii=False)


def write_markdown(text: str, path: str) -> None:
    """Write Markdown brief to disk."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
