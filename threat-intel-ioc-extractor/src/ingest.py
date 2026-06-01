#!/usr/bin/env python3
"""
ingest.py - Threat feed ingestion layer.

Handles live RSS/Atom fetching + offline sample mode.  All network calls use
polite headers and rate-limiting.  Raw XML/text is parsed in-memory and
immediately discarded after IOC extraction.
"""

from __future__ import annotations

import json
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from src.config import DEFAULT_FEEDS, RATE_LIMIT_SECONDS, REQUEST_TIMEOUT, USER_AGENT


@dataclass(frozen=True, slots=True)
class Article:
    """Normalized article from any feed."""

    title: str
    summary: str
    link: str
    published: str
    source: str


_headers = {"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml"}

_last_fetch_time: float = 0.0


def _rate_limited_get(url: str) -> requests.Response:
    """Fetch *url* respecting global rate limit."""
    global _last_fetch_time
    elapsed = time.monotonic() - _last_fetch_time
    if elapsed < RATE_LIMIT_SECONDS:
        time.sleep(RATE_LIMIT_SECONDS - elapsed)
    resp = requests.get(url, headers=_headers, timeout=REQUEST_TIMEOUT)
    _last_fetch_time = time.monotonic()
    resp.raise_for_status()
    return resp


def _parse_rss_atom(xml_text: str, source_url: str) -> list[Article]:
    """Parse RSS 2.0 or Atom 1.0 into Article objects."""
    articles: list[Article] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"Malformed XML from {source_url}: {exc}") from exc

    # Detect RSS vs Atom by tag names
    tag = root.tag.lower()
    if "rss" in tag:
        channel = root.find("channel")
        if channel is None:
            raise ValueError(f"No <channel> found in RSS feed {source_url}")
        for item in channel.findall("item"):
            title = item.findtext("title", default="")
            summary = item.findtext("description", default="")
            link = item.findtext("link", default="")
            pub = item.findtext("pubDate", default="")
            articles.append(
                Article(
                    title=title,
                    summary=summary,
                    link=link,
                    published=pub,
                    source=source_url,
                )
            )
    elif "feed" in tag:
        # Atom
        for entry in root.findall("{http://www.w3.org/2005/Atom}entry"):
            title = entry.findtext("{http://www.w3.org/2005/Atom}title", default="")
            summary = entry.findtext("{http://www.w3.org/2005/Atom}summary", default="")
            if not summary:
                summary = entry.findtext("{http://www.w3.org/2005/Atom}content", default="")
            link_el = entry.find("{http://www.w3.org/2005/Atom}link")
            link = link_el.get("href", "") if link_el is not None else ""
            pub = entry.findtext("{http://www.w3.org/2005/Atom}published", default="")
            articles.append(
                Article(
                    title=title,
                    summary=summary,
                    link=link,
                    published=pub,
                    source=source_url,
                )
            )
        # Try without namespace fallback
        if not articles:
            for entry in root.findall("entry"):
                title = entry.findtext("title", default="")
                summary = entry.findtext("summary", default="") or entry.findtext("content", default="")
                link_el = entry.find("link")
                link = link_el.get("href", "") if link_el is not None else ""
                pub = entry.findtext("published", default="")
                articles.append(
                    Article(
                        title=title,
                        summary=summary,
                        link=link,
                        published=pub,
                        source=source_url,
                    )
                )
    else:
        raise ValueError(f"Unrecognized feed format from {source_url}: root tag {root.tag}")

    return articles


def fetch_feed(url: str) -> list[Article]:
    """Fetch and parse a single RSS/Atom feed URL."""
    try:
        resp = _rate_limited_get(url)
        return _parse_rss_atom(resp.text, url)
    except (requests.RequestException, ValueError) as exc:
        # Re-raise for CLI to handle / log
        raise RuntimeError(f"Failed to ingest feed {url}: {exc}") from exc


def fetch_all_feeds(urls: list[str] | None = None) -> list[Article]:
    """Fetch multiple feeds, collecting successes and warning on failures."""
    urls = urls or DEFAULT_FEEDS
    articles: list[Article] = []
    for url in urls:
        try:
            articles.extend(fetch_feed(url))
        except RuntimeError as exc:
            print(f"[WARN] {exc}")
    return articles


def load_samples(path: str = "data/samples.json") -> list[Article]:
    """Load bundled synthetic sample articles for offline demo."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Sample file not found: {p.resolve()}")
    data = json.loads(p.read_text(encoding="utf-8"))
    return [Article(**item) for item in data]
