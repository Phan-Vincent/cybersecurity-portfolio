#!/usr/bin/env python3
"""
cli.py - Main command-line entry point.

Orchestrates: ingest → extract → dedup/filter → output.

Security design:
- --no-phi-log (default True): raw article text is never persisted to disk.
- Logging goes to stdout only.
- Only structured, deduplicated IOCs are written to output files.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from src.config import DEFAULT_FEEDS, DEFAULT_FORMAT, DEFAULT_OUTPUT_DIR
from src.extractor import extract_iocs, filter_by_confidence, partition_private
from src.ingest import Article, fetch_all_feeds, load_samples
from src.output import to_brief, to_stix_lite, write_json, write_markdown


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stdout,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat-intel-ioc-extractor",
        description="Extract IOCs from threat intel feeds and export to STIX-lite or Markdown brief.",
    )
    parser.add_argument(
        "--feed",
        action="append",
        help="RSS/Atom feed URL (can specify multiple; overrides defaults)",
    )
    parser.add_argument(
        "--samples",
        action="store_true",
        help="Use bundled synthetic sample articles instead of live feeds",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to write output files",
    )
    parser.add_argument(
        "--format",
        choices=["stix", "brief", "both"],
        default=DEFAULT_FORMAT,
        help="Output format",
    )
    parser.add_argument(
        "--confidence-threshold",
        type=float,
        default=0.0,
        help="Minimum confidence score (0-100) to include in output",
    )
    parser.add_argument(
        "--no-phi-log",
        action="store_true",
        default=True,
        help="Never write raw source text to disk (default: True)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    log = logging.getLogger(__name__)

    # ── Ingest ───────────────────────────────────────────────────────────
    articles: list[Article] = []
    source_feeds: list[str] = []

    if args.samples:
        log.info("Loading bundled synthetic sample articles...")
        try:
            articles = load_samples()
            source_feeds = ["samples"]
        except FileNotFoundError as exc:
            log.error("%s", exc)
            return 1
    else:
        feeds = args.feed if args.feed else DEFAULT_FEEDS
        source_feeds = feeds[:]
        log.info("Fetching %d feed(s)...", len(feeds))
        articles = fetch_all_feeds(feeds)

    if not articles:
        log.warning("No articles ingested.")
        return 2

    log.info("Ingested %d articles.", len(articles))

    # ── Extract ──────────────────────────────────────────────────────────
    all_iocs: list[Any] = []
    for article in articles:
        text = f"{article.title} {article.summary}"
        iocs = extract_iocs(text, source_article=article.title)
        all_iocs.extend(iocs)
        log.debug("Extracted %d IOCs from: %s", len(iocs), article.title)

    log.info("Total IOCs before dedup/filter: %d", len(all_iocs))

    # ── Filter ─────────────────────────────────────────────────────────────
    if args.confidence_threshold > 0:
        all_iocs = filter_by_confidence(all_iocs, args.confidence_threshold)
        log.info("After confidence filter (≥%.1f): %d", args.confidence_threshold, len(all_iocs))

    if not all_iocs:
        log.warning("No IOCs met the confidence threshold.")
        return 2

    # ── Output ─────────────────────────────────────────────────────────────
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    meta: dict[str, Any] = {
        "article_count": len(articles),
        "source_feeds": source_feeds,
    }

    timestamp = Path().stem  # simple approach — use date string instead
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if args.format in ("stix", "both"):
        bundle = to_stix_lite(all_iocs, metadata=meta)
        stix_path = out_dir / f"threat_intel_{ts}.json"
        write_json(bundle, str(stix_path))
        log.info("Wrote STIX-lite bundle: %s", stix_path)

    if args.format in ("brief", "both"):
        brief = to_brief(all_iocs, metadata=meta)
        brief_path = out_dir / f"threat_intel_{ts}.md"
        write_markdown(brief, str(brief_path))
        log.info("Wrote Markdown brief: %s", brief_path)

    # Also write latest symlinks / overwrite for convenience
    if args.format in ("stix", "both"):
        latest_json = out_dir / "latest.json"
        bundle = to_stix_lite(all_iocs, metadata=meta)
        write_json(bundle, str(latest_json))

    if args.format in ("brief", "both"):
        latest_md = out_dir / "latest.md"
        brief = to_brief(all_iocs, metadata=meta)
        write_markdown(brief, str(latest_md))

    # Summary to stdout
    print("\n=== EXTRACTION SUMMARY ===")
    print(f"Articles:   {len(articles)}")
    print(f"IOCs:       {len(all_iocs)}")
    print(f"Confidence: threshold ≥ {args.confidence_threshold}")
    print(f"Output dir: {out_dir.resolve()}")
    print("========================\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
