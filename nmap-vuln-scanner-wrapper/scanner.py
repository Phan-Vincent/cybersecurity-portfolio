#!/usr/bin/env python3
"""
scanner.py — Main entrypoint for the nmap vulnerability scanner wrapper.

Enforces ethical scope-of-engagement, runs authorized nmap scans (or demo mode),
and orchestrates parse → score → report pipeline.

Author: Vincent Phan
"""

import argparse
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from nmap_parser import NmapParser, ScanResult
from report_generator import ReportGenerator
from vuln_db import VulnDatabase


# ── Constants ───────────────────────────────────────────────────────────────

DEMO_XML_PATH = Path(__file__).parent / "demo_data" / "sample-scan.xml"
DEMO_SERVICES_PATH = Path(__file__).parent / "demo_data" / "risky-services.yaml"
NMAP_REQUIRED_VERSION = (7, 80)


# ── CLI ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authorized network reconnaissance wrapper with vulnerability scoring."
    )
    parser.add_argument(
        "--target",
        type=str,
        help="Target IP, CIDR, or hostname (e.g., 192.168.1.0/24). Required unless --demo.",
    )
    parser.add_argument(
        "--scope",
        type=str,
        required=True,
        help="Mandatory authorization statement: who authorized this scan and for what scope.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="scan-report.json",
        help="Output file for structured report (JSON). Default: scan-report.json",
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["json", "markdown"],
        default="json",
        help="Report output format. Default: json",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run in demo mode using synthetic sample data. No real network scan performed.",
    )
    parser.add_argument(
        "--nmap-path",
        type=str,
        default="nmap",
        help="Path to nmap binary. Default: nmap",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print nmap command and raw XML preview to stderr.",
    )
    return parser


# ── Validation ─────────────────────────────────────────────────────────────

def validate_nmap_binary(path: str) -> bool:
    """Check that nmap is installed and meets minimum version."""
    try:
        result = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return False
        # nmap version line: "Nmap version 7.94 ..."
        first_line = result.stdout.splitlines()[0]
        version_str = first_line.split()[2]
        major, minor = map(int, version_str.split(".")[:2])
        if (major, minor) < NMAP_REQUIRED_VERSION:
            print(
                f"[ERROR] nmap {version_str} is too old. Minimum: {NMAP_REQUIRED_VERSION[0]}.{NMAP_REQUIRED_VERSION[1]}",
                file=sys.stderr,
            )
            return False
        return True
    except FileNotFoundError:
        print(f"[ERROR] nmap binary not found at: {path}", file=sys.stderr)
        return False
    except Exception as exc:
        print(f"[ERROR] Failed to validate nmap: {exc}", file=sys.stderr)
        return False


def validate_scope(scope: str) -> bool:
    """Basic sanity check: scope must be non-empty and reasonably descriptive."""
    if not scope or len(scope.strip()) < 10:
        print(
            "[ERROR] --scope must be a meaningful authorization statement (min 10 chars).",
            file=sys.stderr,
        )
        return False
    return True


# ── Scan Orchestration ─────────────────────────────────────────────────────

def run_nmap_scan(
    target: str,
    nmap_path: str,
    verbose: bool,
) -> Path:
    """
    Execute an nmap scan with safe, read-only flags and output XML.

    Safety flags used:
      -sS        : SYN stealth scan (no full TCP handshake, less intrusive)
      -sV        : Version detection (banner grabbing, not exploitation)
      -O         : OS detection (passive fingerprinting)
      --top-ports 1000 : Limit to most common ports, avoid full 65535 noise
      -oX        : XML output for structured parsing
      --max-retries 2  : Limit retry noise
    """
    # Build a safe, read-only nmap command
    cmd = [
        nmap_path,
        "-sS", "-sV", "-O",
        "--top-ports", "1000",
        "--max-retries", "2",
        "-oX", "-",  # XML to stdout
        target,
    ]

    if verbose:
        print(f"[INFO] Running: {' '.join(cmd)}", file=sys.stderr)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,  # 5-minute cap on scan duration
    )

    if result.returncode not in (0, 1):
        # nmap returns 1 for hosts that are down; that's acceptable
        print(f"[ERROR] nmap failed with code {result.returncode}", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)

    # Write XML to a temp file so the parser can read it path-based
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False)
    tmp.write(result.stdout)
    tmp.flush()
    return Path(tmp.name)


# ── Main Pipeline ──────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # ── Scope enforcement ───────────────────────────────────────────────────
    if not validate_scope(args.scope):
        return 2

    # ── Demo mode ───────────────────────────────────────────────────────────
    if args.demo:
        print("[INFO] DEMO MODE: Using synthetic sample data. No network scan performed.")
        xml_path = DEMO_XML_PATH
        services_path = DEMO_SERVICES_PATH
    else:
        if not args.target:
            print("[ERROR] --target is required unless using --demo", file=sys.stderr)
            return 2
        if not validate_nmap_binary(args.nmap_path):
            return 2
        xml_path = run_nmap_scan(args.target, args.nmap_path, args.verbose)
        services_path = DEMO_SERVICES_PATH  # always use the risk profile db

    # ── Parse ─────────────────────────────────────────────────────────────
    nmap_parser = NmapParser(xml_path)
    scan_result: ScanResult = nmap_parser.parse()

    # ── Score ─────────────────────────────────────────────────────────────
    vuln_db = VulnDatabase(services_path)
    scored_findings = vuln_db.score_findings(scan_result.findings)

    # ── Report ─────────────────────────────────────────────────────────────
    generator = ReportGenerator(
        scope=args.scope,
        scan_meta=scan_result.metadata,
        findings=scored_findings,
    )

    if args.format == "json":
        report = generator.to_json()
    else:
        report = generator.to_markdown()

    output_path = Path(args.output)
    output_path.write_text(report, encoding="utf-8")
    print(f"[INFO] Report written to: {output_path.resolve()}")

    # Print a one-line executive summary to stdout
    critical = sum(1 for f in scored_findings if f.get("risk_score", 0) >= 90)
    high = sum(1 for f in scored_findings if 70 <= f.get("risk_score", 0) < 90)
    medium = sum(1 for f in scored_findings if 40 <= f.get("risk_score", 0) < 70)
    low = sum(1 for f in scored_findings if f.get("risk_score", 0) < 40)
    print(
        f"[SUMMARY] {critical} Critical | {high} High | {medium} Medium | {low} Low risk findings"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
