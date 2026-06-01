#!/usr/bin/env python3
"""
AWS IAM Least-Privilege Auditor - CLI Entry Point

Usage:
    python scripts/run_audit.py --mock
    python scripts/run_audit.py --mock --format json --output report.json
    python scripts/run_audit.py --mock --format csv --output report.csv

Live AWS mode (requires IAM read-only credentials):
    python scripts/run_audit.py --format json --output report.json
"""

import argparse
import sys
from pathlib import Path

# Add the package to the path so imports work without installation
sys.path.insert(0, str(Path(__file__).parent.parent))

from aws_iam_auditor.auditor import Auditor
from aws_iam_auditor.report import (
    generate_console_report,
    generate_csv_report,
    generate_json_report,
    write_csv_report,
    write_json_report,
)


def main():
    parser = argparse.ArgumentParser(
        description="AWS IAM Least-Privilege Auditor — scan IAM for over-permissive configurations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --mock                          Run with synthetic data (no AWS needed)
  %(prog)s --mock --format json            Output JSON to stdout
  %(prog)s --mock --format csv --output out.csv   Write CSV report
  %(prog)s --format json --output live.json  Run against live AWS account
        """,
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use bundled synthetic data instead of live AWS (no credentials required).",
    )
    parser.add_argument(
        "--format",
        choices=["console", "json", "csv"],
        default="console",
        help="Output format (default: console).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file path. If omitted, writes to stdout.",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="Override path to mock data directory (used with --mock).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in console output.",
    )

    args = parser.parse_args()

    # Initialize auditor
    try:
        auditor = Auditor(mock=args.mock, data_dir=args.data_dir)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Run the audit
    try:
        findings = auditor.run_audit()
    except Exception as e:
        print(f"Audit failed: {e}", file=sys.stderr)
        sys.exit(1)

    # Generate output
    if args.format == "console":
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                generate_console_report(findings, output=f, use_color=not args.no_color)
        else:
            generate_console_report(findings, output=sys.stdout, use_color=not args.no_color)

    elif args.format == "json":
        json_report = generate_json_report(findings, pretty=True)
        if args.output:
            write_json_report(findings, args.output, pretty=True)
        else:
            print(json_report)

    elif args.format == "csv":
        csv_report = generate_csv_report(findings)
        if args.output:
            write_csv_report(findings, args.output)
        else:
            print(csv_report)

    # Exit with non-zero code if critical findings exist (useful for CI/CD)
    critical_count = sum(1 for f in findings if f.severity == "critical")
    if critical_count > 0:
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
