#!/usr/bin/env python3
"""CLI entry point for the Credential Hygiene Auditor.

Provides a command-line interface for auditing credential hygiene with
NIST 800-63B policy evaluation, breach detection, and reuse analysis.

Example usage:
    python main.py --demo
    python main.py --input data/sample_credentials.json --output report.md --format md
    python main.py --input credentials.json --weak-hashes data/known_weak_hashes.txt --format json
"""

import argparse
import json
import sys
from pathlib import Path

from auditor import audit_credentials
from breach import load_weak_hashes
from report import generate_markdown_report, generate_json_report, save_report


def _color(text: str, color: str) -> str:
    """Return ANSI-colored text for terminal output.

    Args:
        text: The text to colorize.
        color: The color name (red, green, yellow, cyan, bold).

    Returns:
        ANSI-colored string if terminal supports it, otherwise plain text.
    """
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "cyan": "\033[96m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }
    if sys.stdout.isatty():
        return f"{colors.get(color, '')}{text}{colors['reset']}"
    return text


def print_banner() -> None:
    """Print the synthetic data warning banner."""
    print()
    print(_color("=" * 70, "bold"))
    print(_color("  ⚠️  SYNTHETIC DATA ONLY — NO REAL CREDENTIALS", "yellow"))
    print(_color("=" * 70, "bold"))
    print()
    print(
        "This tool processes synthetic data for demonstration and educational purposes."
    )
    print("Never commit real credentials to version control or audit logs.")
    print()


def print_summary(result: dict) -> None:
    """Print a colorized summary of the audit results to stdout.

    Args:
        result: The audit result dictionary from auditor.audit_credentials().
    """
    print_banner()

    total = result["total_credentials"]
    score = result["overall_risk_score"]
    risk_label = _risk_label(score)
    color = _risk_color(score)

    print(_color("📊 CREDENTIAL HYGIENE AUDIT SUMMARY", "bold"))
    print()
    print(f"  Total Credentials:    {total}")
    print(f"  Overall Risk Score:   {_color(f'{score}/100 ({risk_label})', color)}")
    print()

    nist = result["nist_compliance_summary"]
    compliant = nist["nist_compliant"]
    non_compliant = nist["nist_non_compliant"]
    rate = nist["compliance_rate_percent"]

    print(_color("📋 NIST SP 800-63B Compliance", "bold"))
    print(f"  Compliant:     {_color(str(compliant), 'green')}")
    print(f"  Non-Compliant: {_color(str(non_compliant), 'red' if non_compliant > 0 else 'green')}")
    print(f"  Rate:          {rate}%")
    print()

    reused = result["reused_passwords"]
    if reused:
        print(_color("🔄 Password Reuse Detected", "bold"))
        for r in reused:
            services = ", ".join(
                f"{s['username']}@{s['service']}" for s in r["services_affected"]
            )
            print(f"  Reused across {r['reuse_count']} services: {services}")
        print()
    else:
        print(_color("✅ No password reuse detected", "green"))
        print()

    print(_color("🔍 Per-Credential Highlights", "bold"))
    for finding in result["per_credential_findings"]:
        username = finding["username"]
        service = finding["service"]
        policy = finding["policy"]
        weak = finding["weak_hash_check"]
        score_text = f"Score {policy['score']}/4"

        status = "✅"
        status_color = "green"
        if weak["breached"]:
            status = "🚨"
            status_color = "red"
        elif not policy["nist_compliant"]:
            status = "⚠️"
            status_color = "yellow"

        print(
            f"  {_color(status, status_color)} {username}@{service}: "
            f"{score_text}, entropy={policy['entropy_bits']} bits, "
            f"breached={'YES' if weak['breached'] else 'no'}"
        )
    print()

    print(_color("=" * 70, "bold"))
    print()


def _risk_label(score: int) -> str:
    """Return a risk label for the given score."""
    if score < 20:
        return "Low"
    if score < 40:
        return "Moderate"
    if score < 60:
        return "Elevated"
    if score < 80:
        return "High"
    return "Critical"


def _risk_color(score: int) -> str:
    """Return a color name for the given risk score."""
    if score < 20:
        return "green"
    if score < 40:
        return "green"
    if score < 60:
        return "yellow"
    if score < 80:
        return "red"
    return "red"


def run_demo() -> None:
    """Run the built-in demo with sample data."""
    script_dir = Path(__file__).parent
    input_path = script_dir / "data" / "sample_credentials.json"
    weak_hashes_path = script_dir / "data" / "known_weak_hashes.txt"

    if not input_path.exists():
        print(_color(f"Error: Demo input file not found: {input_path}", "red"))
        sys.exit(1)
    if not weak_hashes_path.exists():
        print(_color(f"Error: Demo weak hashes file not found: {weak_hashes_path}", "red"))
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        credentials = json.load(f)

    weak_hashes = load_weak_hashes(str(weak_hashes_path))
    result = audit_credentials(credentials, weak_hashes)
    print_summary(result)


def main() -> None:
    """Parse CLI arguments and execute the audit."""
    parser = argparse.ArgumentParser(
        description="Credential Hygiene & Password Policy Auditor",
        epilog="Example: python main.py --demo",
    )
    parser.add_argument(
        "--input",
        type=str,
        help="Path to JSON credentials file (array of credential objects).",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Path to write the report (default: stdout).",
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["md", "json"],
        default="md",
        help="Report format: md (Markdown) or json (JSON).",
    )
    parser.add_argument(
        "--weak-hashes",
        type=str,
        default="data/known_weak_hashes.txt",
        help="Path to weak password hash database file.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run the built-in demo with synthetic sample data.",
    )

    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    if not args.input:
        print(_color("Error: --input is required (or use --demo).", "red"))
        parser.print_help()
        sys.exit(1)

    input_path = Path(args.input)
    weak_hashes_path = Path(args.weak_hashes)

    if not input_path.exists():
        print(_color(f"Error: Input file not found: {input_path}", "red"))
        sys.exit(1)
    if not weak_hashes_path.exists():
        print(_color(f"Error: Weak hashes file not found: {weak_hashes_path}", "red"))
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        credentials = json.load(f)

    weak_hashes = load_weak_hashes(str(weak_hashes_path))
    result = audit_credentials(credentials, weak_hashes)

    if args.format == "md":
        report = generate_markdown_report(result)
    else:
        report = generate_json_report(result)

    if args.output:
        save_report(report, args.output)
        print(f"Report saved to: {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
