"""
main.py
CLI entry point for the Auth Log Analyzer.
"""

import argparse
import yaml
import sys
from pathlib import Path

# Local imports
from parser import parse_logfile
from detections import DetectionEngine
from formatter import write_outputs


def load_rules(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(
        description="Auth Log Analyzer (SIEM-lite) — detect security anomalies in Linux auth logs"
    )
    parser.add_argument("--log", required=True, help="Path to auth.log file")
    parser.add_argument("--rules", default="data/ruleset.yaml", help="Path to YAML ruleset")
    parser.add_argument("--output", default="reports", help="Output directory for reports")
    parser.add_argument("--year", type=int, default=None, help="Year for syslog timestamps (defaults to current)")
    parser.add_argument("--format", choices=["json", "human", "both"], default="both", help="Output format")
    args = parser.parse_args()

    log_path = Path(args.log)
    if not log_path.exists():
        print(f"ERROR: Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    rules_path = Path(args.rules)
    if not rules_path.exists():
        print(f"ERROR: Rules file not found: {rules_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loading rules from {rules_path}")
    rules = load_rules(str(rules_path))

    print(f"[*] Parsing log: {log_path}")
    events = list(parse_logfile(str(log_path), year=args.year))
    print(f"[*] Parsed {len(events)} events")

    print(f"[*] Running detections...")
    engine = DetectionEngine(rules)
    for ev in events:
        engine.ingest(ev)
    alerts = engine.run_detections()
    print(f"[*] {len(alerts)} alert(s) generated")

    if args.format in ("both", "json", "human"):
        paths = write_outputs(alerts, args.output, basename="auth-analysis")
        if "json" in paths:
            print(f"[+] JSON report:  {paths['json']}")
        if "human" in paths:
            print(f"[+] Human report: {paths['human']}")

    # Print human summary to stdout as well
    from formatter import format_human
    print("\n" + format_human(alerts))


if __name__ == "__main__":
    main()
