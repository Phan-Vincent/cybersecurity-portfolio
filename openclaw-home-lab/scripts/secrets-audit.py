#!/usr/bin/env python3
"""
secrets-audit.py — Hardcoded Secret Scanner

Scans a directory tree for patterns that look like API keys, tokens, passwords,
or private keys. Safe to run on public repos because it only reports findings —
it does not upload or transmit anything.

Patterns checked:
  - AWS Access Key IDs (AKIA...)
  - GitHub personal access tokens (ghp_..., github_pat_...)
  - Discord bot tokens
  - Generic high-entropy strings matching API key shapes
  - Private key files (*.pem, *.key, id_rsa, id_ed25519)
  - .env files
  - config.yaml / openclaw.json with key-like fields

Usage:
    python3 secrets-audit.py --workspace ./
    python3 secrets-audit.py --workspace ./ --json

Author: Vincent Phan
License: MIT
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "regex": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "critical",
    },
    {
        "name": "GitHub Personal Access Token",
        "regex": re.compile(r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]+"),
        "severity": "critical",
    },
    {
        "name": "Discord Bot Token",
        "regex": re.compile(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),
        "severity": "high",
    },
    {
        "name": "Generic API Key (high entropy)",
        "regex": re.compile(r"['\"]?(api[_-]?key|apikey|token|secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{32,})['\"]", re.IGNORECASE),
        "severity": "high",
    },
    {
        "name": "Base64-encoded blob (suspicious)",
        "regex": re.compile(r"['\"][A-Za-z0-9+/]{100,}={0,2}['\"]"),
        "severity": "medium",
    },
    {
        "name": "Private Key Inline",
        "regex": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "severity": "critical",
    },
]

SUSPICIOUS_FILENAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".envrc",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
}

SUSPICIOUS_EXTENSIONS = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".keystore",
    ".jks",
}

# Files to skip (common non-secret patterns)
SKIP_PATTERNS = [
    re.compile(r"node_modules"),
    re.compile(r"\.git/"),
    re.compile(r"__pycache__"),
    re.compile(r"\.venv"),
    re.compile(r"vendor/"),
    re.compile(r"\.openclaw-install-backups"),
    re.compile(r"\.bak-"),
    re.compile(r"\.deleted\."),
]


# ---------------------------------------------------------------------------
# Scan logic
# ---------------------------------------------------------------------------


def redact(secret: str) -> str:
    """Never echo a discovered secret: keep a 4-char prefix for triage plus the length."""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}…[{len(secret)} chars redacted]"


def should_skip(path: Path) -> bool:
    rel = str(path)
    for pat in SKIP_PATTERNS:
        if pat.search(rel):
            return True
    return False


def scan_file(path: Path) -> list[dict]:
    findings = []

    # Filename-based checks
    if path.name in SUSPICIOUS_FILENAMES:
        findings.append({
            "file": str(path),
            "line": 0,
            "column": 0,
            "match": path.name,
            "pattern": "suspicious_filename",
            "severity": "high",
            "context": "File name matches known secret file pattern",
        })

    if path.suffix in SUSPICIOUS_EXTENSIONS:
        findings.append({
            "file": str(path),
            "line": 0,
            "column": 0,
            "match": path.suffix,
            "pattern": "suspicious_extension",
            "severity": "critical",
            "context": f"File extension '{path.suffix}' indicates a key/certificate file",
        })

    # Content-based checks
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    lines = text.splitlines()
    for pat in PATTERNS:
        for line_no, line in enumerate(lines, 1):
            for match in pat["regex"].finditer(line):
                # Reduce false positives: ignore comments in markdown/docs
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("<!--"):
                    # But keep if it's in a config/code block, not just docs
                    if "example" in stripped.lower() or "sample" in stripped.lower() or "synthetic" in stripped.lower():
                        continue  # Explicitly marked safe

                findings.append({
                    "file": str(path),
                    "line": line_no,
                    "column": match.start() + 1,
                    "match": redact(match.group(0)),
                    "pattern": pat["name"],
                    "severity": pat["severity"],
                    "context": line.strip().replace(match.group(0), redact(match.group(0)))[:120],
                })

    return findings


def scan_workspace(workspace: Path) -> dict:
    all_findings = []
    files_scanned = 0

    for root, _, files in os.walk(workspace):
        for fname in files:
            fpath = Path(root) / fname
            if should_skip(fpath):
                continue
            files_scanned += 1
            findings = scan_file(fpath)
            all_findings.extend(findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    overall = "ok"
    if severity_counts["critical"] > 0:
        overall = "critical"
    elif severity_counts["high"] > 0:
        overall = "high"
    elif severity_counts["medium"] > 0:
        overall = "medium"

    return {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "workspace": str(workspace.resolve()),
        "files_scanned": files_scanned,
        "overall_status": overall,
        "severity_counts": severity_counts,
        "findings": all_findings,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Scan workspace for hardcoded secrets")
    parser.add_argument("--workspace", required=True, help="Path to workspace directory")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    workspace = Path(args.workspace)
    if not workspace.is_dir():
        print(f"Error: {workspace} is not a directory", file=sys.stderr)
        sys.exit(1)

    result = scan_workspace(workspace)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Secrets Audit Report")
        print(f"====================")
        print(f"Workspace:    {result['workspace']}")
        print(f"Scanned:      {result['files_scanned']} files")
        print(f"Overall:      {result['overall_status'].upper()}")
        print(f"Critical:     {result['severity_counts']['critical']}")
        print(f"High:         {result['severity_counts']['high']}")
        print(f"Medium:       {result['severity_counts']['medium']}")
        print()
        if result["findings"]:
            for f in result["findings"]:
                print(f"[{f['severity'].upper():8}] {f['file']}:{f['line']}  {f['pattern']}")
                print(f"         Context: {f['context']}")
                print(f"         Match:   {f['match']}")
                print()
        else:
            print("No findings. Good secret hygiene.")

    sys.exit(0 if result["overall_status"] == "ok" else 1)


if __name__ == "__main__":
    main()
