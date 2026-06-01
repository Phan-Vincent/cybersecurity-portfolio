#!/usr/bin/env python3
"""
check_iocs.py
Cross-reference file hashes (SHA-256), IP addresses, and domain names against
a local JSON IOC database. Outputs a match report with confidence scores and MITRE mappings.

Purpose:
    Designed to run on an isolated Linux USB stick (air-gapped IR laptop) against
    potentially compromised pharmacy systems. Uses ONLY the Python 3 standard library
    so no pip install is required. Ideal for healthcare environments where internet
    access is restricted during incidents.

Output:
    - JSON report with IOC matches, confidence scores, and recommended actions
    - Markdown human-readable report for incident commander

Author: Vincent Phan (CPhT, Entry-level IT/Cybersecurity student)
License: MIT
"""

import json
import sys
import os
import argparse
import hashlib
import ipaddress
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────────────
# Default IOC Database (embedded, matches synthetic data from generate_sample_logs.py)
# ──────────────────────────────────────────────────────────────────────────────
DEFAULT_IOC_DB = {
    "metadata": {
        "source": "embedded",
        "description": "Synthetic IOC database for portfolio demonstration.",
        "last_updated": "2026-05-15",
        "author": "Vincent Phan",
        "disclaimer": "ALL IOCs ARE FABRICATED. No real threat intel."
    },
    "file_hashes": {
        "sha256": {
            "88e80df89cd71b7f6ca924d669977b292d906b229308730c727f4f1e04ee8dda": {
                "name": "encryptor.exe",
                "type": "ransomware",
                "family": "FakeLock",
                "confidence": 0.95,
                "mitre_technique": "T1486",
                "mitre_tactic": "Data Encrypted for Impact",
                "description": "Ransomware encryption tool targeting healthcare shares.",
                "first_seen": "2026-04-01",
                "notes": "Synthetic sample for portfolio."
            },
            "29c59adddeea115bfe13599cc7322b44886ab27b69f4f14eb40b91894d4bbce5": {
                "name": "payload.ps1",
                "type": "dropper",
                "family": "FakeDrop",
                "confidence": 0.88,
                "mitre_technique": "T1059.001",
                "mitre_tactic": "Command and Scripting Interpreter: PowerShell",
                "description": "PowerShell payload downloader."
            },
            "4e8039a2fc962f9ef69dc8ea6489398a6f6e19f97c3ec40ec9b7f92614439941": {
                "name": "shadowwiper.exe",
                "type": "wiper",
                "family": "FakeWipe",
                "confidence": 0.92,
                "mitre_technique": "T1490",
                "mitre_tactic": "Inhibit System Recovery",
                "description": "Volume shadow copy deletion tool."
            },
            "c7a8d88d81aeecac1e70efabbea00f987e986e5ecb8ce48f26909ba4f5af67e1": {
                "name": "defenderkill.exe",
                "type": "evasion",
                "family": "FakeEvasion",
                "confidence": 0.85,
                "mitre_technique": "T1562.001",
                "mitre_tactic": "Impair Defenses: Disable or Modify Tools",
                "description": "Windows Defender tampering tool."
            }
        }
    },
    "ip_addresses": {
        "203.0.113.77": {
            "type": "c2_server",
            "confidence": 0.90,
            "mitre_technique": "T1071",
            "mitre_tactic": "Application Layer Protocol",
            "description": "External RDP brute-force / C2 IP (TEST-NET-3, synthetic).",
            "first_seen": "2026-03-15",
            "asn": "AS64496",
            "country": "XX"
        },
        "192.168.200.55": {
            "type": "c2_server",
            "confidence": 0.85,
            "mitre_technique": "T1071",
            "mitre_tactic": "Application Layer Protocol",
            "description": "Internal payload staging server (RFC 1918, synthetic).",
            "first_seen": "2026-04-01",
            "asn": "N/A",
            "country": "N/A"
        },
        "198.51.100.42": {
            "type": "scanner",
            "confidence": 0.75,
            "mitre_technique": "T1046",
            "mitre_tactic": "Network Service Discovery",
            "description": "Known port scanner / reconnaissance IP (TEST-NET-2, synthetic).",
            "first_seen": "2026-02-20",
            "asn": "AS64497",
            "country": "XX"
        }
    },
    "domains": {
        "temp-sensor-01.pharm.local": {
            "type": "legitimate_compromised",
            "confidence": 0.60,
            "mitre_technique": "T1496",
            "mitre_tactic": "Resource Hijacking",
            "description": "Pharmacy IoT temp sensor DNS (legitimate, but disconnected during attack)."
        },
        "pharmax-update.com": {
            "type": "malicious",
            "confidence": 0.93,
            "mitre_technique": "T1566.002",
            "mitre_tactic": "Phishing: Spearphishing Link",
            "description": "Fake pharmacy software update domain (synthetic typosquat)."
        },
        "secure-pharma-billing.net": {
            "type": "malicious",
            "confidence": 0.91,
            "mitre_technique": "T1566.002",
            "mitre_tactic": "Phishing: Spearphishing Link",
            "description": "Fake pharmacy billing portal (synthetic typosquat)."
        }
    }
}


# ──────────────────────────────────────────────────────────────────────────────
# Hashing Utilities
# ──────────────────────────────────────────────────────────────────────────────
def sha256_file(path: str) -> Optional[str]:
    """
    Compute SHA-256 hash of a file.

    Args:
        path: File path.

    Returns:
        Hexdigest string, or None if file cannot be read.
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, IOError):
        return None


def sha256_string(data: str) -> str:
    """Compute SHA-256 hash of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# ──────────────────────────────────────────────────────────────────────────────
# Validation Helpers
# ──────────────────────────────────────────────────────────────────────────────
def is_valid_ipv4(ip: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_ipv6(ip: str) -> bool:
    """Check if string is a valid IPv6 address."""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP (v4 or v6)."""
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def is_valid_domain(domain: str) -> bool:
    """
    Basic domain validation.
    Allows FQDNs, .local, and punycode. No real TLD check.
    """
    if not domain or len(domain) > 253:
        return False
    # Simple regex: labels separated by dots, alphanumeric + hyphen
    pattern = re.compile(r"^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)$")
    return bool(pattern.match(domain))


def is_valid_sha256(h: str) -> bool:
    """Check if string is a 64-character hex SHA-256 hash."""
    return bool(re.match(r"^[a-fA-F0-9]{64}$", h))


# ──────────────────────────────────────────────────────────────────────────────
# Matching Engine
# ──────────────────────────────────────────────────────────────────────────────
def check_hashes(hashes: List[str], ioc_db: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Cross-reference SHA-256 hashes against IOC database.

    Args:
        hashes: List of SHA-256 hex strings.
        ioc_db: Loaded IOC database dictionary.

    Returns:
        List of match dictionaries.
    """
    matches = []
    db = ioc_db.get("file_hashes", {}).get("sha256", {})
    for h in hashes:
        h_lower = h.lower()
        if h_lower in db:
            entry = db[h_lower]
            matches.append({
                "ioc_type": "file_hash",
                "value": h_lower,
                "match_type": "exact",
                "confidence": entry.get("confidence", 0.5),
                "name": entry.get("name", "unknown"),
                "type": entry.get("type", "unknown"),
                "family": entry.get("family", "unknown"),
                "mitre_technique": entry.get("mitre_technique", "T0000"),
                "mitre_tactic": entry.get("mitre_tactic", "Unknown"),
                "description": entry.get("description", ""),
                "first_seen": entry.get("first_seen", ""),
                "notes": entry.get("notes", ""),
                "recommendation": "Quarantine file immediately. Preserve for forensic analysis. Check hash on VirusTotal if internet available."
            })
        else:
            # Partial match: first 8 chars (weak indicator, low confidence)
            for db_hash, entry in db.items():
                if h_lower[:8] == db_hash[:8] and h_lower != db_hash:
                    matches.append({
                        "ioc_type": "file_hash",
                        "value": h_lower,
                        "match_type": "partial_prefix",
                        "confidence": 0.15,
                        "name": entry.get("name", "unknown"),
                        "type": entry.get("type", "unknown"),
                        "family": entry.get("family", "unknown"),
                        "mitre_technique": entry.get("mitre_technique", "T0000"),
                        "mitre_tactic": entry.get("mitre_tactic", "Unknown"),
                        "description": f"Prefix collision with known IOC: {entry.get('name', 'unknown')}",
                        "recommendation": "Investigate further. Prefix match is weak evidence."
                    })
                    break
    return matches


def check_ips(ips: List[str], ioc_db: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Cross-reference IP addresses against IOC database.

    Args:
        ips: List of IP strings.
        ioc_db: Loaded IOC database dictionary.

    Returns:
        List of match dictionaries.
    """
    matches = []
    db = ioc_db.get("ip_addresses", {})
    for ip in ips:
        ip_clean = ip.strip()
        if ip_clean in db:
            entry = db[ip_clean]
            matches.append({
                "ioc_type": "ip_address",
                "value": ip_clean,
                "match_type": "exact",
                "confidence": entry.get("confidence", 0.5),
                "type": entry.get("type", "unknown"),
                "mitre_technique": entry.get("mitre_technique", "T0000"),
                "mitre_tactic": entry.get("mitre_tactic", "Unknown"),
                "description": entry.get("description", ""),
                "first_seen": entry.get("first_seen", ""),
                "asn": entry.get("asn", ""),
                "country": entry.get("country", ""),
                "recommendation": "Block at firewall. Check netflow logs. If internal, scan for compromise."
            })
        else:
            # Check if private / public for context
            try:
                addr = ipaddress.ip_address(ip_clean)
                if addr.is_private:
                    matches.append({
                        "ioc_type": "ip_address",
                        "value": ip_clean,
                        "match_type": "no_match",
                        "confidence": 0.0,
                        "description": "RFC 1918 / private IP. No IOC match, but review for lateral movement.",
                        "recommendation": "Check internal DNS/DHCP logs. May be staging server."
                    })
                elif addr.is_global:
                    matches.append({
                        "ioc_type": "ip_address",
                        "value": ip_clean,
                        "match_type": "no_match",
                        "confidence": 0.0,
                        "description": "Public IP. No IOC match in local database.",
                        "recommendation": "Check firewall logs. Consider enriching with external threat intel if internet available."
                    })
            except ValueError:
                pass
    return matches


def check_domains(domains: List[str], ioc_db: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Cross-reference domain names against IOC database.

    Args:
        domains: List of domain strings.
        ioc_db: Loaded IOC database dictionary.

    Returns:
        List of match dictionaries.
    """
    matches = []
    db = ioc_db.get("domains", {})
    for domain in domains:
        d_clean = domain.strip().lower()
        if d_clean in db:
            entry = db[d_clean]
            matches.append({
                "ioc_type": "domain",
                "value": d_clean,
                "match_type": "exact",
                "confidence": entry.get("confidence", 0.5),
                "type": entry.get("type", "unknown"),
                "mitre_technique": entry.get("mitre_technique", "T0000"),
                "mitre_tactic": entry.get("mitre_tactic", "Unknown"),
                "description": entry.get("description", ""),
                "recommendation": "Sinkhole or block at DNS. Check proxy logs for outbound requests."
            })
        else:
            # Typosquat / substring heuristic
            for db_domain, entry in db.items():
                if db_domain in d_clean or d_clean in db_domain:
                    if d_clean != db_domain:
                        matches.append({
                            "ioc_type": "domain",
                            "value": d_clean,
                            "match_type": "substring_similarity",
                            "confidence": 0.30,
                            "type": entry.get("type", "unknown"),
                            "mitre_technique": entry.get("mitre_technique", "T0000"),
                            "mitre_tactic": entry.get("mitre_tactic", "Unknown"),
                            "description": f"Similar to known IOC: {db_domain}. Possible typosquat or variant.",
                            "recommendation": "Investigate DNS history. Check for certificate transparency logs."
                        })
                        break
    return matches


def calculate_overall_confidence(matches: List[Dict[str, Any]]) -> Tuple[float, str]:
    """
    Calculate overall confidence score and risk level from matches.

    Args:
        matches: All match dictionaries.

    Returns:
        Tuple of (confidence_score, risk_level).
    """
    if not matches:
        return 0.0, "NONE"

    exact_matches = [m for m in matches if m["match_type"] == "exact"]
    if not exact_matches:
        return 0.0, "NONE"

    avg_conf = sum(m["confidence"] for m in exact_matches) / len(exact_matches)
    max_conf = max(m["confidence"] for m in exact_matches)

    # Weighted score: average + max bonus
    score = min(1.0, avg_conf * 0.6 + max_conf * 0.4)

    if score >= 0.90:
        return score, "CRITICAL"
    elif score >= 0.75:
        return score, "HIGH"
    elif score >= 0.50:
        return score, "MEDIUM"
    else:
        return score, "LOW"


# ──────────────────────────────────────────────────────────────────────────────
# Report Generators
# ──────────────────────────────────────────────────────────────────────────────
def generate_json_report(matches: List[Dict[str, Any]], overall_score: float, risk_level: str, output_path: str) -> None:
    """Write JSON IOC report."""
    report = {
        "metadata": {
            "tool": "check_iocs.py",
            "version": "1.0.0",
            "generated_at": datetime.now().isoformat(),
            "author": "Vincent Phan (CPhT, CSUSB-bound IT/Cybersecurity student)",
            "disclaimer": "Synthetic IOCs for portfolio. No real threat intelligence.",
            "overall_confidence": round(overall_score, 2),
            "risk_level": risk_level,
            "total_matches": len(matches),
            "exact_matches": len([m for m in matches if m["match_type"] == "exact"]),
        },
        "matches": matches,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[+] JSON IOC report: {output_path}")


def generate_markdown_report(matches: List[Dict[str, Any]], overall_score: float, risk_level: str, output_path: str) -> None:
    """Write Markdown IOC report."""
    lines = [
        "# IOC Cross-Reference Report",
        "",
        f"> **Tool:** `check_iocs.py` v1.0.0  ",
        f"> **Analyst:** Vincent Phan (CPhT, CSUSB-bound IT/Cybersecurity student)  ",
        f"> **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"> **Disclaimer:** Synthetic IOCs for portfolio demonstration.  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total IOCs Checked | {len(matches)} |",
        f"| Exact Matches | {len([m for m in matches if m['match_type'] == 'exact'])} |",
        f"| Overall Confidence | {overall_score:.0%} |",
        f"| Risk Level | **{risk_level}** |",
        "",
    ]

    if risk_level == "CRITICAL":
        lines.append(
            "**MULTIPLE KNOWN MALICIOUS IOCs DETECTED.** Systems are highly likely compromised. "
            "Immediate containment, evidence preservation, and HIPAA breach notification assessment required."
        )
    elif risk_level == "HIGH":
        lines.append(
            "**KNOWN MALICIOUS IOCs DETECTED.** Strong evidence of compromise. "
            "Initiate containment and notify incident commander."
        )
    elif risk_level == "MEDIUM":
        lines.append(
            "**SUSPICIOUS IOCs DETECTED.** Some indicators match known patterns. "
            "Investigate further and consider precautionary measures."
        )
    else:
        lines.append(
            "**NO SIGNIFICANT MATCHES.** No known malicious IOCs detected in local database. "
            "Continue monitoring and consider external enrichment."
        )

    lines += ["", "---", "", "## Match Details", ""]

    for idx, match in enumerate(matches, 1):
        lines += [
            f"### {idx}. {match['ioc_type'].upper()}: `{match['value']}`",
            "",
            f"| Attribute | Value |",
            f"|-----------|-------|",
            f"| Match Type | {match['match_type']} |",
            f"| Confidence | {match['confidence']:.0%} |",
            f"| MITRE Technique | [{match.get('mitre_technique', 'N/A')}](https://attack.mitre.org/techniques/{match.get('mitre_technique', 'T0000')}/) |",
            f"| MITRE Tactic | {match.get('mitre_tactic', 'N/A')} |",
            f"| Description | {match.get('description', 'N/A')} |",
            "",
            f"**Recommendation:** {match.get('recommendation', 'N/A')}",
            "",
        ]

    lines += [
        "---",
        "",
        "## Next Steps (Pharmacy IR Playbook)",
        "",
        "1. **Hash-based:** Quarantine matched files. Preserve disk images.",
        "2. **IP-based:** Block at perimeter firewall. Check netflow for beaconing.",
        "3. **Domain-based:** Sinkhole or block at DNS. Review proxy logs.",
        "4. **Cross-reference:** Feed results into `analyze_logs.py` timeline.",
        "5. **Notification:** Run `hipaa_notification_calculator.py` for deadlines.",
        "",
        "*End of Report*",
    ]

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[+] Markdown IOC report: {output_path}")


# ──────────────────────────────────────────────────────────────────────────────
# CLI & Main
# ──────────────────────────────────────────────────────────────────────────────
def main() -> int:
    """
    CLI entry point for check_iocs.py.

    Returns:
        0 on success, 1 on error.
    """
    parser = argparse.ArgumentParser(
        description="Cross-reference file hashes, IPs, and domains against a local IOC database.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check a list of hashes
  python3 check_iocs.py --hashes hash1.txt hash2.txt --db ioc_db.json

  # Check IPs and domains from a file (one per line)
  python3 check_iocs.py --ip-file suspicious_ips.txt --domain-file suspicious_domains.txt

  # Check files on disk (compute SHA-256 on the fly)
  python3 check_iocs.py --file-paths /mnt/evidence/encryptor.exe /mnt/evidence/payload.ps1

  # Use default embedded IOC database (no --db needed)
  python3 check_iocs.py --hashes hash1.txt

Author: Vincent Phan (CPhT, IT/Cybersecurity student)
        """,
    )
    parser.add_argument("--db", help="Path to JSON IOC database (default: embedded)")
    parser.add_argument("--hashes", nargs="*", help="SHA-256 hash strings to check")
    parser.add_argument("--hash-file", help="File containing one SHA-256 hash per line")
    parser.add_argument("--ips", nargs="*", help="IP addresses to check")
    parser.add_argument("--ip-file", help="File containing one IP per line")
    parser.add_argument("--domains", nargs="*", help="Domain names to check")
    parser.add_argument("--domain-file", help="File containing one domain per line")
    parser.add_argument("--file-paths", nargs="*", help="File paths to hash and check")
    parser.add_argument("--json-out", default="ioc_report.json", help="Output JSON path")
    parser.add_argument("--md-out", default="ioc_report.md", help="Output Markdown path")
    args = parser.parse_args()

    # Load IOC database
    if args.db:
        if not os.path.isfile(args.db):
            print(f"[-] IOC database not found: {args.db}", file=sys.stderr)
            return 1
        with open(args.db, "r", encoding="utf-8") as f:
            ioc_db = json.load(f)
    else:
        ioc_db = DEFAULT_IOC_DB
        print("[*] Using embedded synthetic IOC database.")

    # Collect inputs
    hashes = []
    ips = []
    domains = []

    if args.hashes:
        hashes.extend(args.hashes)
    if args.hash_file:
        if not os.path.isfile(args.hash_file):
            print(f"[-] Hash file not found: {args.hash_file}", file=sys.stderr)
            return 1
        with open(args.hash_file, "r") as f:
            hashes.extend(line.strip() for line in f if line.strip())

    if args.ips:
        ips.extend(args.ips)
    if args.ip_file:
        if not os.path.isfile(args.ip_file):
            print(f"[-] IP file not found: {args.ip_file}", file=sys.stderr)
            return 1
        with open(args.ip_file, "r") as f:
            ips.extend(line.strip() for line in f if line.strip())

    if args.domains:
        domains.extend(args.domains)
    if args.domain_file:
        if not os.path.isfile(args.domain_file):
            print(f"[-] Domain file not found: {args.domain_file}", file=sys.stderr)
            return 1
        with open(args.domain_file, "r") as f:
            domains.extend(line.strip() for line in f if line.strip())

    if args.file_paths:
        for fp in args.file_paths:
            if os.path.isfile(fp):
                h = sha256_file(fp)
                if h:
                    hashes.append(h)
                    print(f"[*] Computed SHA-256 for {fp}: {h[:16]}...")
                else:
                    print(f"[-] Could not read {fp}", file=sys.stderr)
            else:
                print(f"[-] File not found: {fp}", file=sys.stderr)

    # Validate
    valid_hashes = [h for h in hashes if is_valid_sha256(h)]
    invalid_hashes = [h for h in hashes if not is_valid_sha256(h)]
    if invalid_hashes:
        print(f"[!] Ignored {len(invalid_hashes)} invalid hash strings.")

    valid_ips = [ip for ip in ips if is_valid_ip(ip)]
    invalid_ips = [ip for ip in ips if not is_valid_ip(ip)]
    if invalid_ips:
        print(f"[!] Ignored {len(invalid_ips)} invalid IP strings.")

    valid_domains = [d for d in domains if is_valid_domain(d)]
    invalid_domains = [d for d in domains if not is_valid_domain(d)]
    if invalid_domains:
        print(f"[!] Ignored {len(invalid_domains)} invalid domain strings.")

    print(f"[*] Checking {len(valid_hashes)} hashes, {len(valid_ips)} IPs, {len(valid_domains)} domains.")

    matches = []
    matches.extend(check_hashes(valid_hashes, ioc_db))
    matches.extend(check_ips(valid_ips, ioc_db))
    matches.extend(check_domains(valid_domains, ioc_db))

    overall_score, risk_level = calculate_overall_confidence(matches)

    print(f"[*] {len(matches)} total matches. Overall confidence: {overall_score:.0%} ({risk_level})")

    generate_json_report(matches, overall_score, risk_level, args.json_out)
    generate_markdown_report(matches, overall_score, risk_level, args.md_out)

    print("\n" + "=" * 60)
    print("IOC CHECK COMPLETE")
    print(f"    JSON: {args.json_out}")
    print(f"    Markdown: {args.md_out}")
    print("=" * 60)
    return 0


# ──────────────────────────────────────────────────────────────────────────────
# Embedded assertions for self-test
# ──────────────────────────────────────────────────────────────────────────────
# Test: sha256_file returns 64-char hex
#   python3 -c "import check_iocs, tempfile, os; t=tempfile.NamedTemporaryFile(mode='w',delete=False); t.write('test'); t.close(); h=check_iocs.sha256_file(t.name); os.unlink(t.name); assert len(h)==64; print('PASS: sha256_file')"
#
# Test: is_valid_ipv4
#   python3 -c "import check_iocs; assert check_iocs.is_valid_ipv4('10.0.0.1'); assert not check_iocs.is_valid_ipv4('999.999.999.999'); print('PASS: is_valid_ipv4')"
#
# Test: check_hashes finds exact match
#   python3 -c "import check_iocs; m = check_iocs.check_hashes(['a3b8c9d2e4f5g6h7i8j9k0l1m2n3o4p5q6r7s8t9u0v1w2x3y4z5a6b7c8d9e0f1'], check_iocs.DEFAULT_IOC_DB); assert len(m)==1; assert m[0]['match_type']=='exact'; print('PASS: check_hashes exact')"
#
# Test: check_ips finds exact match
#   python3 -c "import check_iocs; m = check_iocs.check_ips(['203.0.113.77'], check_iocs.DEFAULT_IOC_DB); assert len(m)==1; assert m[0]['match_type']=='exact'; print('PASS: check_ips exact')"
#
# Test: calculate_overall_confidence
#   python3 -c "import check_iocs; score, level = check_iocs.calculate_overall_confidence([{'match_type':'exact','confidence':0.95}]); assert score > 0.9; assert level == 'CRITICAL'; print('PASS: calculate_overall_confidence')"

if __name__ == "__main__":
    sys.exit(main())
