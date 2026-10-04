#!/usr/bin/env python3
"""
analyze_logs.py
Parse Windows Event Log exports (.evtx XML or Sysmon XML) to detect ransomware indicators.

Purpose:
    Reads Windows Event Log XML files (exported from .evtx) and flags indicators
    of compromise (IOCs) associated with ransomware in a pharmacy environment.
    Designed to run on an air-gapped IR laptop with only Python 3 standard library.

Indicators Detected:
    - Mass file extension changes (.encrypted, .locked, .README_*.txt)
    - Suspicious PowerShell / VBScript execution (encoded commands, download strings)
    - RDP logins from unusual / external IPs (non-RFC-1918)
    - Volume shadow copy deletion (vssadmin delete shadows)
    - Windows Defender tampering (disabled, exclusions added)
    - Lateral movement patterns (network logons, credential reuse)
    - Process creation of known ransomware tools

Output:
    - JSON timeline with scored events
    - Markdown human-readable summary report

Author: Vincent Phan (CPhT, Entry-level IT/Cybersecurity student)
License: MIT
"""

import xml.etree.ElementTree as ET
import json
import re
import sys
import os
import argparse
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional


# ──────────────────────────────────────────────────────────────────────────────
# Detection Rules (heuristic, no external threat-intel required)
# ──────────────────────────────────────────────────────────────────────────────
SUSPICIOUS_EXTENSIONS = [".encrypted", ".locked", ".locked3", ".pay2dec"]
# Ransom notes: common note filenames (LockBit, BlackCat, Hive, Royal, generic) and wording
RANSOM_NOTE_PATTERN = re.compile(
    r"(readme[_\-.]?(recover|restore|decrypt|for_decrypt)"
    r"|restore-my-files|recover-readme|how[_\-]?to[_\-]?(decrypt|restore|recover)"
    r"|decrypt[_\-]?instructions|!+\s*readme|your files (have been|are) encrypted)",
    re.IGNORECASE,
)
SUSPICIOUS_POWERSHELL_PATTERNS = [
    "invoke-expression", "iex", "downloadstring", "downloadfile",
    "frombase64string", "-enc", "-encodedcommand", "bypass", "noprofile",
    "vbscript", "wscript", "cscript", "mshta", "regsvr32", "rundll32"
]
SUSPICIOUS_PROCESS_NAMES = [
    "vssadmin.exe", "bcdedit.exe", "wevtutil.exe", "wbadmin.exe",
    "cipher.exe", "format.com", "diskpart.exe", "encryptor.exe", "locker.exe",
    "shadowcopydeletion.exe", "readme.exe"
]
SUSPICIOUS_CMD_PATTERNS = [
    "delete shadows", "shadowstorage", "resize shadowstorage", "bcdedit /set",
    "wevtutil cl", "wbadmin delete", "cipher /w", "format ", "diskpart /s",
    "vssadmin resize", "wbadmin delete catalog", "reg add.*disabledefender",
    "netsh advfirewall set allprofiles state off", "taskkill /f /im"
]

# RFC-1918 and link-local ranges (internal IPs that are NOT suspicious on their own)
PRIVATE_IP_RANGES = [
    re.compile(r"^(10\.\d{1,3}\.\d{1,3}\.\d{1,3})$"),
    re.compile(r"^(172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})$"),
    re.compile(r"^(192\.168\.\d{1,3}\.\d{1,3})$"),
    re.compile(r"^(127\.\d{1,3}\.\d{1,3}\.\d{1,3})$"),
    re.compile(r"^(169\.254\.\d{1,3}\.\d{1,3})$"),  # link-local
]

# Known MITRE ATT&CK technique mapping (simplified)
MITRE_MAP = {
    "vssadmin": {"technique": "T1490", "tactic": "Inhibit System Recovery"},
    "delete shadows": {"technique": "T1490", "tactic": "Inhibit System Recovery"},
    "bcdedit": {"technique": "T1490", "tactic": "Inhibit System Recovery"},
    "wevtutil": {"technique": "T1070.001", "tactic": "Indicator Removal"},
    "wbadmin": {"technique": "T1490", "tactic": "Inhibit System Recovery"},
    "cipher": {"technique": "T1485", "tactic": "Data Destruction"},
    "format": {"technique": "T1485", "tactic": "Data Destruction"},
    "encryptor": {"technique": "T1486", "tactic": "Data Encrypted for Impact"},
    "locker": {"technique": "T1486", "tactic": "Data Encrypted for Impact"},
    "invoke-expression": {"technique": "T1059.001", "tactic": "Command and Scripting Interpreter: PowerShell"},
    "downloadstring": {"technique": "T1071", "tactic": "Application Layer Protocol"},
    "downloadfile": {"technique": "T1071", "tactic": "Application Layer Protocol"},
    "frombase64string": {"technique": "T1059.001", "tactic": "Command and Scripting Interpreter: PowerShell"},
    "-enc": {"technique": "T1059.001", "tactic": "Command and Scripting Interpreter: PowerShell"},
    "rdp": {"technique": "T1021.001", "tactic": "Remote Services: RDP"},
    "logon type 10": {"technique": "T1021.001", "tactic": "Remote Services: RDP"},
    "valid accounts": {"technique": "T1078", "tactic": "Valid Accounts"},
    "disabledefender": {"technique": "T1562.001", "tactic": "Impair Defenses: Disable or Modify Tools"},
    "netsh advfirewall": {"technique": "T1562.004", "tactic": "Impair Defenses: Disable or Modify System Firewall"},
    "taskkill": {"technique": "T1562.001", "tactic": "Impair Defenses: Disable or Modify Tools"},
    "IoT": {"technique": "T1496", "tactic": "Resource Hijacking"},
    "temp sensor": {"technique": "T1496", "tactic": "Resource Hijacking"},
}

# Scoring weights
WEIGHTS = {
    "file_encryption": 8,
    "shadow_deletion": 9,
    "defender_disable": 9,
    "suspicious_powershell": 7,
    "external_rdp": 7,
    "lateral_movement": 6,
    "suspicious_process": 6,
    "evidence_deletion": 7,
    "firewall_disable": 8,
    "iot_disconnect": 4,
    "ransom_note": 8,
    "brute_force": 5,
    "credential_reuse": 5,
}


# ──────────────────────────────────────────────────────────────────────────────
# Parsers
# ──────────────────────────────────────────────────────────────────────────────
def parse_windows_xml(path: str) -> List[Dict[str, Any]]:
    """
    Parse a Windows Event Log XML export (.evtx converted to XML).

    Args:
        path: Path to the XML file.

    Returns:
        List of event dictionaries with normalized keys:
        EventID, TimeCreated, Channel, Level, Provider, Computer,
        EventRecordID, Data (dict of Name->text), Message.
    """
    events = []
    tree = ET.parse(path)
    root = tree.getroot()

    # Handle both single Event root and Events wrapper
    # ElementTree namespace wildcard: {*} strips namespace prefix for matching
    event_elems = root.findall(".//{*}Event")
    # Only treat root as a single event if root IS an Event (not Events wrapper)
    if root.tag.endswith("}Event") or root.tag == "Event":
        event_elems = [root]

    for event in event_elems:
        system = event.find("{*}System")
        if system is None:
            continue

        def get_text(tag: str, attr: Optional[str] = None) -> Optional[str]:
            elem = system.find("{*}" + tag)
            if elem is None:
                return None
            if attr:
                return elem.get(attr)
            return elem.text or elem.get("text")  # Handle both text content and text="..." attribute

        record = {
            "EventID": get_text("EventID") or "0",
            "TimeCreated": get_text("TimeCreated", "SystemTime") or "",
            "Channel": get_text("Channel") or "",
            "Level": get_text("Level") or "4",
            "Provider": get_text("Provider", "Name") or "",
            "Computer": get_text("Computer") or "",
            "EventRecordID": get_text("EventRecordID") or "",
            "Data": {},
            "Message": "",
        }

        event_data = event.find("{*}EventData")
        if event_data is not None:
            for data in event_data:
                name = data.get("Name", "")
                text = data.text or ""
                if not text and data.get("text"):
                    text = data.get("text")
                if name:
                    record["Data"][name] = text
                # Heuristic: if a Data element has no Name but has text, treat as Message
                if not name and text:
                    record["Message"] = text

        # Also check RenderingInfo for Message if available
        rendering = event.find("{*}RenderingInfo")
        if rendering is not None:
            msg = rendering.find("{*}Message")
            if msg is not None and msg.text:
                record["Message"] = msg.text

        events.append(record)

    return events


def is_external_ip(ip: str) -> bool:
    """
    Check if an IP address is external (not RFC-1918 or loopback).

    Args:
        ip: IP address string.

    Returns:
        True if the IP appears to be external/public.
    """
    if not ip or ip in ("-", "::1", "localhost", "0.0.0.0"):
        return False
    for pattern in PRIVATE_IP_RANGES:
        if pattern.match(ip):
            return False
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Detection Engine
# ──────────────────────────────────────────────────────────────────────────────
def detect_indicators(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Scan all events for ransomware indicators and return scored findings.

    Args:
        events: Parsed event list from parse_windows_xml().

    Returns:
        List of detection dictionaries with keys:
        severity, category, technique, tactic, description, event_ids, timestamps, score.
    """
    findings = []
    data_texts = []
    for ev in events:
        dt = ev.get("Data", {})
        text = " ".join(str(v).lower() for v in dt.values())
        text += " " + (ev.get("Message", "")).lower()
        data_texts.append(text)

    # 1. File encryption / mass extension changes / ransom notes
    encrypted_files = []
    ransom_notes = []
    for i, ev in enumerate(events):
        text = data_texts[i]
        if RANSOM_NOTE_PATTERN.search(text):
            ransom_notes.append((ev["EventID"], ev["TimeCreated"], text))
        elif any(ext in text for ext in SUSPICIOUS_EXTENSIONS):
            encrypted_files.append((ev["EventID"], ev["TimeCreated"], text))

    if encrypted_files:
        findings.append({
            "severity": "CRITICAL",
            "category": "file_encryption",
            "technique": "T1486",
            "tactic": "Data Encrypted for Impact",
            "description": f"Detected {len(encrypted_files)} file modification events with suspicious extensions (e.g., .encrypted, .locked).",
            "event_ids": list(set(e[0] for e in encrypted_files))[:10],
            "timestamps": list(set(e[1] for e in encrypted_files))[:5],
            "score": WEIGHTS["file_encryption"],
            "details": [e[2][:200] for e in encrypted_files[:3]],
        })

    if ransom_notes:
        findings.append({
            "severity": "CRITICAL",
            "category": "ransom_note",
            "technique": "T1486",
            "tactic": "Data Encrypted for Impact",
            "description": f"Detected {len(ransom_notes)} ransom note creation events.",
            "event_ids": list(set(e[0] for e in ransom_notes))[:10],
            "timestamps": list(set(e[1] for e in ransom_notes))[:5],
            "score": WEIGHTS["ransom_note"],
            "details": [e[2][:200] for e in ransom_notes[:3]],
        })

    # 2. Volume shadow copy deletion
    shadow_deletions = []
    for i, ev in enumerate(events):
        text = data_texts[i]
        if "vssadmin" in text and "delete" in text and "shadow" in text:
            shadow_deletions.append((ev["EventID"], ev["TimeCreated"], text))
        if "wbadmin" in text and "delete" in text:
            shadow_deletions.append((ev["EventID"], ev["TimeCreated"], text))
        if "bcdedit" in text and ("/set" in text or "recoveryenabled" in text or "safeboot" in text):
            shadow_deletions.append((ev["EventID"], ev["TimeCreated"], text))

    if shadow_deletions:
        findings.append({
            "severity": "CRITICAL",
            "category": "shadow_deletion",
            "technique": "T1490",
            "tactic": "Inhibit System Recovery",
            "description": f"Volume shadow copy or recovery mechanism tampered with in {len(shadow_deletions)} events.",
            "event_ids": list(set(e[0] for e in shadow_deletions))[:10],
            "timestamps": list(set(e[1] for e in shadow_deletions))[:5],
            "score": WEIGHTS["shadow_deletion"],
            "details": [e[2][:200] for e in shadow_deletions[:3]],
        })

    # 3. Suspicious PowerShell / VBScript
    ps_events = []
    for i, ev in enumerate(events):
        text = data_texts[i]
        if ev.get("Channel", "").lower() in ("windows powershell", "microsoft-windows-powershell"):
            ps_events.append((ev["EventID"], ev["TimeCreated"], text))
        for pattern in SUSPICIOUS_POWERSHELL_PATTERNS:
            if pattern in text:
                ps_events.append((ev["EventID"], ev["TimeCreated"], text))
                break

    if ps_events:
        high_risk = [e for e in ps_events if any(p in e[2] for p in ["downloadstring", "downloadfile", "frombase64string", "-enc"])]
        severity = "CRITICAL" if high_risk else "HIGH"
        score = WEIGHTS["suspicious_powershell"] + (2 if high_risk else 0)
        findings.append({
            "severity": severity,
            "category": "suspicious_powershell",
            "technique": "T1059.001",
            "tactic": "Command and Scripting Interpreter: PowerShell",
            "description": f"Detected {len(ps_events)} suspicious PowerShell/scripting events. {len(high_risk)} involve download/encoding patterns.",
            "event_ids": list(set(e[0] for e in ps_events))[:10],
            "timestamps": list(set(e[1] for e in ps_events))[:5],
            "score": score,
            "details": [e[2][:200] for e in ps_events[:3]],
        })

    # 4. External RDP logins
    rdp_events = []
    for i, ev in enumerate(events):
        text = data_texts[i]
        if "logon type 10" in text or "rdp" in text:
            ip = ev.get("Data", {}).get("IpAddress", "")
            if not ip:
                # Try to extract IP from text via regex
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text)
                if match:
                    ip = match.group(1)
            if is_external_ip(ip):
                rdp_events.append((ev["EventID"], ev["TimeCreated"], text, ip))

    if rdp_events:
        findings.append({
            "severity": "HIGH",
            "category": "external_rdp",
            "technique": "T1021.001",
            "tactic": "Remote Services: RDP",
            "description": f"Detected {len(rdp_events)} successful/failed RDP logins from external IP addresses: {list(set(e[3] for e in rdp_events))[:5]}.",
            "event_ids": list(set(e[0] for e in rdp_events))[:10],
            "timestamps": list(set(e[1] for e in rdp_events))[:5],
            "score": WEIGHTS["external_rdp"],
            "details": [e[2][:200] for e in rdp_events[:3]],
        })

    # 5. Lateral movement (network logons + credential reuse pattern)
    lateral_events = []
    for i, ev in enumerate(events):
        text = data_texts[i]
        if "logon type 3" in text and "network" in text:
            # Check if same user appears on multiple hosts quickly
            lateral_events.append((ev["EventID"], ev["TimeCreated"], text))
        if "4648" in str(ev.get("EventID", "")) and "attempted logon" in text:
            lateral_events.append((ev["EventID"], ev["TimeCreated"], text))

    if lateral_events:
        findings.append({
            "severity": "HIGH",
            "category": "lateral_movement",
            "technique": "T1078",
            "tactic": "Valid Accounts",
            "description": f"Detected {len(lateral_events)} events suggesting lateral movement (network logons, explicit credential use).",
            "event_ids": list(set(e[0] for e in lateral_events))[:10],
            "timestamps": list(set(e[1] for e in lateral_events))[:5],
            "score": WEIGHTS["lateral_movement"],
            "details": [e[2][:200] for e in lateral_events[:3]],
        })

    # 6. Defender / security tool tampering
    defender_events = []
    for i, ev in enumerate(events):
        text = data_texts[i]
        if "defender" in text and ("disable" in text or "stop" in text or "tamper" in text):
            defender_events.append((ev["EventID"], ev["TimeCreated"], text))
        if "reg add" in text and "disabledefender" in text:
            defender_events.append((ev["EventID"], ev["TimeCreated"], text))
        if ev.get("EventID", "") == "5001":  # Defender disabled event
            defender_events.append((ev["EventID"], ev["TimeCreated"], text))
        if "windows defender" in text and "protection disabled" in text:
            defender_events.append((ev["EventID"], ev["TimeCreated"], text))

    if defender_events:
        findings.append({
            "severity": "CRITICAL",
            "category": "defender_disable",
            "technique": "T1562.001",
            "tactic": "Impair Defenses: Disable or Modify Tools",
            "description": f"Detected {len(defender_events)} events indicating Windows Defender or AV tampering.",
            "event_ids": list(set(e[0] for e in defender_events))[:10],
            "timestamps": list(set(e[1] for e in defender_events))[:5],
            "score": WEIGHTS["defender_disable"],
            "details": [e[2][:200] for e in defender_events[:3]],
        })

    # 7. Suspicious process creation
    process_events = []
    for i, ev in enumerate(events):
        text = data_texts[i]
        if str(ev.get("EventID", "")) == "4688":
            for proc in SUSPICIOUS_PROCESS_NAMES:
                if proc in text:
                    process_events.append((ev["EventID"], ev["TimeCreated"], text))
                    break
            for cmd in SUSPICIOUS_CMD_PATTERNS:
                if cmd in text:
                    process_events.append((ev["EventID"], ev["TimeCreated"], text))
                    break

    if process_events:
        findings.append({
            "severity": "HIGH",
            "category": "suspicious_process",
            "technique": "T1059",
            "tactic": "Command and Scripting Interpreter",
            "description": f"Detected {len(process_events)} suspicious process creation events.",
            "event_ids": list(set(e[0] for e in process_events))[:10],
            "timestamps": list(set(e[1] for e in process_events))[:5],
            "score": WEIGHTS["suspicious_process"],
            "details": [e[2][:200] for e in process_events[:3]],
        })

    # 8. Evidence deletion (wevtutil, etc.)
    evidence_events = []
    for i, ev in enumerate(events):
        text = data_texts[i]
        if "wevtutil" in text or "clear-log" in text or "cl " in text:
            evidence_events.append((ev["EventID"], ev["TimeCreated"], text))

    if evidence_events:
        findings.append({
            "severity": "HIGH",
            "category": "evidence_deletion",
            "technique": "T1070.001",
            "tactic": "Indicator Removal: Clear Windows Event Logs",
            "description": f"Detected {len(evidence_events)} events suggesting log/evidence deletion.",
            "event_ids": list(set(e[0] for e in evidence_events))[:10],
            "timestamps": list(set(e[1] for e in evidence_events))[:5],
            "score": WEIGHTS["evidence_deletion"],
            "details": [e[2][:200] for e in evidence_events[:3]],
        })

    # 9. Firewall disable
    fw_events = []
    for i, ev in enumerate(events):
        text = data_texts[i]
        if "netsh advfirewall" in text and "off" in text:
            fw_events.append((ev["EventID"], ev["TimeCreated"], text))

    if fw_events:
        findings.append({
            "severity": "HIGH",
            "category": "firewall_disable",
            "technique": "T1562.004",
            "tactic": "Impair Defenses: Disable or Modify System Firewall",
            "description": f"Detected {len(fw_events)} firewall disable attempts.",
            "event_ids": list(set(e[0] for e in fw_events))[:10],
            "timestamps": list(set(e[1] for e in fw_events))[:5],
            "score": WEIGHTS["firewall_disable"],
            "details": [e[2][:200] for e in fw_events[:3]],
        })

    # 10. IoT / sensor disconnect (pharmacy-specific: temperature monitoring)
    iot_events = []
    for i, ev in enumerate(events):
        text = data_texts[i]
        if any(k in text for k in ["iot_", "temp sensor", "humidity sensor", "temperature monitoring"]):
            iot_events.append((ev["EventID"], ev["TimeCreated"], text))
        if "dns resolution failed" in text and "sensor" in text:
            iot_events.append((ev["EventID"], ev["TimeCreated"], text))

    if iot_events:
        findings.append({
            "severity": "MEDIUM",
            "category": "iot_disconnect",
            "technique": "T1496",
            "tactic": "Resource Hijacking",
            "description": f"Detected {len(iot_events)} IoT/sensor disconnect events. Pharmacy temperature monitoring may be compromised.",
            "event_ids": list(set(e[0] for e in iot_events))[:10],
            "timestamps": list(set(e[1] for e in iot_events))[:5],
            "score": WEIGHTS["iot_disconnect"],
            "details": [e[2][:200] for e in iot_events[:3]],
        })

    # 11. Brute-force / failed logon pattern
    failed_logons = []
    for i, ev in enumerate(events):
        if str(ev.get("EventID", "")) == "4625":
            failed_logons.append((ev["EventID"], ev["TimeCreated"], data_texts[i]))

    if len(failed_logons) >= 3:
        findings.append({
            "severity": "MEDIUM",
            "category": "brute_force",
            "technique": "T1110",
            "tactic": "Brute Force",
            "description": f"Detected {len(failed_logons)} failed logon events (possible brute-force or credential stuffing).",
            "event_ids": ["4625"],
            "timestamps": list(set(e[1] for e in failed_logons))[:5],
            "score": WEIGHTS["brute_force"],
            "details": [e[2][:200] for e in failed_logons[:3]],
        })

    # Sort by score descending, then by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: (severity_order.get(x["severity"], 4), -x["score"]))
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Report Generators
# ──────────────────────────────────────────────────────────────────────────────
def generate_json_report(findings: List[Dict[str, Any]], events: List[Dict[str, Any]], output_path: str) -> None:
    """
    Write a structured JSON report with timeline and scored findings.

    Args:
        findings: Detection results from detect_indicators().
        events: Original parsed events.
        output_path: Destination JSON file.
    """
    total_score = sum(f["score"] for f in findings)
    max_possible = sum(WEIGHTS.values())
    risk_level = "LOW"
    if total_score >= 30:
        risk_level = "CRITICAL"
    elif total_score >= 20:
        risk_level = "HIGH"
    elif total_score >= 10:
        risk_level = "MEDIUM"

    report = {
        "metadata": {
            "tool": "analyze_logs.py",
            "version": "1.0.0",
            "generated_at": datetime.now().isoformat(),
            "author": "Vincent Phan (CPhT, CSUSB-bound IT/Cybersecurity student)",
            "disclaimer": "Synthetic data analysis for portfolio purposes. No real PHI.",
            "input_event_count": len(events),
            "finding_count": len(findings),
            "total_risk_score": total_score,
            "max_possible_score": max_possible,
            "risk_level": risk_level,
        },
        "findings": findings,
        "timeline": [
            {
                "timestamp": e["TimeCreated"],
                "event_id": e["EventID"],
                "channel": e["Channel"],
                "description": e.get("Message", "")[:200],
            }
            for e in events
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[+] JSON report written: {output_path}")


def generate_markdown_report(findings: List[Dict[str, Any]], events: List[Dict[str, Any]], output_path: str) -> None:
    """
    Write a human-readable markdown summary for incident responders.

    Args:
        findings: Detection results from detect_indicators().
        events: Original parsed events.
        output_path: Destination markdown file.
    """
    total_score = sum(f["score"] for f in findings)
    risk_level = "LOW"
    if total_score >= 30:
        risk_level = "CRITICAL"
    elif total_score >= 20:
        risk_level = "HIGH"
    elif total_score >= 10:
        risk_level = "MEDIUM"

    lines = [
        "# Ransomware Incident Response Analysis Report",
        "",
        f"> **Generated by:** `analyze_logs.py` v1.0.0  ",
        f"> **Analyst:** Vincent Phan (CPhT, CSUSB-bound IT/Cybersecurity student)  ",
        f"> **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"> **Disclaimer:** Synthetic data for portfolio demonstration. No real PHI.  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total Events Analyzed | {len(events)} |",
        f"| Findings Detected | {len(findings)} |",
        f"| Total Risk Score | {total_score} / {sum(WEIGHTS.values())} |",
        f"| Risk Level | **{risk_level}** |",
        "",
    ]

    if risk_level == "CRITICAL":
        lines.append(
            "**RANSOMWARE ACTIVITY IS HIGHLY LIKELY.** Multiple critical indicators detected. "
            "Immediate containment, evidence preservation, and HIPAA breach assessment required. "
            "Isolate affected systems per `network_isolation.sh` and escalate to incident commander."
        )
    elif risk_level == "HIGH":
        lines.append(
            "**SIGNIFICANT MALICIOUS ACTIVITY DETECTED.** Several high-confidence indicators of "
            "ransomware or advanced persistent threat activity. Proceed with containment and "
            "notification assessment per HIPAA playbook."
        )
    elif risk_level == "MEDIUM":
        lines.append(
            "**SUSPICIOUS ACTIVITY DETECTED.** Some indicators suggest compromise. "
            "Investigate further and consider precautionary isolation."
        )
    else:
        lines.append(
            "**LOW RISK.** No significant indicators detected. Continue monitoring."
        )

    lines += ["", "---", "", "## Detailed Findings", ""]

    for idx, finding in enumerate(findings, 1):
        lines += [
            f"### {idx}. {finding['category'].replace('_', ' ').title()}",
            "",
            f"| Attribute | Value |",
            f"|-----------|-------|",
            f"| Severity | {finding['severity']} |",
            f"| Score | {finding['score']} |",
            f"| MITRE Technique | [{finding['technique']}](https://attack.mitre.org/techniques/{finding['technique']}/) |",
            f"| MITRE Tactic | {finding['tactic']} |",
            f"| Event IDs | {', '.join(str(e) for e in finding['event_ids'][:5])} |",
            f"| Timestamps | {', '.join(finding['timestamps'][:3])} |",
            "",
            f"**Description:** {finding['description']}",
            "",
        ]
        if finding.get("details"):
            lines.append("**Raw Evidence (excerpt):**")
            lines.append("```")
            for d in finding["details"][:3]:
                lines.append(d)
            lines.append("```")
            lines.append("")

    lines += [
        "---",
        "",
        "## Recommended Actions (Pharmacy/Healthcare IR Playbook)",
        "",
        "1. **Immediate Containment:** Run `network_isolation.sh` to segment affected VLANs.",
        "2. **Evidence Preservation:** Do NOT power off systems. Snapshot memory and disk images.",
        "3. **HHS Notification:** Use `hipaa_notification_calculator.py` to determine all deadlines.",
        "4. **IOC Verification:** Run `check_iocs.py` against known file hashes and IPs.",
        "5. **State Board:** Notify state pharmacy board if ePHI or medication inventory data compromised.",
        "6. **Business Associates:** Notify any HIPAA BAs (e.g., insurance processors, cloud vendors) within 60 days.",
        "7. **Law Enforcement:** File FBI IC3 report if ransomware confirmed.",
        "",
        "---",
        "",
        "## Full Event Timeline",
        "",
        "| Time | Event ID | Channel | Description |",
        "|------|----------|---------|-------------|",
    ]

    for e in events:
        ts = e.get("TimeCreated", "N/A")
        eid = e.get("EventID", "N/A")
        ch = e.get("Channel", "N/A")
        desc = (e.get("Message", "") or "No message")[:80].replace("|", "\\|")
        lines.append(f"| {ts} | {eid} | {ch} | {desc} |")

    lines += [
        "",
        "---",
        "",
        "*End of Report*",
    ]

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[+] Markdown report written: {output_path}")


# ──────────────────────────────────────────────────────────────────────────────
# CLI & Main
# ──────────────────────────────────────────────────────────────────────────────
def main() -> int:
    """
    CLI entry point for analyze_logs.py.

    Returns:
        0 on success, 1 on error.
    """
    parser = argparse.ArgumentParser(
        description="Parse Windows Event Logs for ransomware indicators.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 analyze_logs.py sample_logs.xml
  python3 analyze_logs.py sample_logs.xml --json-out ir_timeline.json --md-out ir_summary.md

Author: Vincent Phan (CPhT, IT/Cybersecurity student)
        """,
    )
    parser.add_argument("input_xml", help="Path to Windows Event Log XML export")
    parser.add_argument("--json-out", default="ir_timeline.json", help="Output JSON report path")
    parser.add_argument("--md-out", default="ir_summary.md", help="Output Markdown report path")
    args = parser.parse_args()

    if not os.path.isfile(args.input_xml):
        print(f"[-] File not found: {args.input_xml}", file=sys.stderr)
        return 1

    print("=" * 60)
    print("RANSOMWARE LOG ANALYZER")
    print("Healthcare / Pharmacy Incident Response Playbook")
    print("=" * 60)
    print(f"[*] Parsing: {args.input_xml}")

    try:
        events = parse_windows_xml(args.input_xml)
    except ET.ParseError as e:
        print(f"[-] XML parse error: {e}", file=sys.stderr)
        return 1

    print(f"[*] Parsed {len(events)} events.")

    findings = detect_indicators(events)
    print(f"[*] Detected {len(findings)} indicator categories.")

    generate_json_report(findings, events, args.json_out)
    generate_markdown_report(findings, events, args.md_out)

    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print(f"    JSON: {args.json_out}")
    print(f"    Markdown: {args.md_out}")
    print("=" * 60)
    return 0


# ──────────────────────────────────────────────────────────────────────────────
# Embedded assertions for self-test (run with `python3 -c "import analyze_logs; ..."`)
# ──────────────────────────────────────────────────────────────────────────────
# Test 1: parse_windows_xml returns list
#   python3 -c "import analyze_logs, xml.etree.ElementTree as ET; import tempfile, os; " \
#     "root = ET.Element('Events'); e = ET.SubElement(root, 'Event'); s = ET.SubElement(e, 'System'); " \
#     "ET.SubElement(s, 'EventID', text='4624'); ET.SubElement(s, 'TimeCreated', SystemTime='2026-01-01T00:00:00Z'); " \
#     "ET.SubElement(s, 'Channel', text='Security'); ET.SubElement(s, 'Provider', Name='Test'); " \
#     "ET.SubElement(s, 'Computer', text='PC'); ET.SubElement(s, 'EventRecordID', text='1'); " \
#     "ET.SubElement(s, 'Level', text='4'); t = tempfile.NamedTemporaryFile(mode='wb', suffix='.xml', delete=False); " \
#     "ET.ElementTree(root).write(t.name); t.close(); " \
#     "events = analyze_logs.parse_windows_xml(t.name); os.unlink(t.name); " \
#     "assert len(events) == 1; assert events[0]['EventID'] == '4624'; print('PASS: parse_windows_xml')"
#
# Test 2: is_external_ip correctly identifies RFC-1918 vs external
#   python3 -c "import analyze_logs; assert not analyze_logs.is_external_ip('10.0.0.1'); assert not analyze_logs.is_external_ip('192.168.1.1'); assert analyze_logs.is_external_ip('203.0.113.77'); print('PASS: is_external_ip')"
#
# Test 3: detect_indicators flags vssadmin shadow deletion
#   python3 -c "import analyze_logs; events = [{'EventID': '4688', 'TimeCreated': '2026-01-01T00:00:00Z', 'Channel': 'Security', 'Level': '4', 'Provider': 'Test', 'Computer': 'PC', 'EventRecordID': '1', 'Data': {'CommandLine': 'vssadmin delete shadows /all /quiet'}, 'Message': ''}]; f = analyze_logs.detect_indicators(events); assert any(x['category'] == 'shadow_deletion' for x in f); print('PASS: detect shadow_deletion')"
#
# Test 4: detect_indicators flags .encrypted extension
#   python3 -c "import analyze_logs; events = [{'EventID': '4663', 'TimeCreated': '2026-01-01T00:00:00Z', 'Channel': 'Security', 'Level': '4', 'Provider': 'Test', 'Computer': 'PC', 'EventRecordID': '1', 'Data': {'ObjectName': 'C:\\\\data\\\\file.encrypted'}, 'Message': ''}]; f = analyze_logs.detect_indicators(events); assert any(x['category'] == 'file_encryption' for x in f); print('PASS: detect file_encryption')"

if __name__ == "__main__":
    sys.exit(main())
