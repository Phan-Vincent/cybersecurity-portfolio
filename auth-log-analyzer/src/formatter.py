"""
formatter.py
Alert formatter — outputs alerts as structured JSON and human-readable summaries.

Designed for two consumption paths:
  1. SIEM ingestion (JSON with schema)
  2. SOC analyst triage (human-readable markdown/text)
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any
from detections import Alert


def _alert_to_dict(alert: Alert) -> Dict[str, Any]:
    """Convert an Alert to a JSON-serializable dict."""
    return {
        "alert_id": alert.alert_id,
        "severity": alert.severity,
        "detection_type": alert.detection_type,
        "title": alert.title,
        "description": alert.description,
        "mitre_technique": alert.mitre_technique,
        "mitre_tactic": alert.mitre_tactic,
        "source_ips": alert.source_ips,
        "usernames": alert.usernames,
        "timestamp": alert.timestamp.isoformat(),
        "confidence": alert.confidence,
        "source_event_count": len(alert.source_events),
        "source_events": [
            {
                "timestamp": e.timestamp.isoformat(),
                "hostname": e.hostname,
                "process": e.process,
                "event_type": e.event_type,
                "username": e.username,
                "source_ip": e.source_ip,
                "message": e.message,
            }
            for e in alert.source_events
        ],
    }


def format_json(alerts: List[Alert], pretty: bool = True) -> str:
    """Return alerts as a JSON string."""
    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "alert_count": len(alerts),
        "alerts": [_alert_to_dict(a) for a in alerts],
    }
    indent = 2 if pretty else None
    return json.dumps(data, indent=indent, default=str)


def format_human(alerts: List[Alert]) -> str:
    """Return a human-readable summary for SOC triage."""
    if not alerts:
        return "=== AUTH LOG ANALYSIS REPORT ===\nNo alerts generated. Clean log.\n"

    lines = [
        "=== AUTH LOG ANALYSIS REPORT ===",
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"Total Alerts: {len(alerts)}",
        "",
        "─" * 60,
    ]

    # Sort by severity: critical > high > medium > low
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_alerts = sorted(alerts, key=lambda a: severity_order.get(a.severity, 99))

    for alert in sorted_alerts:
        lines.extend([
            f"\n[ {alert.severity.upper()} ] {alert.title}",
            f"  Alert ID:    {alert.alert_id}",
            f"  Type:        {alert.detection_type}",
            f"  MITRE:       {alert.mitre_technique} ({alert.mitre_tactic})",
            f"  Confidence:  {alert.confidence}",
            f"  Time:        {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"  IPs:         {', '.join(alert.source_ips) if alert.source_ips else 'N/A'}",
            f"  Users:       {', '.join(alert.usernames) if alert.usernames else 'N/A'}",
            f"  Events:      {len(alert.source_events)} source log lines",
            "",
            f"  Description: {alert.description}",
            "─" * 60,
        ])

    # Executive summary
    lines.extend([
        "",
        "=== EXECUTIVE SUMMARY ===",
        f"  Critical: {sum(1 for a in alerts if a.severity == 'critical')}",
        f"  High:     {sum(1 for a in alerts if a.severity == 'high')}",
        f"  Medium:   {sum(1 for a in alerts if a.severity == 'medium')}",
        f"  Low:      {sum(1 for a in alerts if a.severity == 'low')}",
        "",
        "Recommended Actions:",
    ])

    recs = _generate_recommendations(alerts)
    for r in recs:
        lines.append(f"  • {r}")

    lines.append("")
    return "\n".join(lines)


def _generate_recommendations(alerts: List[Alert]) -> List[str]:
    """Generate analyst-facing recommendations based on alert types."""
    recs = set()
    types = {a.detection_type for a in alerts}

    if "brute_force" in types:
        recs.add("Block source IPs at the network edge (WAF/firewall). Review fail2ban or equivalent.")
    if "credential_stuffing_success" in types:
        recs.add("FORCE PASSWORD RESET for affected accounts. Enable MFA immediately. Review for lateral movement.")
    if "impossible_travel" in types:
        recs.add("Correlate with VPN logs and MFA push logs. Check for session hijacking or credential reuse.")
    if "privilege_escalation" in types:
        recs.add("Audit sudoers file. Validate need for root access. Review command history for persistence.")
    if "off_hours_useradd" in types:
        recs.add("Validate new account creation against change tickets. Check for shadow admin accounts.")

    if not recs:
        recs.add("No specific action required. Continue monitoring.")

    return sorted(recs)


def write_outputs(alerts: List[Alert], output_dir: str, basename: str = "report") -> Dict[str, str]:
    """Write JSON and human-readable reports to disk. Returns paths written."""
    os.makedirs(output_dir, exist_ok=True)
    paths = {}

    json_path = os.path.join(output_dir, f"{basename}.json")
    with open(json_path, "w") as f:
        f.write(format_json(alerts))
    paths["json"] = json_path

    human_path = os.path.join(output_dir, f"{basename}.txt")
    with open(human_path, "w") as f:
        f.write(format_human(alerts))
    paths["human"] = human_path

    return paths
