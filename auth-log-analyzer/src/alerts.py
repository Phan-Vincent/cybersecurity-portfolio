"""Alert dataclass + formatting utilities."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Alert:
    """Single detection alert."""

    rule: str
    severity: str  # critical, high, medium, low
    timestamp: str  # ISO-8601
    description: str
    source_ip: Optional[str]
    mitre_technique: str
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "description": self.description,
            "source_ip": self.source_ip,
            "mitre_technique": self.mitre_technique,
            "evidence": self.evidence,
        }


class AlertManager:
    """Converts a list of Alerts into human-readable Markdown."""

    def __init__(self, alerts: List[Alert]):
        self.alerts = alerts

    def to_markdown(self) -> str:
        if not self.alerts:
            return "# Auth Log Analysis Report\n\n✅ No anomalies detected.\n"

        lines = [
            "# Auth Log Analysis Report",
            f"\n**Total Alerts:** {len(self.alerts)}",
            "",
        ]

        # Severity summary
        sev_counts: dict = {}
        for a in self.alerts:
            sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
        lines.append("## Severity Breakdown")
        for sev in ("critical", "high", "medium", "low"):
            if sev in sev_counts:
                lines.append(f"- **{sev.upper()}:** {sev_counts[sev]}")
        lines.append("")

        # Detailed alerts
        lines.append("## Detected Anomalies")
        for idx, alert in enumerate(self.alerts, start=1):
            lines.append(f"\n### Alert {idx}: `{alert.rule}` ({alert.severity.upper()})")
            lines.append(f"- **Time:** {alert.timestamp}")
            lines.append(f"- **MITRE:** {alert.mitre_technique}")
            if alert.source_ip:
                lines.append(f"- **Source IP:** {alert.source_ip}")
            lines.append(f"- **Description:** {alert.description}")
            if alert.evidence:
                lines.append("- **Evidence:**")
                for ev in alert.evidence:
                    lines.append(f"  ```")
                    lines.append(f"  {ev}")
                    lines.append(f"  ```")
            lines.append("")

        return "\n".join(lines)
