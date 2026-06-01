"""
Report Generator
Produces JSON and Markdown reports from parsed scan data.
"""
import json
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path

from .parser import Host


class ReportGenerator:
    """Generate structured reports from scan results."""
    
    def generate(self, hosts: List[Host], scan_start: str, demo_mode: bool = False) -> Dict[str, Any]:
        """Generate report dictionary with metadata and findings."""
        # Convert Host objects to serializable dicts
        host_dicts = []
        for host in hosts:
            port_dicts = []
            for port in host.ports:
                port_dicts.append({
                    "port": port.port,
                    "protocol": port.protocol,
                    "state": port.state,
                    "service_name": port.service_name,
                    "product": port.product,
                    "version": port.version,
                    "extra_info": port.extra_info,
                    "risk_level": port.risk_level,
                    "cve_matches": port.cve_matches
                })
            
            host_dicts.append({
                "address": host.address,
                "hostname": host.hostname,
                "status": host.status,
                "os_match": host.os_match,
                "ports": port_dicts
            })
        
        # Calculate summary
        total_ports = sum(len(h.ports) for h in hosts)
        high_risk = sum(1 for h in hosts for p in h.ports if p.risk_level == "HIGH")
        medium_risk = sum(1 for h in hosts for p in h.ports if p.risk_level == "MEDIUM")
        low_risk = sum(1 for h in hosts for p in h.ports if p.risk_level == "LOW")
        
        report = {
            "metadata": {
                "tool": "nmap-vuln-scanner-wrapper",
                "version": "1.0.0",
                "scan_start": scan_start,
                "scan_end": datetime.now().isoformat(),
                "demo_mode": demo_mode,
                "ethical_notice": "This scan was conducted with explicit authorization. "
                                "Unauthorized scanning is illegal and unethical."
            },
            "summary": {
                "total_hosts": len(hosts),
                "total_ports": total_ports,
                "high_risk": high_risk,
                "medium_risk": medium_risk,
                "low_risk": low_risk,
                "unknown_risk": total_ports - high_risk - medium_risk - low_risk
            },
            "hosts": host_dicts
        }
        
        return report
    
    def save(self, report: Dict[str, Any], output_path: str, format: str = "json") -> str:
        """Save report to file."""
        path = Path(output_path)
        
        if format == "json":
            path.write_text(json.dumps(report, indent=2))
        elif format == "markdown":
            path.write_text(self._to_markdown(report))
        else:
            raise ValueError(f"Unknown format: {format}")
        
        return str(path.absolute())
    
    def _to_markdown(self, report: Dict[str, Any]) -> str:
        """Convert report to Markdown format."""
        meta = report["metadata"]
        summary = report["summary"]
        
        md = f"""# Network Reconnaissance Report

> **Generated:** {meta['scan_end']}  
> **Tool:** {meta['tool']} v{meta['version']}  
> **Demo Mode:** {'Yes' if meta['demo_mode'] else 'No'}

## ⚠️ Ethical Notice

{meta['ethical_notice']}

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Hosts | {summary['total_hosts']} |
| Total Open Ports | {summary['total_ports']} |
| 🔴 High Risk | {summary['high_risk']} |
| ⚠️ Medium Risk | {summary['medium_risk']} |
| 🟢 Low Risk | {summary['low_risk']} |

## Detailed Findings

"""
        
        for host in report["hosts"]:
            hostname = host.get("hostname", "N/A")
            os_info = host.get("os_match", "Unknown")
            md += f"### Host: {host['address']} ({hostname})\n\n"
            md += f"- **Status:** {host['status']}\n"
            md += f"- **OS:** {os_info}\n\n"
            md += "| Port | Protocol | Service | Product | Version | Risk | CVEs |\n"
            md += "|------|----------|---------|---------|---------|------|------|\n"
            
            for port in host["ports"]:
                cves = ", ".join([c['id'] for c in port['cve_matches']]) if port['cve_matches'] else "None"
                risk_emoji = "🔴" if port['risk_level'] == "HIGH" else "⚠️" if port['risk_level'] == "MEDIUM" else "🟢"
                md += f"| {port['port']} | {port['protocol']} | {port['service_name']} | {port.get('product', 'N/A')} | {port.get('version', 'N/A')} | {risk_emoji} {port['risk_level']} | {cves} |\n"
            
            md += "\n"
        
        md += "---\n\n"
        md += "**Recommendations:**\n\n"
        
        if summary['high_risk'] > 0:
            md += "1. **Immediate:** Review all HIGH risk findings. Exposed RDP/SMB should be firewalled or VPN-restricted.\n"
        if summary['medium_risk'] > 0:
            md += "2. **Short-term:** Patch services with known CVE matches. Prioritize internet-facing services.\n"
        md += "3. **Ongoing:** Implement continuous scanning with authorized scope boundaries.\n"
        
        return md
