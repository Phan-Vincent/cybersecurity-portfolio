import logging
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime

from .parser import NmapParser, Host, Port
from .vuln_db import VulnDB
from .reporter import ReportGenerator

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Immutable scan configuration with validation."""
    targets: List[str]
    ports: List[str] = field(default_factory=lambda: ["22", "80", "443", "445", "3389"])
    output_format: str = "json"  # json or markdown
    output_path: Optional[str] = None
    demo_mode: bool = False
    aggressive: bool = False  # -A flag (version, OS, script, traceroute)
    timing: int = 3  # nmap timing template (1-5)
    
    def __post_init__(self):
        if not self.targets and not self.demo_mode:
            raise ValueError("At least one target required (or use --demo)")
        if self.timing < 1 or self.timing > 5:
            raise ValueError("Timing must be between 1 and 5")
        if self.output_format not in ("json", "markdown"):
            raise ValueError("Output format must be 'json' or 'markdown'")


class NmapScanner:
    """
    Secure wrapper around nmap execution.
    
    Security considerations:
    - All user input is validated before subprocess execution
    - No shell=True (prevents injection)
    - Arguments are passed as a list (prevents shell metacharacter injection)
    - Output is XML (structured parsing, no regex on raw text)
    - Demo mode requires no network privileges or nmap installation
    """
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.vuln_db = VulnDB()
        self.reporter = ReportGenerator()
        self.results: List[Host] = []
        
    def _validate_targets(self, targets: List[str]) -> None:
        """Basic input validation to prevent accidental broad scans."""
        import re
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')
        hostname_pattern = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]$')
        
        for target in targets:
            if not (ip_pattern.match(target) or hostname_pattern.match(target)):
                raise ValueError(f"Invalid target format: {target}")
            # Prevent scanning overly broad ranges in non-demo mode
            if '/' in target:
                cidr = int(target.split('/')[1])
                if cidr < 16:
                    raise ValueError(f"CIDR /{cidr} too broad. Max /16 for safety.")
    
    def _build_nmap_args(self, targets: List[str], ports: List[str]) -> List[str]:
        """Build safe nmap argument list (no shell injection possible)."""
        args = [
            "nmap",
            "-oX", "-",  # Output XML to stdout
            "-T", str(self.config.timing),
            "-p", ",".join(ports),
        ]
        
        if self.config.aggressive:
            args.append("-A")
        else:
            args.extend(["-sV", "-sS"])  # Version scan + SYN scan
            
        args.extend(targets)
        return args
    
    def _run_nmap(self, targets: List[str], ports: List[str]) -> str:
        """Execute nmap subprocess and return XML string."""
        self._validate_targets(targets)
        
        args = self._build_nmap_args(targets, ports)
        logger.info(f"Executing: {' '.join(args)}")
        
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                check=False
            )
        except FileNotFoundError:
            raise RuntimeError(
                "nmap not found. Install nmap or use --demo mode. "
                "macOS: brew install nmap | Linux: apt install nmap"
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("nmap scan timed out (5 min limit)")
        
        if result.returncode != 0 and result.returncode != 1:
            # nmap returns 1 for "no hosts found", which is fine
            raise RuntimeError(f"nmap failed: {result.stderr}")
        
        return result.stdout
    
    def _load_demo_data(self) -> str:
        """Load bundled synthetic nmap XML for demo mode."""
        demo_path = Path(__file__).parent.parent / "data" / "sample_nmap_output.xml"
        if not demo_path.exists():
            raise FileNotFoundError(f"Demo data not found at {demo_path}")
        return demo_path.read_text()
    
    def run(self) -> Dict[str, Any]:
        """
        Execute scan (or load demo data) and generate report.
        
        Returns:
            Dict containing scan metadata, hosts, and risk summary.
        """
        logger.info("=" * 60)
        logger.info("Network Recon & Vuln Scanner Wrapper")
        logger.info("⚠️  AUTHORIZED USE ONLY")
        logger.info("=" * 60)
        
        scan_start = datetime.now().isoformat()
        
        if self.config.demo_mode:
            logger.info("Running in DEMO mode (no network traffic)")
            xml_data = self._load_demo_data()
        else:
            logger.info(f"Targets: {', '.join(self.config.targets)}")
            logger.info(f"Ports: {', '.join(self.config.ports)}")
            xml_data = self._run_nmap(self.config.targets, self.config.ports)
        
        # Parse XML into structured objects
        parser = NmapParser(xml_data)
        self.results = parser.parse()
        
        # Cross-reference with synthetic CVE database
        for host in self.results:
            for port in host.ports:
                port.cve_matches = self.vuln_db.check_version(
                    port.service_name, port.product, port.version
                )
                port.risk_level = self._calculate_risk(port)
        
        # Generate report
        report = self.reporter.generate(
            hosts=self.results,
            scan_start=scan_start,
            demo_mode=self.config.demo_mode
        )
        
        # Save to file if path provided
        if self.config.output_path:
            self.reporter.save(report, self.config.output_path, self.config.output_format)
        
        # Print console summary
        self._print_summary(report)
        
        return report
    
    def _calculate_risk(self, port: Port) -> str:
        """Heuristic risk scoring based on service + CVE matches."""
        # High-risk services (exposed management/RMI)
        high_risk_services = {"ms-wbt-server", "microsoft-ds", "mysql", "ms-sql", "rdp", "vnc", "telnet", "ftp"}
        # Medium-risk services (web, but may have known vulns)
        medium_risk_services = {"http", "https", "ssh", "smtp", "imap", "pop3"}
        
        if port.service_name in high_risk_services or port.port in {445, 3389, 3306, 1433, 23, 21}:
            if port.cve_matches:
                return "HIGH"
            return "HIGH"  # Exposed RDP/SMB is always high risk
        
        if port.service_name in medium_risk_services or port.port in {80, 443, 22, 25, 143, 110}:
            if port.cve_matches:
                return "MEDIUM"
            return "LOW"
        
        return "LOW"
    
    def _print_summary(self, report: Dict[str, Any]) -> None:
        """Print formatted console output."""
        print()
        print("╔" + "=" * 62 + "╗")
        print("║" + " " * 12 + "Network Recon & Vuln Scanner Wrapper" + " " * 12 + "║")
        print("║" + " " * 15 + "⚠️ AUTHORIZED USE ONLY ⚠️" + " " * 16 + "║")
        print("╚" + "=" * 62 + "╝")
        print()
        
        for host in report["hosts"]:
            print(f"Host: {host['address']} {host.get('hostname', '')}")
            for port in host["ports"]:
                risk_emoji = "🔴" if port["risk_level"] == "HIGH" else "⚠️" if port["risk_level"] == "MEDIUM" else "🟢"
                print(f"  {risk_emoji} Port {port['port']}/{port['protocol']}\t{port['state']}\t{port['service_name']}\t{port.get('product', 'unknown')} {port.get('version', '')}")
                if port["cve_matches"]:
                    cve = port["cve_matches"][0]
                    print(f"      └─ Risk: {port['risk_level']} | CVE match: {cve['id']} ({cve['description'][:50]}...)")
                else:
                    print(f"      └─ Risk: {port['risk_level']} | CVE match: None")
            print()
        
        print("═" * 64)
        summary = report["summary"]
        print(f"SUMMARY: {summary['total_hosts']} hosts | {summary['total_ports']} open ports | "
              f"{summary['high_risk']} HIGH | {summary['medium_risk']} MEDIUM | {summary['low_risk']} LOW")
        print("═" * 64)
        
        if report.get("saved_path"):
            print(f"\nReport saved: {report['saved_path']}")
