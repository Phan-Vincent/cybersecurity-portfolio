#!/usr/bin/env python3
"""
nmap_parser.py — Parse nmap XML output into structured Python dataclasses.

Handles the standard nmap XML format produced by `nmap -oX`.
Extracts host metadata, open ports, service banners, and OS fingerprints.

Author: Vincent Phan
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from xml.etree import ElementTree as ET


@dataclass
class HostInfo:
    """Structured representation of a scanned host."""
    ip: str
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    os_accuracy: Optional[int] = None
    state: str = "unknown"


@dataclass
class PortFinding:
    """A single open port with its detected service and banner."""
    port: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    service_extrainfo: Optional[str] = None
    banner: Optional[str] = None


@dataclass
class ScanMetadata:
    """Top-level scan execution metadata."""
    scanner: str = "nmap"
    args: str = ""
    start_time: Optional[str] = None
    nmap_version: Optional[str] = None
    xml_version: Optional[str] = None


@dataclass
class ScanResult:
    """Full parsed result from a single nmap XML file."""
    metadata: ScanMetadata = field(default_factory=ScanMetadata)
    hosts: List[HostInfo] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)


class NmapParser:
    """Parse nmap XML output into structured ScanResult objects."""

    def __init__(self, xml_path: Path) -> None:
        self.xml_path = xml_path
        if not self.xml_path.exists():
            raise FileNotFoundError(f"nmap XML not found: {xml_path}")

    def parse(self) -> ScanResult:
        """Parse the XML file and return a fully populated ScanResult."""
        tree = ET.parse(self.xml_path)
        root = tree.getroot()

        result = ScanResult()
        result.metadata = self._extract_metadata(root)

        for host_elem in root.findall("host"):
            host_info = self._parse_host(host_elem)
            result.hosts.append(host_info)

            for port_finding in self._parse_ports(host_elem, host_info):
                result.findings.append(port_finding)

        return result

    def _extract_metadata(self, root: ET.Element) -> ScanMetadata:
        """Pull top-level nmap run attributes."""
        meta = ScanMetadata()
        nmaprun = root
        if nmaprun is not None:
            meta.args = nmaprun.get("args", "")
            meta.start_time = nmaprun.get("startstr", "")
            meta.nmap_version = nmaprun.get("version", "")
            meta.xml_version = nmaprun.get("xmloutputversion", "")
        return meta

    def _parse_host(self, host_elem: ET.Element) -> HostInfo:
        """Extract host-level info (IP, hostname, state, OS guess)."""
        # Address
        address_elem = host_elem.find("address[@addrtype='ipv4']")
        ip = address_elem.get("addr", "unknown") if address_elem is not None else "unknown"

        # Hostname
        hostnames = host_elem.find("hostnames")
        hostname = None
        if hostnames is not None:
            name_elem = hostnames.find("hostname")
            if name_elem is not None:
                hostname = name_elem.get("name")

        # State
        status = host_elem.find("status")
        state = status.get("state", "unknown") if status is not None else "unknown"

        # OS detection
        os_guess = None
        os_accuracy = None
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_guess = osmatch.get("name")
                os_accuracy = int(osmatch.get("accuracy", "0"))

        return HostInfo(
            ip=ip,
            hostname=hostname,
            os_guess=os_guess,
            os_accuracy=os_accuracy,
            state=state,
        )

    def _parse_ports(self, host_elem: ET.Element, host_info: HostInfo) -> List[dict]:
        """Extract all open port findings for a given host."""
        findings: List[dict] = []
        ports = host_elem.find("ports")
        if ports is None:
            return findings

        for port in ports.findall("port"):
            state_elem = port.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            port_num = int(port.get("portid", 0))
            protocol = port.get("protocol", "tcp")

            service_elem = port.find("service")
            service_name = None
            service_product = None
            service_version = None
            service_extrainfo = None
            banner = None

            if service_elem is not None:
                service_name = service_elem.get("name")
                service_product = service_elem.get("product")
                service_version = service_elem.get("version")
                service_extrainfo = service_elem.get("extrainfo")
                # Construct a synthetic banner from product + version + extrainfo
                parts = [p for p in [service_product, service_version, service_extrainfo] if p]
                if parts:
                    banner = " ".join(parts)

            findings.append({
                "host_ip": host_info.ip,
                "host_hostname": host_info.hostname,
                "host_os": host_info.os_guess,
                "port": port_num,
                "protocol": protocol,
                "service_name": service_name,
                "service_product": service_product,
                "service_version": service_version,
                "banner": banner,
            })

        return findings
