"""
Nmap XML Parser
Converts nmap XML output into structured Python dataclasses.
"""
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class Port:
    """Represents a single open port with service information."""
    port: int
    protocol: str
    state: str
    service_name: str
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    cve_matches: List[Dict] = field(default_factory=list)
    risk_level: str = "UNKNOWN"


@dataclass
class Host:
    """Represents a scanned host with its open ports."""
    address: str
    hostname: Optional[str] = None
    status: str = "unknown"
    os_match: Optional[str] = None
    ports: List[Port] = field(default_factory=list)


class NmapParser:
    """
    Secure XML parser for nmap output.
    
    Security note:
    - Uses xml.etree.ElementTree (standard lib, no external deps)
    - No DTD processing to prevent XXE attacks
    - No regex parsing of raw XML (structured parsing only)
    """
    
    def __init__(self, xml_data: str):
        self.xml_data = xml_data
        
    def parse(self) -> List[Host]:
        """Parse nmap XML and return list of Host objects."""
        # Security: disable external entity resolution
        # ET.parse in Python 3.x doesn't process external DTDs by default,
        # but we strip any DOCTYPE declarations as defense in depth
        xml_data = self._sanitize_xml(self.xml_data)
        
        root = ET.fromstring(xml_data)
        hosts = []
        
        for host_elem in root.findall("host"):
            host = self._parse_host(host_elem)
            if host.ports:  # Only include hosts with open ports
                hosts.append(host)
        
        return hosts
    
    def _sanitize_xml(self, xml_data: str) -> str:
        """Remove DOCTYPE declarations to prevent XXE."""
        lines = xml_data.split('\n')
        cleaned = []
        for line in lines:
            if line.strip().upper().startswith('<!DOCTYPE'):
                continue
            cleaned.append(line)
        return '\n'.join(cleaned)
    
    def _parse_host(self, host_elem: ET.Element) -> Host:
        """Extract host information from XML element."""
        address = "unknown"
        hostname = None
        status = "unknown"
        os_match = None
        
        # Get IP address
        addr_elem = host_elem.find("address[@addrtype='ipv4']")
        if addr_elem is not None:
            address = addr_elem.get("addr", "unknown")
        
        # Get hostname
        hostnames = host_elem.find("hostnames")
        if hostnames is not None:
            hostname_elem = hostnames.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name")
        
        # Get status
        status_elem = host_elem.find("status")
        if status_elem is not None:
            status = status_elem.get("state", "unknown")
        
        # Get OS match (if available)
        os_elem = host_elem.find("os/osmatch")
        if os_elem is not None:
            os_match = os_elem.get("name")
        
        # Parse ports
        ports = self._parse_ports(host_elem.find("ports"))
        
        return Host(
            address=address,
            hostname=hostname,
            status=status,
            os_match=os_match,
            ports=ports
        )
    
    def _parse_ports(self, ports_elem: Optional[ET.Element]) -> List[Port]:
        """Extract port information from XML element."""
        if ports_elem is None:
            return []
        
        ports = []
        for port_elem in ports_elem.findall("port"):
            port = self._parse_port(port_elem)
            if port.state == "open":
                ports.append(port)
        
        return ports
    
    def _parse_port(self, port_elem: ET.Element) -> Port:
        """Extract single port information."""
        port_id = port_elem.get("portid", "0")
        protocol = port_elem.get("protocol", "tcp")
        
        state = "unknown"
        state_elem = port_elem.find("state")
        if state_elem is not None:
            state = state_elem.get("state", "unknown")
        
        service_name = "unknown"
        product = None
        version = None
        extra_info = None
        
        service_elem = port_elem.find("service")
        if service_elem is not None:
            service_name = service_elem.get("name", "unknown")
            product = service_elem.get("product")
            version = service_elem.get("version")
            extra_info = service_elem.get("extrainfo")
        
        return Port(
            port=int(port_id),
            protocol=protocol,
            state=state,
            service_name=service_name,
            product=product,
            version=version,
            extra_info=extra_info
        )
    
    def get_statistics(self, hosts: List[Host]) -> Dict:
        """Calculate scan statistics."""
        total_hosts = len(hosts)
        total_ports = sum(len(h.ports) for h in hosts)
        high_risk = sum(1 for h in hosts for p in h.ports if p.risk_level == "HIGH")
        medium_risk = sum(1 for h in hosts for p in h.ports if p.risk_level == "MEDIUM")
        low_risk = sum(1 for h in hosts for p in h.ports if p.risk_level == "LOW")
        
        return {
            "total_hosts": total_hosts,
            "total_ports": total_ports,
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": low_risk
        }
