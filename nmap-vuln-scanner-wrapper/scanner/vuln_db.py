"""
Synthetic CVE Database
Local, curated vulnerability database for version cross-referencing.

IMPORTANT: This is synthetic/demo data for educational purposes.
- No live NVD API calls (no internet required, no data leakage)
- Curated subset of well-known CVEs
- Not exhaustive — demonstrates the concept, not a production scanner
"""
from typing import Dict, List, Optional


class VulnDB:
    """
    Local vulnerability database.
    
    Maps service names and versions to known CVEs.
    This is a curated subset of high-impact vulnerabilities for demonstration.
    In production, you would integrate with NVD API or local vulnerability feeds.
    """
    
    def __init__(self):
        # Database structure: {service_name: [(version_pattern, cve_entries)]}
        self._db = self._build_database()
    
    def _build_database(self) -> Dict[str, List]:
        """Build synthetic vulnerability database."""
        db = {
            "ssh": [
                {
                    "version": "7.4",
                    "cve": {
                        "id": "CVE-2018-15473",
                        "description": "OpenSSH user enumeration via timing attack",
                        "severity": "MEDIUM",
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2018-15473"
                    }
                },
                {
                    "version": "8.2",
                    "cve": {
                        "id": "CVE-2020-15778",
                        "description": "OpenSSH scp command injection vulnerability",
                        "severity": "HIGH",
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-15778"
                    }
                }
            ],
            "http": [
                {
                    "version": "2.4.41",
                    "cve": {
                        "id": "CVE-2021-41773",
                        "description": "Apache HTTP Server path traversal and file disclosure",
                        "severity": "HIGH",
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
                    }
                },
                {
                    "version": "2.4.29",
                    "cve": {
                        "id": "CVE-2018-1312",
                        "description": "Apache HTTP Server mod_session cookie expiration vulnerability",
                        "severity": "MEDIUM",
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2018-1312"
                    }
                }
            ],
            "https": [
                {
                    "version": "2.4.41",
                    "cve": {
                        "id": "CVE-2021-41773",
                        "description": "Apache HTTP Server path traversal and file disclosure",
                        "severity": "HIGH",
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
                    }
                }
            ],
            "mysql": [
                {
                    "version": "5.7.33",
                    "cve": {
                        "id": "CVE-2021-2154",
                        "description": "MySQL privilege escalation vulnerability",
                        "severity": "HIGH",
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-2154"
                    }
                },
                {
                    "version": "5.7.29",
                    "cve": {
                        "id": "CVE-2020-2574",
                        "description": "MySQL denial of service via malformed handshake",
                        "severity": "MEDIUM",
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-2574"
                    }
                }
            ],
            "microsoft-ds": [
                {
                    "version": "4.11.6",
                    "cve": {
                        "id": "CVE-2020-1472",
                        "description": "Zerologon - Netlogon elevation of privilege",
                        "severity": "CRITICAL",
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-1472"
                    }
                }
            ],
            "ms-sql": [
                {
                    "version": "2017",
                    "cve": {
                        "id": "CVE-2019-1068",
                        "description": "Microsoft SQL Server remote code execution",
                        "severity": "HIGH",
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-1068"
                    }
                }
            ],
            "ftp": [
                {
                    "version": "3.0.3",
                    "cve": {
                        "id": "CVE-2019-12815",
                        "description": "ProFTPd mod_copy information disclosure",
                        "severity": "HIGH",
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-12815"
                    }
                }
            ],
            "nginx": [
                {
                    "version": "1.14.0",
                    "cve": {
                        "id": "CVE-2019-9511",
                        "description": "Nginx HTTP/2 excessive resource consumption",
                        "severity": "HIGH",
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-9511"
                    }
                }
            ]
        }
        return db
    
    def check_version(self, service_name: str, product: Optional[str], version: Optional[str]) -> List[Dict]:
        """
        Check if a service version has known CVEs.
        
        Args:
            service_name: nmap service name (e.g., 'http', 'ssh')
            product: product name (e.g., 'Apache httpd', 'OpenSSH')
            version: version string (e.g., '2.4.41')
        
        Returns:
            List of matching CVE dictionaries
        """
        if not version:
            return []
        
        matches = []
        
        # Check by service name
        entries = self._db.get(service_name.lower(), [])
        for entry in entries:
            # Simple version matching: check if version starts with DB version
            # In production, you'd use semver comparison or proper parsing
            if version.startswith(entry["version"]):
                matches.append(entry["cve"])
        
        # Also check by product name if available
        if product:
            product_key = product.lower().split()[0]  # First word of product
            entries = self._db.get(product_key, [])
            for entry in entries:
                if version.startswith(entry["version"]):
                    if entry["cve"] not in matches:  # Avoid duplicates
                        matches.append(entry["cve"])
        
        return matches
    
    def get_all_cves(self) -> Dict[str, List[Dict]]:
        """Return full database (for reporting/debugging)."""
        result = {}
        for service, entries in self._db.items():
            result[service] = [e["cve"] for e in entries]
        return result
