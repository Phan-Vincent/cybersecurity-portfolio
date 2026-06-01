"""
Unit tests for the scanner wrapper.
Run with: python -m pytest tests/
"""
import unittest
from pathlib import Path

from scanner.parser import NmapParser, Host, Port
from scanner.vuln_db import VulnDB
from scanner.reporter import ReportGenerator
from scanner.scanner import ScanConfig, NmapScanner


class TestParser(unittest.TestCase):
    """Test XML parsing functionality."""
    
    def test_parse_demo_xml(self):
        """Parse the bundled demo XML file."""
        xml_path = Path(__file__).parent.parent / "data" / "sample_nmap_output.xml"
        xml_data = xml_path.read_text()
        
        parser = NmapParser(xml_data)
        hosts = parser.parse()
        
        self.assertEqual(len(hosts), 3)
        self.assertEqual(hosts[0].address, "192.168.1.10")
        self.assertEqual(hosts[0].hostname, "web-server-01")
        
        # Check ports
        self.assertEqual(len(hosts[0].ports), 4)
        self.assertEqual(hosts[0].ports[0].port, 22)
        self.assertEqual(hosts[0].ports[0].service_name, "ssh")
    
    def test_sanitize_xml(self):
        """Ensure DOCTYPE is stripped."""
        xml_with_doctype = """<?xml version="1.0"?>
<!DOCTYPE nmaprun SYSTEM "nmap.dtd">
<nmaprun><host></host></nmaprun>"""
        
        parser = NmapParser(xml_with_doctype)
        cleaned = parser._sanitize_xml(xml_with_doctype)
        self.assertNotIn("<!DOCTYPE", cleaned)
    
    def test_empty_xml(self):
        """Handle empty nmap output gracefully."""
        parser = NmapParser("<nmaprun></nmaprun>")
        hosts = parser.parse()
        self.assertEqual(len(hosts), 0)


class TestVulnDB(unittest.TestCase):
    """Test synthetic vulnerability database."""
    
    def test_known_cve_match(self):
        """Find known CVE for Apache 2.4.41."""
        db = VulnDB()
        matches = db.check_version("http", "Apache httpd", "2.4.41")
        
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["id"], "CVE-2021-41773")
    
    def test_openssh_user_enum(self):
        """Find user enumeration CVE for OpenSSH 7.4."""
        db = VulnDB()
        matches = db.check_version("ssh", "OpenSSH", "7.4p1")
        
        self.assertTrue(any(m["id"] == "CVE-2018-15473" for m in matches))
    
    def test_no_match(self):
        """Return empty list for unknown version."""
        db = VulnDB()
        matches = db.check_version("http", "Apache httpd", "9.9.99")
        
        self.assertEqual(len(matches), 0)
    
    def test_zerologon(self):
        """Detect Zerologon in Samba/microsoft-ds."""
        db = VulnDB()
        matches = db.check_version("microsoft-ds", "Samba", "4.11.6")
        
        self.assertTrue(any(m["id"] == "CVE-2020-1472" for m in matches))


class TestReporter(unittest.TestCase):
    """Test report generation."""
    
    def test_generate_report(self):
        """Generate report from parsed data."""
        xml_path = Path(__file__).parent.parent / "data" / "sample_nmap_output.xml"
        xml_data = xml_path.read_text()
        
        parser = NmapParser(xml_data)
        hosts = parser.parse()
        
        reporter = ReportGenerator()
        report = reporter.generate(hosts, "2024-01-15T14:32:01", demo_mode=True)
        
        self.assertEqual(report["metadata"]["tool"], "nmap-vuln-scanner-wrapper")
        self.assertEqual(report["summary"]["total_hosts"], 3)
        self.assertTrue(report["metadata"]["demo_mode"])
    
    def test_markdown_output(self):
        """Generate markdown report."""
        xml_path = Path(__file__).parent.parent / "data" / "sample_nmap_output.xml"
        xml_data = xml_path.read_text()
        
        parser = NmapParser(xml_data)
        hosts = parser.parse()
        
        reporter = ReportGenerator()
        report = reporter.generate(hosts, "2024-01-15T14:32:01")
        
        md = reporter._to_markdown(report)
        self.assertIn("# Network Reconnaissance Report", md)
        self.assertIn("192.168.1.10", md)
    
    def test_save_json(self):
        """Save JSON report to temp file."""
        import tempfile
        import json
        
        xml_path = Path(__file__).parent.parent / "data" / "sample_nmap_output.xml"
        xml_data = xml_path.read_text()
        
        parser = NmapParser(xml_data)
        hosts = parser.parse()
        
        reporter = ReportGenerator()
        report = reporter.generate(hosts, "2024-01-15T14:32:01")
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            reporter.save(report, f.name, "json")
            
            # Read back and verify
            f.seek(0)
            loaded = json.loads(Path(f.name).read_text())
            self.assertEqual(loaded["summary"]["total_hosts"], 3)


class TestScannerConfig(unittest.TestCase):
    """Test configuration validation."""
    
    def test_valid_config(self):
        """Create valid config."""
        config = ScanConfig(
            targets=["192.168.1.1"],
            ports=["22", "80"],
            output_format="json"
        )
        self.assertEqual(config.targets, ["192.168.1.1"])
    
    def test_invalid_timing(self):
        """Reject invalid timing."""
        with self.assertRaises(ValueError):
            ScanConfig(
                targets=["192.168.1.1"],
                timing=6
            )
    
    def test_invalid_format(self):
        """Reject invalid format."""
        with self.assertRaises(ValueError):
            ScanConfig(
                targets=["192.168.1.1"],
                output_format="xml"
            )


class TestIntegration(unittest.TestCase):
    """Integration test with demo mode."""
    
    def test_demo_run(self):
        """Run full demo scan."""
        config = ScanConfig(
            targets=[],
            demo_mode=True,
            output_format="json"
        )
        
        scanner = NmapScanner(config)
        report = scanner.run()
        
        self.assertEqual(report["summary"]["total_hosts"], 3)
        # At least some ports should have CVE matches
        all_ports = [p for h in report["hosts"] for p in h["ports"]]
        ports_with_cves = [p for p in all_ports if p["cve_matches"]]
        self.assertGreater(len(ports_with_cves), 0)


if __name__ == "__main__":
    unittest.main()
