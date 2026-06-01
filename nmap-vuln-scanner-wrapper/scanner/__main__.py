"""
Network Recon & Vuln Scanner Wrapper
Entry point for CLI execution.
"""
import argparse
import logging
import sys
from pathlib import Path

from scanner.scanner import NmapScanner, ScanConfig


def setup_logging():
    """Configure logging for both file and console output."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Network Recon & Vuln Scanner Wrapper - AUTHORIZED USE ONLY",
        epilog="Example: python -m scanner --target 192.168.1.0/24 --demo"
    )
    
    parser.add_argument(
        "--target",
        nargs="+",
        help="Target IP(s) or CIDR range(s) to scan (e.g., 192.168.1.1 192.168.1.0/24)"
    )
    
    parser.add_argument(
        "--ports",
        default="22,80,443,445,3389",
        help="Comma-separated port list (default: 22,80,443,445,3389)"
    )
    
    parser.add_argument(
        "--output",
        default=None,
        help="Output file path (default: auto-generated)"
    )
    
    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="json",
        help="Output format (default: json)"
    )
    
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run in demo mode with synthetic data (no network scanning)"
    )
    
    parser.add_argument(
        "--aggressive",
        action="store_true",
        help="Enable aggressive scan (-A: OS detection, version, script, traceroute)"
    )
    
    parser.add_argument(
        "--timing",
        type=int,
        choices=[1, 2, 3, 4, 5],
        default=3,
        help="nmap timing template (1=slow/stealthy, 5=fast)"
    )
    
    return parser


def main():
    """Main entry point."""
    setup_logging()
    
    parser = create_parser()
    args = parser.parse_args()
    
    # Validate arguments
    if not args.demo and not args.target:
        parser.error("--target required (or use --demo for synthetic data)")
    
    # Build configuration
    ports = args.ports.split(",")
    
    config = ScanConfig(
        targets=args.target or [],
        ports=ports,
        output_format=args.format,
        output_path=args.output,
        demo_mode=args.demo,
        aggressive=args.aggressive,
        timing=args.timing
    )
    
    # Execute scan
    try:
        scanner = NmapScanner(config)
        report = scanner.run()
        
        # Exit with appropriate code
        high_risk = report["summary"]["high_risk"]
        if high_risk > 0:
            print(f"\n⚠️  {high_risk} HIGH risk findings detected. Review immediately.")
            sys.exit(1)  # Non-zero exit for CI/CD integration
        else:
            print("\n✅ Scan complete. No high-risk findings.")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
