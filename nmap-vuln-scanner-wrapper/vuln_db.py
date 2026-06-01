#!/usr/bin/env python3
"""
vuln_db.py — Curated vulnerability database and risk scoring engine.

Maps common service names and version patterns to known CVE-prone profiles,
severity scores, and remediation guidance. Uses a static YAML file (no
live API calls) so the tool works offline and avoids API key exposure.

Scoring philosophy (aligned with SOC triage workflows):
  - 90-100 : Critical — known RCE, default creds, no-auth required
  - 70-89  : High — known vuln with PoC, weak encryption, info leak
  - 40-69  : Medium — outdated but no known exploit, risky config
  - 0-39   : Low — exposed service, up-to-date version, standard config

Author: Vincent Phan
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class VulnDatabase:
    """Load and query a curated service-to-risk mapping database."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        if not self.db_path.exists():
            raise FileNotFoundError(f"Vulnerability database not found: {db_path}")
        self._db = self._load_db()

    def _load_db(self) -> Dict[str, Any]:
        with open(self.db_path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)

    def lookup_service(self, service_name: Optional[str]) -> Optional[Dict[str, Any]]:
        """Return the risk profile for a given service name (case-insensitive)."""
        if not service_name:
            return None
        key = service_name.lower()
        return self._db.get("services", {}).get(key)

    def score_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich each finding with a risk_score, severity label, and remediation.

        Scoring logic:
          1. Base score from service risk profile (0-100)
          2. +20 if version is known-vulnerable and matches a pattern
          3. +10 if banner reveals excessive info (full version string)
          4. -10 if host OS is identified (slightly reduces uncertainty)
        """
        scored = []
        for finding in findings:
            service_name = finding.get("service_name")
            profile = self.lookup_service(service_name)

            base_score = 0
            severity = "info"
            cves: List[str] = []
            remediation = "No specific risk profile. Verify service necessity and apply latest patches."

            if profile:
                base_score = profile.get("base_risk", 0)
                severity = profile.get("default_severity", "info")
                cves = profile.get("known_cves", [])
                remediation = profile.get("remediation", remediation)

                # Version pattern match bonus
                version = finding.get("service_version") or ""
                for vuln in profile.get("vulnerable_versions", []):
                    if vuln.get("pattern") and vuln["pattern"] in version:
                        base_score += vuln.get("score_boost", 20)
                        cves.extend(vuln.get("cves", []))
                        remediation = vuln.get("remediation", remediation)

            # Banner leakage penalty (information disclosure)
            banner = finding.get("banner") or ""
            if banner and len(banner) > 10:
                base_score += 10

            # OS identification slightly reduces uncertainty (small bonus for accuracy)
            if finding.get("host_os"):
                base_score -= 5

            # Clamp
            risk_score = max(0, min(100, base_score))

            # Severity label recalculation
            if risk_score >= 90:
                severity = "critical"
            elif risk_score >= 70:
                severity = "high"
            elif risk_score >= 40:
                severity = "medium"
            else:
                severity = "low"

            scored.append({
                **finding,
                "risk_score": risk_score,
                "severity": severity,
                "cves": list(set(cves)),  # dedupe
                "remediation": remediation,
            })

        # Sort by risk descending
        scored.sort(key=lambda x: x["risk_score"], reverse=True)
        return scored
