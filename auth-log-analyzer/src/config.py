"""
config.py
Configuration defaults and validation for the detection engine.
"""

from typing import Dict, Any

DEFAULT_RULES: Dict[str, Any] = {
    "brute_force": {
        "failed_attempt_threshold": 5,
        "time_window_minutes": 10,
    },
    "impossible_travel": {
        "min_speed_kmh": 800,  # ~500 mph — commercial jet speed
    },
    "privilege_escalation": {
        "non_admin_users": ["alice", "bob", "mallory"],  # Users not expected to sudo to root
        "suspicious_commands": ["/bin/cat /etc/shadow", "chmod u+s", "nc -e /bin/sh", "nmap"],
    },
    "off_hours": {
        "business_hours_start": 8,
        "business_hours_end": 18,
    },
}


def validate_rules(rules: Dict[str, Any]) -> Dict[str, Any]:
    """Merge user-provided rules over defaults and validate."""
    merged = DEFAULT_RULES.copy()
    for key, val in rules.items():
        if key in merged and isinstance(val, dict):
            merged[key].update(val)
        else:
            merged[key] = val
    return merged
