"""
detections.py
Detection engine — applies rules to a stream of AuthEvents and produces alerts.

Detections implemented:
  1. Brute-force SSH attacks (multiple failed attempts within a time window)
  2. Impossible travel (same user, different geos, faster than physically possible)
  3. Privilege escalation (sudo to root, especially for non-admin users)
  4. Account creation anomaly (new user added outside business hours)
  5. Suspicious SSH success after repeated failures (potential credential stuffing success)
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime, timedelta

from parser import AuthEvent


@dataclass(frozen=True)
class Alert:
    alert_id: str
    severity: str           # critical, high, medium, low
    detection_type: str     # brute_force, impossible_travel, privilege_escalation, etc.
    title: str
    description: str
    mitre_technique: str    # e.g., T1110
    mitre_tactic: str       # e.g., Credential Access
    source_events: List[AuthEvent]
    source_ips: List[str]
    usernames: List[str]
    timestamp: datetime
    confidence: str         # high, medium, low


class DetectionEngine:
    def __init__(self, rules: Dict):
        self.rules = rules
        # Buffers for time-windowed detections
        self._failed_attempts: Dict[str, List[AuthEvent]] = defaultdict(list)
        self._successful_logins: Dict[str, List[AuthEvent]] = defaultdict(list)
        self._sudo_sessions: List[AuthEvent] = []
        self._useradd_events: List[AuthEvent] = []
        self._all_events: List[AuthEvent] = []

    def ingest(self, event: AuthEvent):
        """Feed a single event into the detection engine."""
        self._all_events.append(event)

        if event.event_type == "ssh_failed":
            key = event.source_ip or "unknown"
            self._failed_attempts[key].append(event)
        elif event.event_type == "ssh_accepted":
            key = event.username or event.source_ip or "unknown"
            self._successful_logins[key].append(event)
        elif event.event_type.startswith("sudo"):
            self._sudo_sessions.append(event)
        elif event.event_type == "useradd":
            self._useradd_events.append(event)

    def run_detections(self) -> List[Alert]:
        """Execute all detection rules and return alerts."""
        alerts = []
        alerts.extend(self._detect_brute_force())
        alerts.extend(self._detect_credential_stuffing_success())
        alerts.extend(self._detect_impossible_travel())
        alerts.extend(self._detect_privilege_escalation())
        alerts.extend(self._detect_off_hours_useradd())
        return alerts

    # ── Detection 1: Brute-force SSH ───────────────────────────────────────

    def _detect_brute_force(self) -> List[Alert]:
        alerts = []
        threshold = self.rules.get("brute_force", {}).get("failed_attempt_threshold", 5)
        window_minutes = self.rules.get("brute_force", {}).get("time_window_minutes", 10)
        window = timedelta(minutes=window_minutes)

        for ip, events in self._failed_attempts.items():
            events = sorted(events, key=lambda e: e.timestamp)
            for i in range(len(events)):
                window_events = [events[i]]
                for j in range(i + 1, len(events)):
                    if events[j].timestamp - events[i].timestamp <= window:
                        window_events.append(events[j])
                    else:
                        break
                if len(window_events) >= threshold:
                    usernames = list(set(e.username for e in window_events if e.username))
                    alert = Alert(
                        alert_id=f"BF-{ip}-{events[i].timestamp.strftime('%Y%m%d%H%M%S')}",
                        severity="high",
                        detection_type="brute_force",
                        title=f"Brute-force SSH attack from {ip}",
                        description=(
                            f"{len(window_events)} failed SSH login attempts from {ip} "
                            f"within {window_minutes} minutes targeting user(s): {', '.join(usernames)}. "
                            f"This is consistent with a password-spray or brute-force attack."
                        ),
                        mitre_technique="T1110",
                        mitre_tactic="Credential Access",
                        source_events=window_events,
                        source_ips=[ip],
                        usernames=usernames,
                        timestamp=window_events[-1].timestamp,
                        confidence="high",
                    )
                    alerts.append(alert)
                    break  # One alert per IP per window start
        return alerts

    # ── Detection 2: Credential Stuffing Success ───────────────────────────

    def _detect_credential_stuffing_success(self) -> List[Alert]:
        """
        Flag a successful SSH login that follows multiple failed attempts for the
        same username/IP pair — suggests the attacker found valid credentials.
        """
        alerts = []
        threshold = self.rules.get("brute_force", {}).get("failed_attempt_threshold", 5)

        for success in self._successful_logins.values():
            for s in success:
                if s.event_type != "ssh_accepted":
                    continue
                # Count failures for same IP before this success
                ip = s.source_ip
                if not ip:
                    continue
                failures = [
                    f for f in self._failed_attempts.get(ip, [])
                    if f.timestamp < s.timestamp
                ]
                if len(failures) >= threshold:
                    usernames = list(set(f.username for f in failures if f.username))
                    alert = Alert(
                        alert_id=f"CS-{ip}-{s.timestamp.strftime('%Y%m%d%H%M%S')}",
                        severity="critical",
                        detection_type="credential_stuffing_success",
                        title=f"Successful login after brute-force from {ip}",
                        description=(
                            f"User '{s.username}' successfully authenticated from {ip} "
                            f"after {len(failures)} failed attempts. This pattern is highly "
                            f"suspicious for credential stuffing or brute-force success. "
                            f"Recommend immediate account review and IP block."
                        ),
                        mitre_technique="T1110.001",
                        mitre_tactic="Credential Access",
                        source_events=failures[-5:] + [s],
                        source_ips=[ip],
                        usernames=[s.username] if s.username else usernames,
                        timestamp=s.timestamp,
                        confidence="high",
                    )
                    alerts.append(alert)
        return alerts

    # ── Detection 3: Impossible Travel ─────────────────────────────────────

    def _detect_impossible_travel(self) -> List[Alert]:
        """
        Detect logins for the same user from geolocations that are impossible
        to travel between within the observed time delta.
        Uses a synthetic geo lookup table for the portfolio project.
        """
        alerts = []
        min_speed_kmh = self.rules.get("impossible_travel", {}).get("min_speed_kmh", 800)
        geo_table = _GEO_LOOKUP_TABLE  # Static synthetic data

        # Group accepted logins by username
        by_user: Dict[str, List[AuthEvent]] = defaultdict(list)
        for ev in self._all_events:
            if ev.event_type == "ssh_accepted" and ev.username and ev.source_ip:
                by_user[ev.username].append(ev)

        for user, events in by_user.items():
            events = sorted(events, key=lambda e: e.timestamp)
            for i in range(len(events) - 1):
                e1, e2 = events[i], events[i + 1]
                loc1 = geo_table.get(e1.source_ip)
                loc2 = geo_table.get(e2.source_ip)
                if not loc1 or not loc2 or loc1 == loc2:
                    continue
                # Calculate distance
                dist_km = _haversine(loc1["lat"], loc1["lon"], loc2["lat"], loc2["lon"])
                time_h = (e2.timestamp - e1.timestamp).total_seconds() / 3600.0
                if time_h <= 0:
                    continue
                speed = dist_km / time_h
                if speed > min_speed_kmh:
                    alert = Alert(
                        alert_id=f"IT-{user}-{e2.timestamp.strftime('%Y%m%d%H%M%S')}",
                        severity="medium",
                        detection_type="impossible_travel",
                        title=f"Impossible travel detected for user '{user}'",
                        description=(
                            f"User '{user}' logged in from {loc1['city']} ({e1.source_ip}) "
                            f"then {loc2['city']} ({e2.source_ip}) within {time_h:.1f} hours. "
                            f"Required speed: {speed:.0f} km/h (threshold: {min_speed_kmh}). "
                            f"Possible account compromise or VPN jump."
                        ),
                        mitre_technique="T1078",
                        mitre_tactic="Initial Access",
                        source_events=[e1, e2],
                        source_ips=[e1.source_ip, e2.source_ip],
                        usernames=[user],
                        timestamp=e2.timestamp,
                        confidence="medium",
                    )
                    alerts.append(alert)
        return alerts

    # ── Detection 4: Privilege Escalation ──────────────────────────────────

    def _detect_privilege_escalation(self) -> List[Alert]:
        alerts = []
        watch_users = self.rules.get("privilege_escalation", {}).get("non_admin_users", [])
        watch_commands = self.rules.get("privilege_escalation", {}).get("suspicious_commands", [])

        for ev in self._sudo_sessions:
            if ev.event_type != "sudo_cmd":
                continue
            # Parse USER= and COMMAND= from raw message
            msg = ev.message
            if "USER=root" in msg:
                user = ev.username
                is_watched = not watch_users or (user in watch_users)
                cmd = ""
                if "COMMAND=" in msg:
                    cmd = msg.split("COMMAND=", 1)[1].strip()
                cmd_suspicious = any(sc in cmd for sc in watch_commands) if watch_commands else False

                if not is_watched:
                    severity = "low"
                elif cmd_suspicious:
                    severity = "high"
                else:
                    severity = "medium"

                title = f"Sudo escalation to root by '{user}'"
                desc = (
                    f"User '{user}' executed sudo to root on {ev.hostname}. "
                    f"Command: '{cmd}'. This is a legitimate administrative action for admins, "
                    f"but should be reviewed if the user is not in the admin roster."
                )
                if cmd_suspicious:
                    desc += f" The command '{cmd}' matches the suspicious command list."

                alert = Alert(
                    alert_id=f"PE-{ev.hostname}-{ev.timestamp.strftime('%Y%m%d%H%M%S')}",
                    severity=severity,
                    detection_type="privilege_escalation",
                    title=title,
                    description=desc,
                    mitre_technique="T1548.003",
                    mitre_tactic="Privilege Escalation",
                    source_events=[ev],
                    source_ips=[ev.source_ip] if ev.source_ip else [],
                    usernames=[user] if user else [],
                    timestamp=ev.timestamp,
                    confidence="low" if not is_watched else ("high" if cmd_suspicious else "medium"),
                )
                alerts.append(alert)
        return alerts

    # ── Detection 5: Off-Hours Account Creation ────────────────────────────

    def _detect_off_hours_useradd(self) -> List[Alert]:
        alerts = []
        business_start = self.rules.get("off_hours", {}).get("business_hours_start", 8)
        business_end = self.rules.get("off_hours", {}).get("business_hours_end", 18)

        for ev in self._useradd_events:
            hour = ev.timestamp.hour
            if hour < business_start or hour >= business_end:
                alert = Alert(
                    alert_id=f"UA-{ev.hostname}-{ev.timestamp.strftime('%Y%m%d%H%M%S')}",
                    severity="low",
                    detection_type="off_hours_useradd",
                    title=f"New user '{ev.username}' created outside business hours",
                    description=(
                        f"User '{ev.username}' was created at {ev.timestamp.strftime('%H:%M')} "
                        f"on {ev.timestamp.strftime('%Y-%m-%d')} (outside {business_start}:00–{business_end}:00). "
                        f"Low-severity anomaly — correlate with change tickets."
                    ),
                    mitre_technique="T1136.001",
                    mitre_tactic="Persistence",
                    source_events=[ev],
                    source_ips=[ev.source_ip] if ev.source_ip else [],
                    usernames=[ev.username] if ev.username else [],
                    timestamp=ev.timestamp,
                    confidence="low",
                )
                alerts.append(alert)
        return alerts


# ── Synthetic Geo Lookup Table (for portfolio demo) ─────────────────────────
# In production, this would be MaxMind GeoIP2 or similar.
_GEO_LOOKUP_TABLE = {
    "203.0.113.45": {"city": "Beijing", "country": "CN", "lat": 39.9042, "lon": 116.4074},
    "198.51.100.22": {"city": "Los Angeles", "country": "US", "lat": 34.0522, "lon": -118.2437},
    "192.168.1.5": {"city": "Rancho Cucamonga", "country": "US", "lat": 34.1064, "lon": -117.5931},
    "10.0.0.99": {"city": "Internal", "country": "US", "lat": 34.0, "lon": -117.5},
    "185.220.101.7": {"city": "Amsterdam", "country": "NL", "lat": 52.3676, "lon": 4.9041},
    "45.142.214.58": {"city": "Moscow", "country": "RU", "lat": 55.7558, "lon": 37.6173},
}


def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return great-circle distance in km between two lat/lon points."""
    R = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c
