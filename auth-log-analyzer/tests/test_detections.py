"""
test_detections.py
End-to-end and unit tests for the detection engine.
"""

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from parser import parse_line, parse_logfile
from detections import DetectionEngine


def load_rules():
    with open(ROOT / "data" / "ruleset.yaml") as f:
        return yaml.safe_load(f)


def run(lines, rules=None):
    engine = DetectionEngine(rules if rules is not None else load_rules())
    for line in lines:
        ev = parse_line(line, year=2026)
        if ev:
            engine.ingest(ev)
    return engine.run_detections()


def by_type(alerts, detection_type):
    return [a for a in alerts if a.detection_type == detection_type]


class TestSampleLog:
    """The shipped sample log is designed to trigger every detection at least once."""

    def setup_method(self):
        engine = DetectionEngine(load_rules())
        for ev in parse_logfile(str(ROOT / "data" / "sample-auth.log"), year=2026):
            engine.ingest(ev)
        self.alerts = engine.run_detections()

    def test_every_detection_fires(self):
        types = {a.detection_type for a in self.alerts}
        assert types == {
            "brute_force",
            "credential_stuffing_success",
            "impossible_travel",
            "privilege_escalation",
            "off_hours_useradd",
        }

    def test_sample_uses_documentation_or_private_ips(self):
        for a in self.alerts:
            for ip in a.source_ips:
                assert ip.startswith(("203.0.113.", "198.51.100.", "192.0.2.", "192.168.", "10."))

    def test_alerts_carry_mitre_ids(self):
        assert all(a.mitre_technique.startswith("T") for a in self.alerts)


class TestBruteForce:
    def _failures(self, n, start_sec=0, step=20, ip="203.0.113.45"):
        lines = []
        for i in range(n):
            s = start_sec + i * step
            lines.append(
                f"Jun  3 09:{s // 60:02d}:{s % 60:02d} web sshd[{100 + i}]: "
                f"Failed password for root from {ip} port {40000 + i} ssh2"
            )
        return lines

    def test_threshold_reached(self):
        alerts = by_type(run(self._failures(5)), "brute_force")
        assert len(alerts) == 1
        assert alerts[0].severity == "high"
        assert alerts[0].source_ips == ["203.0.113.45"]

    def test_below_threshold(self):
        assert by_type(run(self._failures(4)), "brute_force") == []

    def test_failures_outside_window_do_not_alert(self):
        # 5 failures spaced 3 minutes apart span 12 minutes (> 10-minute window)
        assert by_type(run(self._failures(5, step=180)), "brute_force") == []


class TestCredentialStuffingSuccess:
    def test_success_after_failures_is_critical(self):
        lines = TestBruteForce()._failures(5) + [
            "Jun  3 09:05:00 web sshd[200]: Accepted password for alice from 203.0.113.45 port 41000 ssh2"
        ]
        alerts = by_type(run(lines), "credential_stuffing_success")
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"
        assert alerts[0].usernames == ["alice"]

    def test_success_without_failures_is_quiet(self):
        lines = ["Jun  3 09:05:00 web sshd[200]: Accepted password for alice from 203.0.113.45 port 41000 ssh2"]
        assert by_type(run(lines), "credential_stuffing_success") == []


class TestImpossibleTravel:
    def test_la_to_beijing_in_minutes(self):
        lines = [
            "Jun  3 09:00:00 web sshd[1]: Accepted password for alice from 198.51.100.22 port 1 ssh2",
            "Jun  3 09:30:00 web sshd[2]: Accepted password for alice from 203.0.113.45 port 2 ssh2",
        ]
        alerts = by_type(run(lines), "impossible_travel")
        assert len(alerts) == 1
        assert alerts[0].mitre_technique == "T1078"

    def test_plausible_travel_is_quiet(self):
        # LA -> Beijing (~10,000 km) over 20 hours is ~500 km/h, under the 800 km/h threshold
        lines = [
            "Jun  3 01:00:00 web sshd[1]: Accepted password for alice from 198.51.100.22 port 1 ssh2",
            "Jun  3 21:00:00 web sshd[2]: Accepted password for alice from 203.0.113.45 port 2 ssh2",
        ]
        assert by_type(run(lines), "impossible_travel") == []

    def test_unknown_ip_is_skipped(self):
        lines = [
            "Jun  3 09:00:00 web sshd[1]: Accepted password for alice from 198.51.100.22 port 1 ssh2",
            "Jun  3 09:01:00 web sshd[2]: Accepted password for alice from 192.0.2.99 port 2 ssh2",
        ]
        assert by_type(run(lines), "impossible_travel") == []


class TestPrivilegeEscalation:
    def _sudo(self, user, cmd):
        return f"Jun  3 10:00:00 web sudo:    {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"

    def test_watched_user_suspicious_command_is_high(self):
        alerts = by_type(run([self._sudo("alice", "/bin/cat /etc/shadow")]), "privilege_escalation")
        assert [a.severity for a in alerts] == ["high"]

    def test_watched_user_benign_command_is_medium(self):
        alerts = by_type(run([self._sudo("bob", "/usr/bin/systemctl restart nginx")]), "privilege_escalation")
        assert [a.severity for a in alerts] == ["medium"]

    def test_admin_user_is_low(self):
        alerts = by_type(run([self._sudo("vphan", "/usr/bin/apt update")]), "privilege_escalation")
        assert [a.severity for a in alerts] == ["low"]

    def test_sudo_to_non_root_is_ignored(self):
        line = "Jun  3 10:00:00 web sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=postgres ; COMMAND=/usr/bin/psql"
        assert by_type(run([line]), "privilege_escalation") == []


class TestOffHoursUseradd:
    def _useradd(self, hhmm, name="svc-test"):
        return f"Jun  3 {hhmm}:00 web useradd[9]: new user: name={name}, UID=1010, GID=1010, home=/home/{name}"

    def test_overnight_creation_alerts(self):
        alerts = by_type(run([self._useradd("02:13")]), "off_hours_useradd")
        assert len(alerts) == 1
        assert alerts[0].mitre_technique == "T1136.001"

    def test_business_hours_creation_is_quiet(self):
        assert by_type(run([self._useradd("10:05")]), "off_hours_useradd") == []

    def test_end_of_business_hour_is_off_hours(self):
        # business_hours_end is exclusive: 18:00 counts as off-hours
        assert len(by_type(run([self._useradd("18:00")]), "off_hours_useradd")) == 1
