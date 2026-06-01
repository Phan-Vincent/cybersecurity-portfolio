"""
test_parser.py
Unit tests for the auth log parser.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from parser import parse_line, parse_logfile
from datetime import datetime


class TestParser:
    def test_ssh_accepted(self):
        line = "Jun  1 14:23:01 web sshd[1234]: Accepted password for alice from 192.168.1.5 port 54322 ssh2"
        ev = parse_line(line, year=2024)
        assert ev is not None
        assert ev.event_type == "ssh_accepted"
        assert ev.username == "alice"
        assert ev.source_ip == "192.168.1.5"
        assert ev.hostname == "web"
        assert ev.pid == 1234
        assert ev.timestamp.month == 6
        assert ev.timestamp.day == 1

    def test_ssh_failed(self):
        line = "Jun  1 14:23:05 web sshd[1235]: Failed password for root from 10.0.0.99 port 55555 ssh2"
        ev = parse_line(line, year=2024)
        assert ev is not None
        assert ev.event_type == "ssh_failed"
        assert ev.username == "root"
        assert ev.source_ip == "10.0.0.99"

    def test_ssh_invalid_user(self):
        line = "Jun  1 14:20:05 web sshd[2224]: Invalid user admin from 203.0.113.45 port 49834"
        ev = parse_line(line, year=2024)
        assert ev is not None
        assert ev.event_type == "ssh_invalid_user"
        assert ev.username == "admin"
        assert ev.source_ip == "203.0.113.45"

    def test_sudo_cmd(self):
        line = "Jun  1 14:22:40 web sudo:   alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow"
        ev = parse_line(line, year=2024)
        assert ev is not None
        assert ev.event_type == "sudo_cmd"
        assert ev.username == "alice"
        assert "root" in ev.message

    def test_useradd(self):
        line = "Jun  2 03:10:15 web useradd[9999]: new user: name=backdoor, UID=1010, GID=1010, home=/home/backdoor, shell=/bin/bash"
        ev = parse_line(line, year=2024)
        assert ev is not None
        assert ev.event_type == "useradd"
        assert ev.username == "backdoor"
        assert ev.pid == 9999

    def test_unmatched_line(self):
        line = "Jun  1 14:00:00 web kernel: some unrelated kernel message"
        ev = parse_line(line, year=2024)
        assert ev is None

    def test_parse_logfile(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text(
            "Jun  1 08:15:22 web sshd[1111]: Accepted password for alice from 192.168.1.5 port 51234 ssh2\n"
            "Jun  1 14:20:01 web sshd[2222]: Failed password for root from 203.0.113.45 port 49832 ssh2\n"
        )
        events = list(parse_logfile(str(log), year=2024))
        assert len(events) == 2
        assert events[0].event_type == "ssh_accepted"
        assert events[1].event_type == "ssh_failed"
