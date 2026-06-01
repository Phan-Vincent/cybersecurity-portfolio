"""
parser.py
Auth log parser — normalizes raw syslog-style auth logs into structured events.

Supports:
  - SSH authentication events (Accepted, Failed, Invalid user)
  - Sudo privilege escalation
  - PAM session open/close
  - Useradd/passwd changes
"""

import re
from datetime import datetime
from typing import Iterator, Optional
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    hostname: str
    process: str
    pid: Optional[int]
    event_type: str          # e.g., ssh_accepted, ssh_failed, sudo_cmd, etc.
    username: Optional[str]
    source_ip: Optional[str]
    message: str
    raw_line: str


# Regex patterns for common auth log lines
# Designed to be readable and maintainable — not hyper-optimized
_PATTERNS = {
    # Jun  1 14:23:01 web sshd[1234]: Accepted password for alice from 192.168.1.5 port 54322 ssh2
    "ssh_accepted": re.compile(
        r"^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"sshd\[(?P<pid>\d+)\]:\s+"
        r"Accepted\s+(?P<method>\w+)\s+for\s+(?P<user>\S+)\s+"
        r"from\s+(?P<ip>[\d\.]+)"
    ),
    # Jun  1 14:23:05 web sshd[1235]: Failed password for root from 10.0.0.99 port 55555 ssh2
    "ssh_failed": re.compile(
        r"^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"sshd\[(?P<pid>\d+)\]:\s+"
        r"Failed\s+password\s+for\s+(invalid\s+user\s+)?(?P<user>\S+)\s+"
        r"from\s+(?P<ip>[\d\.]+)"
    ),
    # Jun  1 14:25:10 web sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow
    "sudo_cmd": re.compile(
        r"^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"sudo:\s+(?P<user>\S+)\s+:.*USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<cmd>.+)$"
    ),
    # Jun  1 14:25:12 web sudo: pam_unix(sudo:session): session opened for user root by (uid=0)
    "sudo_session_open": re.compile(
        r"^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"sudo(?:\[\d+\])?:\s+"
        r"pam_unix\(sudo:session\):\s+session\s+opened\s+for\s+user\s+(?P<target_user>\S+)"
    ),
    # Jun  1 14:30:00 web sshd[1236]: Invalid user admin from 192.168.1.10 port 12345
    "ssh_invalid_user": re.compile(
        r"^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"sshd\[(?P<pid>\d+)\]:\s+"
        r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d\.]+)"
    ),
    # Jun  1 14:35:00 web useradd[2345]: new user: name=bob, UID=1001, GID=1001, home=/home/bob
    "useradd": re.compile(
        r"^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"useradd\[(?P<pid>\d+)\]:\s+"
        r"new\s+user:\s+name=(?P<user>[^,\s]+)"
    ),
}


def _parse_syslog_timestamp(ts_str: str, year: int = None) -> datetime:
    """Parse syslog timestamp (no year). Assume current year unless overridden."""
    if year is None:
        year = datetime.now().year
    # Handle single-digit day padding: 'Jun  1 14:23:01'
    try:
        return datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        # Fallback: try without extra space normalization
        return datetime.strptime(f"{year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: int = None) -> Optional[AuthEvent]:
    """Parse a single auth log line into an AuthEvent, or None if unmatched."""
    line = line.strip()
    if not line:
        return None

    for event_type, pattern in _PATTERNS.items():
        match = pattern.match(line)
        if not match:
            continue

        d = match.groupdict()
        ts = _parse_syslog_timestamp(d["ts"], year=year)
        pid = int(d.get("pid")) if d.get("pid") else None

        # Extract username based on event type
        username = d.get("user") or d.get("target_user")

        # Extract IP if present
        source_ip = d.get("ip")

        return AuthEvent(
            timestamp=ts,
            hostname=d["host"],
            process="sshd" if event_type.startswith("ssh") else "sudo" if event_type.startswith("sudo") else "useradd",
            pid=pid,
            event_type=event_type,
            username=username,
            source_ip=source_ip,
            message=line.split(": ", 1)[-1] if ": " in line else line,
            raw_line=line,
        )

    return None


def parse_logfile(filepath: str, year: int = None) -> Iterator[AuthEvent]:
    """Yield parsed AuthEvents from a log file."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line, year=year)
            if event:
                yield event
