# Linux Hardening Toolkit — CIS-Aligned ePHI Server Audit & Remediate

> A Bash-based hardening and audit toolkit for Linux servers in healthcare environments. Designed as a student portfolio project demonstrating practical CIS Benchmark application, HIPAA-aware security thinking, and production-quality scripting discipline.

**Author:** Vincent Phan  
**Context:** Entry-level cybersecurity student (CSUSB, BS InfoSys / Cybersecurity). Former CVS Pharmacy Technician (CPhT) with frontline PHI exposure.  
**Project Type:** Self-directed portfolio piece — built on a local VM lab, tested on Ubuntu 22.04 LTS.

---

## One-Line Pitch

Single-command audit or harden script that scores a Linux server against 30+ CIS controls, maps every finding to its benchmark ID, and generates a markdown report — built with healthcare ePHI in mind.

---

## What's Included

| Component | Purpose |
|-----------|---------|
| `harden.sh` | Entrypoint — audits by default; `--harden` remediates with backups and per-change confirmation |
| `audit.sh` | **Read-only** wrapper around `harden.sh --audit` — refuses any hardening flag |
| `lib/common.sh` | Check engine, scoring, backups, markdown report generation |
| `lib/{ssh,firewall,auth,auditd,filesystem,updates}.sh` | One module per control domain (30 scored controls) |
| `lib/cis-mapping.sh` / `cis-mapping.csv` | CIS Benchmark ID → control description reference |
| `configs/` | Hardening-ready config templates (sshd, login.defs, pwquality, auditd, audit rules, APT) |
| `samples/audit-report-example.txt` | Illustrative audit output (synthetic host) |
| `tests/validate.sh` | Sandboxed test suite — syntax, shellcheck, audit/harden behaviour, template consistency |

---

## Quick Start

```bash
# Clone / copy the toolkit
cd linux-hardening-toolkit

# 1. Audit only (safe, non-destructive)
sudo ./audit.sh

# 2. Hardening (interactive: backs up each config and asks before every change)
sudo ./harden.sh --harden

# 3. Hardening with auto-confirm (lab VM / CI use)
sudo ./harden.sh --harden --auto

# 4. Also disable SSH password auth — only once key-based login works for every admin
sudo ./harden.sh --harden --key-auth

# Point the ePHI checks at the real data directory (default: /var/ephisynth)
sudo ./audit.sh --ephi-dir /srv/ehr-data

# Run the test suite (no root needed; never touches the host)
bash tests/validate.sh
```

Both scripts write a scored markdown report to `./reports/`, echo a summary to stdout, and exit non-zero when any control fails — so a cron job or CI step can alert on drift.

---

## Threat Model & Security Rationale

**Scenario:** A small healthcare clinic runs a self-managed Ubuntu server storing appointment schedules, billing records, and limited ePHI. They have no dedicated security staff. An entry-level IT hire (me, in this framing) needs to assess and improve the server's security posture against a known framework.

### Identified Threats

| Threat | Likelihood | Impact | Control Domain |
|--------|------------|--------|----------------|
| Brute-force SSH access | High | Critical | SSH hardening, firewall |
| Weak / default passwords | High | Critical | Password policy, PAM |
| Privilege escalation via SUID binaries | Medium | High | File permissions, auditd |
| Unpatched OS / package vulnerabilities | High | High | Unattended upgrades |
| Insider abuse / non-repudiation gaps | Medium | Medium | Audit logging, session tracking |
| Misconfigured file access on ePHI dirs | Medium | Critical | Permission scanning, ACL validation |

### Why CIS Benchmarks?

CIS Benchmarks are prescriptive, versioned, and auditable. Mapping every control to a CIS ID makes findings defensible in a compliance conversation and gives a hiring manager confidence that I understand *structured* security assessment, not just ad-hoc tweaks.

---

## Control Matrix (CIS Ubuntu Linux 22.04 Benchmark)

Generated from the check definitions in `lib/*.sh` — this is exactly what runs.

| ID | Control | Reference | Harden | Audit |
|----|---------|-----------|--------|-------|
| SSH-01 | SSH Protocol is 2 | CIS 5.2.1 | ✅ | ✅ |
| SSH-02 | SSH LogLevel is VERBOSE | CIS 5.2.2 | ✅ | ✅ |
| SSH-03 | MaxAuthTries <= 4 | CIS 5.2.3 | ✅ | ✅ |
| SSH-04 | PermitRootLogin is disabled | CIS 5.2.4 | ✅ | ✅ |
| SSH-05 | PasswordAuthentication disabled | CIS 5.2.5 | ✅ with `--key-auth` | ✅ |
| SSH-06 | ClientAliveInterval set to 300 | CIS 5.2.12 | ✅ | ✅ |
| FW-01 | UFW is installed | CIS 3.5.1.1 | ✅ | ✅ |
| FW-02 | UFW service is enabled | CIS 3.5.1.2 | ✅ | ✅ |
| FW-03 | Default deny policy | CIS 3.5.1.3 | ✅ | ✅ |
| FW-04 | Loopback traffic configured | CIS 3.5.1.4 | ✅ | ✅ |
| FW-05 | SSH (port 22) restricted/allowed | ePHI admin path | ✅ | ✅ |
| AUTH-01 | pam_pwquality enforces strong passwords | CIS 5.3.1 | ✅ | ✅ |
| AUTH-02 | pam_faillock locks accounts after failed attempts | CIS 5.3.2 | ✅ | ✅ |
| AUTH-03 | Password max age <= 365 days | CIS 5.4.1.1 | ✅ | ✅ |
| AUTH-04 | Password min age >= 1 day | CIS 5.4.1.2 | ✅ | ✅ |
| AUTH-05 | Password warning >= 7 days | CIS 5.4.1.3 | ✅ | ✅ |
| AUDIT-01 | auditd is installed | CIS 4.1.1.1 | ✅ | ✅ |
| AUDIT-02 | auditd service is enabled | CIS 4.1.1.2 | ✅ | ✅ |
| AUDIT-03 | Max audit log file size configured | CIS 4.1.1.3 | ✅ | ✅ |
| AUDIT-04 | Audit log retention = keep_logs | CIS 4.1.1.4 | ✅ | ✅ |
| AUDIT-05 | sudoers changes are audited | CIS 4.1.3 | ✅ | ✅ |
| AUDIT-06 | ePHI directory access auditing | HIPAA 164.312(b) | ✅ | ✅ |
| FS-01 | SUID binary count is reasonable | CIS 6.1.1 | — | ✅ |
| FS-02 | No world-writable files found | CIS 6.1.2 | report only | ✅ |
| FS-03 | Sticky bit set on all world-writable directories | CIS 6.1.3 | ✅ | ✅ |
| FS-04 | ePHI directory permissions are restricted | HIPAA 164.312(a)(1) | ✅ | ✅ |
| UPD-01 | Unattended-upgrades installed | CIS 1.8 | ✅ | ✅ |
| UPD-02 | Unattended-upgrades enabled in APT | CIS 1.8 | ✅ | ✅ |
| UPD-03 | Security origin enabled in unattended-upgrades | CIS 1.8 | ✅ | ✅ |
| UPD-04 | Auto-reboot enabled for security updates | CIS 1.9 | ✅ | ✅ |
| UPD-05 | Unattended-upgrades mail notification configured | ePHI best practice | ✅ | ✅ |

> **Note on SSH password auth:** The benchmark recommends key-based authentication. This toolkit *checks* for password auth and flags it. In a hardening run with `--key-auth`, it will disable password auth. Without the flag, it warns but does not change, to prevent accidental lockout. Before any sshd restart the config is validated with `sshd -t`; a rejected config is never loaded.

---

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│   harden.sh     │     │    audit.sh     │
│  (remediate)    │     │  (read-only)    │
└────────┬────────┘     └────────┬────────┘
         │                       │
         └───────────┬───────────┘
                     │
              ┌──────┴──────┐
              │ lib/common.sh│
              │  (scoring,   │
              │   backup,    │
              │   report)    │
              └──────┬──────┘
                     │
              ┌──────┴──────┐
              │cis-mapping.sh│
              │ (control IDs)│
              └─────────────┘
```

### Scoring Engine

Every control is scored PASS, FAIL, or FIXED (failed, remediated, and re-verified in the same run); informational findings are WARN and unscored. The final report prints:
- **Score:** `X / Y` passed
- **Risk:** Low / Medium / High / Critical based on failed controls
- **Compliance %:** Against the 30 scored controls
- **Remediation plan:** Ordered by risk

---

## Skills Demonstrated

1. **Structured security assessment** — CIS Benchmark mapping, not ad-hoc tweaks
2. **Bash at scale** — functions, error handling, idempotency, backup/rollback awareness
3. **Healthcare context awareness** — HIPAA 164.312(b) audit logging, ePHI directory monitoring, least-privilege
4. **Operational safety** — audit-only mode, config backups, dry-run flags, interactive confirmation
5. **Reporting** — Markdown generation, scoring, risk-weighted prioritization

---

## Honest Scope Notes

- **Tested on:** Ubuntu 22.04 LTS VM (VirtualBox, local lab). Not tested on RHEL, Fedora, or bare metal.
- **CIS Version:** Ubuntu Linux 22.04 LTS Benchmark v2.0.1. Some controls are simplified for brevity; a full enterprise audit would use CIS-CAT or OpenSCAP.
- **SSH password auth:** The hardening script requires `--key-auth` to disable password auth. Without it, it warns only. This prevents accidental lockout in lab environments.
- **ePHI paths:** Synthetic. The script uses `/var/ephisynth/` as a placeholder ePHI directory; pass `--ephi-dir` to point it at a real one.
- **Not a replacement for:** CIS-CAT, Lynis, OpenSCAP, or a professional audit. This is a *learning* and *demonstration* toolkit.
- **What I actually built:** All Bash, all by hand, with manual testing on a local VM. No copy-paste from existing hardening scripts without understanding.

---

## Future Improvements (Acknowledged Gaps)

- SELinux/AppArmor profile checks
- Full AIDE or Tripwire integrity monitoring
- Automated OpenSCAP integration for formal compliance
- Docker/container-specific CIS controls
- Multi-distro support (RHEL, Debian)

---

## License

MIT — Use freely, attribute if forked.
