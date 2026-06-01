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
| `harden.sh` | Interactive hardening script — checks, remediates, backs up |
| `audit.sh` | **Idempotent, read-only** audit — safe to run anywhere, anytime |
| `lib/common.sh` | Shared functions, scoring engine, reporting helpers |
| `lib/cis-mapping.sh` | CIS Benchmark ID → control description mapping |
| `configs/` | Hardening-ready config templates (sshd, auditd, pwquality) |
| `reports/sample-audit-report.md` | Example output from a scored run |
| `tests/validate.sh` | Quick smoke-test to verify script integrity |

---

## Quick Start

```bash
# Clone / copy the toolkit
cd linux-hardening-toolkit

# 1. Audit only (safe, non-destructive)
sudo ./audit.sh

# 2. Full hardening (interactive, backs up configs)
sudo ./harden.sh

# 3. Hardening with auto-confirm (CI / lab use)
sudo ./harden.sh --auto
```

Both scripts output a scored markdown report to `./reports/` and echo a summary to stdout.

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

## Control Matrix (CIS Ubuntu Linux Benchmark v2.0.1)

| Toolkit Check | CIS ID | Description | Harden | Audit |
|---------------|--------|-------------|--------|-------|
| **SSH** |
| SSH root login disabled | 5.2.8 | Ensure SSH root login is disabled | ✅ | ✅ |
| SSH password auth disabled | 5.2.12 | Ensure SSH password authentication is disabled (key-only preferred) | ✅ | ✅ |
| SSH PermitEmptyPasswords no | 5.2.14 | Ensure SSH empty passwords are not permitted | ✅ | ✅ |
| SSH Protocol 2 only | 5.2.2 | Ensure SSH Protocol is set to 2 | ✅ | ✅ |
| SSH MaxAuthTries ≤ 4 | 5.2.7 | Ensure SSH MaxAuthTries is set to 4 or less | ✅ | ✅ |
| SSH ClientAliveInterval ≤ 300 | 5.2.13 | Ensure SSH idle timeout is configured | ✅ | ✅ |
| **Firewall** |
| UFW enabled | 3.5.1.1 | Ensure UFW is installed and enabled | ✅ | ✅ |
| UFW default deny incoming | 3.5.1.2 | Ensure default deny firewall policy | ✅ | ✅ |
| **Password Policy** |
| Min password length ≥ 14 | 5.4.1 | Ensure password creation requirements are configured | ✅ | ✅ |
| Password complexity (3/4 classes) | 5.4.1 | Ensure password complexity is configured | ✅ | ✅ |
| Max password age ≤ 90 days | 5.4.1.4 | Ensure inactive password lock is 30 days or less | ✅ | ✅ |
| **Auditd** |
| Auditd service enabled | 4.1.1.2 | Ensure auditd service is enabled | ✅ | ✅ |
| Audit sudoers changes | 4.1.14 | Ensure changes to sudoers are collected | ✅ | ✅ |
| Audit user/group modifications | 4.1.4-7 | Ensure events affecting user/group info are collected | ✅ | ✅ |
| Audit ePHI directory access | Custom | Custom: monitor `/var/ephisynth/` for unauthorized access (HIPAA 164.312(b)) | ✅ | ✅ |
| **File Permissions** |
| World-writable files checked | 6.1.9-10 | Ensure no world-writable files exist | ✅ | ✅ |
| SUID/SGID binaries audited | 6.1.11-12 | Audit SUID/SGID special permissions | ✅ | ✅ |
| /etc/shadow permissions 640 | 6.1.3 | Ensure permissions on /etc/shadow are configured | ✅ | ✅ |
| /etc/passwd permissions 644 | 6.1.2 | Ensure permissions on /etc/passwd are configured | ✅ | ✅ |
| **Unattended Upgrades** |
| Unattended-upgrades installed | 1.8 | Ensure automatic updates are configured | ✅ | ✅ |
| Security updates enabled | 1.8 | Ensure security patches are applied automatically | ✅ | ✅ |
| Reboot disabled (lab safety) | Custom | Auto-reboot disabled — manual review required for production | ✅ | ✅ |

> **Note on SSH password auth:** The benchmark recommends key-based authentication. This toolkit *checks* for password auth and flags it. In a hardening run with `--key-auth`, it will disable password auth. Without the flag, it warns but does not change, to prevent accidental lockout.

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

Every control is scored PASS/FAIL/MANUAL. The final report prints:
- **Score:** `X / Y` passed
- **Risk:** Low / Medium / High / Critical based on failed controls
- **Compliance %:** Against the 30 checked controls
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
- **ePHI paths:** Synthetic. The script uses `/var/ephisynth/` as a placeholder ePHI directory. In a real deployment, this would be parameterized.
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
