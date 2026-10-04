# Security Rationale: Why Each CIS Control Matters for ePHI

**Author:** Vincent Phan | CSUSB Cybersecurity Student | Former CVS CPhT  
**Date:** 2026-06-01

---

## SSH Controls (CIS 5.2.x)

### SSH-01: Protocol 2
SSH protocol 1 has known cryptographic weaknesses (CRC-32 insertion attacks, weak key exchange). Protocol 2 uses Diffie-Hellman and modern ciphers. For ePHI servers, an attacker who can downgrade to SSH-1 can potentially intercept admin credentials or session data in transit.

**HIPAA mapping:** Transmission Security (§164.312(e)(1)) — ensures integrity of data in transit during admin sessions.

### SSH-03: MaxAuthTries <= 4
Healthcare IT admin accounts are high-value targets. Automated brute-force tools (Hydra, Medusa) can attempt thousands of passwords per hour. Limiting to 4 attempts slows guessing to a crawl and triggers fail2ban/pam_faillock integration.

**Real-world:** The 2023 MCNA Dental breach (9M+ patients) began with compromised admin credentials.

### SSH-04: PermitRootLogin no
Root is the keys to the kingdom. If root is directly accessible via SSH, a single successful credential compromise = full ePHI server ownership. Disabling it forces the attacker to pivot through a lower-privilege account first, creating detection opportunities (auditd, EDR).

### SSH-05: PasswordAuthentication no
Passwords are the most stolen credential type in healthcare. They appear in breach dumps, are reused across systems, and are vulnerable to phishing. SSH keys are cryptographic credentials that cannot be "phished" in the same way and are not reusable across unrelated breaches.

**HIPAA mapping:** Access Management (§164.312(a)(1)) — unique user identification for ePHI access.

---

## Firewall Controls (CIS 3.5.x)

### FW-03: Default Deny
The HIPAA Security Rule requires "technical safeguards" to limit access to ePHI. A default-deny firewall is the simplest, most reliable technical safeguard: if a service isn't explicitly needed, it's not exposed. This prevents accidental exposure of development ports, database listeners, or management interfaces.

**Real-world:** The 2024 Change Healthcare breach ($22M ransom) involved exposed RDP + lack of network segmentation.

### FW-04: Loopback rules
Localhost spoofing (sending packets with 127.0.0.1 source from outside the host) can bypass IP-based authentication or confuse applications. Explicit loopback rules prevent this anti-pattern.

---

## Authentication Controls (CIS 5.3.x / 5.4.x)

### AUTH-01: pam_pwquality (12-char, mixed case, digits, symbols)
NIST SP 800-63B (2017) deprecated complexity *rules* in favor of length, but CIS still enforces them because most healthcare IT environments lack the infrastructure for NIST's recommended password-strength meters. For a student toolkit, 12-character complexity is a pragmatic baseline that exceeds the 8-character default and matches real-world health org baselines.

**HIPAA mapping:** Password management (§164.312(a)(2)(iv)) — procedures for creating, changing, and safeguarding passwords.

### AUTH-02: pam_faillock (5 attempts, 15-min lockout)
Credential stuffing attacks use lists of millions of stolen passwords. Without lockout, an attacker can test 1000s of passwords against a single account. 5 attempts + 15-minute lockout makes credential stuffing computationally infeasible while not creating a DoS vector (15 minutes is brief enough for a legitimate user to retry after a coffee break).

### AUTH-03: Password expiration (365 days)
NIST now recommends *against* arbitrary expiration for memorized passwords, but in healthcare environments, periodic rotation is still common because:
- Shared/admin accounts exist (bad practice, but real)
- Credential leaks may not be detected for months
- 365 days is a compromise: long enough to avoid NIST's criticism of 90-day rotation, short enough to limit exposure from undetected leaks.

---

## Audit Controls (CIS 4.1.x)

### AUDIT-02: auditd enabled
HIPAA §164.312(b) explicitly requires audit controls to record activity in information systems that contain ePHI. auditd is the standard Linux mechanism for this. Without it, a breach is undetectable and un-investigable.

**Real-world:** HHS OCR fines are 30-50% higher when an organization cannot produce audit logs during an investigation.

### AUDIT-06: ePHI file access rules
HIPAA requires knowing *who* accessed *what* ePHI *when*. auditd rules on the ePHI directory (`/var/ephisynth` by default, `--ephi-dir` in production) (or production equivalent) provide the raw data for this. This is the difference between "we think we were breached" and "user jsmith accessed patient #48291 at 14:23 on June 1."

---

## Filesystem Controls (CIS 6.1.x)

### FS-02: No world-writable files
World-writable files allow any user on the system — including compromised web servers, cron jobs, or temporary accounts — to modify binaries, configs, or data. In an ePHI context, a world-writable script in `/tmp` could be replaced by malware that exfiltrates patient data.

### FS-03: Sticky bit on world-writable directories
The sticky bit (`+t`) means only the owner of a file can delete it in a shared directory. Without it, any user can delete another user's files. For ePHI, this prevents anti-forensics: an attacker who gains a low-privilege shell can't delete `/tmp/audit-trail` or `/var/log` files to cover their tracks.

---

## Update Controls (CIS 1.8 / 1.9)

### UPD-01: Unattended-upgrades
Known Exploited Vulnerabilities (KEV) catalog shows healthcare is a top target. The time between patch release and exploitation is often <7 days for high-profile CVEs. Manual patching is unreliable in understaffed clinic IT. Unattended-upgrades ensures the security patch is *installed* within 24 hours.

### UPD-04: Auto-reboot
A patched kernel that isn't rebooted is still vulnerable. Attackers love "patch gap" — the window between installation and reboot. Auto-reboot at 2 AM (maintenance window) closes this gap for ePHI servers that must be secure 24/7.

**HIPAA mapping:** Integrity Controls (§164.312(c)(1)) — ensures ePHI is not improperly altered or destroyed. A vulnerable kernel is an integrity risk.

---

## Summary Table

| Control | HIPAA Rule | Attack Vector Addressed |
|-----------|------------|------------------------|
| SSH-01 | 164.312(e)(1) | Protocol downgrade |
| SSH-03 | 164.312(a)(1) | Brute-force |
| SSH-04 | 164.312(a)(1) | Root compromise |
| SSH-05 | 164.312(a)(1) | Credential stuffing |
| FW-03 | 164.312(e)(1) | Network exposure |
| AUTH-01 | 164.312(a)(2)(iv) | Weak passwords |
| AUTH-02 | 164.312(a)(1) | Credential stuffing |
| AUTH-03 | 164.312(a)(1) | Stolen credential reuse |
| AUDIT-02 | 164.312(b) | Undetected breach |
| AUDIT-06 | 164.312(b) | Insider threat |
| FS-02 | 164.312(c)(1) | Privilege escalation |
| FS-03 | 164.312(c)(1) | Anti-forensics |
| UPD-01 | 164.308(a)(5)(ii)(B) | Exploited vulnerability |
| UPD-04 | 164.312(c)(1) | Patch gap exploitation |

---

*This document is a student portfolio piece. It represents my understanding of how CIS controls map to HIPAA requirements based on publicly available guidance (HHS, NIST, CIS Benchmarks). It is not legal or compliance advice.*
