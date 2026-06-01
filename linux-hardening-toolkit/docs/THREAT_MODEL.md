# Threat Model: Healthcare Linux Server (ePHI Context)

**Author:** Vincent Phan | CSUSB Cybersecurity Student | Former CVS CPhT  
**Date:** 2026-06-01  
**Scope:** Linux server hosting synthetic ePHI in a small healthcare/clinic IT environment.

---

## 1. Asset Definition

| Asset | Value | Sensitivity |
|-------|-------|-------------|
| ePHI database (PostgreSQL) | Patient records, SSNs, diagnoses | Critical |
| Admin SSH access | Full system control | Critical |
| Application logs | Audit trail for HIPAA | High |
| Backup server | Disaster recovery | High |
| Domain reputation / patient trust | Business continuity | High |

---

## 2. Threat Actors

| Actor | Motivation | Capability | Likelihood |
|-------|------------|------------|------------|
| **Ransomware affiliate** (e.g., LockBit, BlackCat) | Encrypt ePHI, demand ransom, sell data | High | **High** |
| **Script kiddie / automated scanner** | Opportunistic exploitation | Low | High |
| **Insider (malicious employee)** | Steal patient data, fraud, revenge | Medium | Medium |
| **Insider (accidental)** | Misconfigured share, weak password | Low | **High** |
| **Nation-state APT** | Healthcare intelligence, COVID-era targeting | High | Low |
| **Vendor / MSP compromise** | Supply-chain pivot to clinic data | Medium | Medium |

---

## 3. Attack Vectors

### 3.1 Initial Access

1. **Brute-force SSH** — Default port 22, weak admin password, no key-auth → full server compromise.
2. **Credential stuffing** — Stolen pharmacy admin creds from prior breach (e.g., CVS, Walgreens leaks) reused on ePHI server.
3. **Exploited unpatched vulnerability** — Apache Struts, Log4j, or kernel CVE → remote code execution.
4. **Phished IT admin** — Admin clicks link, attacker captures VPN/SSH credentials.
5. **Exposed database port** — PostgreSQL 5432 open to internet via misconfigured firewall.

### 3.2 Lateral Movement / Privilege Escalation

1. **SUID abuse** — World-writable SUID binary modified to spawn root shell.
2. **Sudo misconfiguration** — `/etc/sudoers` allows `ALL` for service account.
3. **Kernel exploit** — Unpatched kernel = local privilege escalation (e.g., Dirty Pipe, PwnKit).

### 3.3 ePHI Exfiltration / Impact

1. **Database dump** — `pg_dump` to attacker C2.
2. **Ransomware encryption** — ePHI files encrypted, backups targeted.
3. **Audit log deletion** — `rm /var/log/audit/*` to cover tracks.
4. **Defacement / reputation harm** — Public notification of breach.

---

## 4. Control-to-Threat Mapping

| Toolkit Control | Mitigated Threat(s) | How |
|-----------------|---------------------|-----|
| **SSH-01** Protocol 2 | SSH downgrade (MITM) | Forces modern crypto |
| **SSH-03** MaxAuthTries | Brute-force SSH | Rate-limits guesses |
| **SSH-04** PermitRootLogin no | Root compromise blast radius | Attacker must compromise non-root first |
| **SSH-05** PasswordAuth disabled | Credential stuffing, brute-force | Keys are non-reusable across breaches |
| **FW-03** Default deny | All network-based initial access | Only explicit ports/services exposed |
| **AUTH-01** pam_pwquality | Weak passwords | Enforces 12-char complexity |
| **AUTH-02** pam_faillock | Brute-force, credential stuffing | 5-attempt lockout, 15-min unlock |
| **AUTH-03** Password expiration | Stolen credential reuse | Forces rotation within 1 year |
| **AUDIT-02** auditd enabled | All post-breach forensics | Immutable log of who touched ePHI |
| **AUDIT-06** ePHI file audit | Insider threat, unauthorized access | Alert on unexpected ePHI reads |
| **FS-02** No world-writable files | Privilege escalation, data tampering | Removes arbitrary-user write access |
| **FS-03** Sticky bit | Data deletion by non-owners | Prevents cleanup/anti-forensics |
| **UPD-01** Auto-updates | Exploited unpatched vulns | Daily security patch application |
| **UPD-04** Auto-reboot | Patched-but-unrebooted kernel | Ensures fixes are live |

---

## 5. Residual Risk

Even after full hardening, these risks remain:

- **Zero-day kernel exploit** — Mitigation: EDR/XDR, kernel live-patching (e.g., Canonical Livepatch)
- **Application-layer vulnerability** — Mitigation: WAF, secure code review, dependency scanning
- **Physical theft of backup drives** — Mitigation: encryption at rest, offsite encrypted backups
- **Social engineering of admin** — Mitigation: security awareness training, MFA on VPN
- **Compromised SSH key** — Mitigation: key rotation, hardware tokens (YubiKey), bastion host

---

## 6. Honest Assessment

This toolkit addresses the **OS-layer** controls. A real ePHI server would also need:
- Full-disk encryption (LUKS) — not included (student scope, but I can discuss it)
- Database-level encryption (TDE) — not included
- Network segmentation (VLANs, VPN-only access) — partially addressed via UFW
- SIEM forwarding (rsyslog → Splunk/Elastic) — not included, but auditd logs are SIEM-ready
- Endpoint Detection & Response (EDR) — not included
- Vulnerability scanning (Nessus/OpenVAS) — not included

These are deliberate scope boundaries for a student portfolio piece. I can explain each gap and what I'd use to fill it.
