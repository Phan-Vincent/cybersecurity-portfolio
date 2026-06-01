# Hardening Checklist

This document tracks the macOS-specific and application-level hardening steps applied to the OpenClaw Home Lab. It is modeled after CIS macOS Security Customization Guides and adapted for a single-user developer/security-student environment.

## macOS System Hardening

### FileVault 2 (Disk Encryption)

- [x] **Enabled** — Full-disk encryption via FileVault 2 (AES-XTS 128-bit).
- [x] **Recovery Key** — Stored in Apple ID cloud escrow (not local-only to prevent lockout).
- [x] **Verification:**
  ```bash
  fdesetup status
  # Expected: FileVault is On.
  ```

### Firewall & Stealth Mode

- [x] **Application Firewall** — Enabled via System Settings.
- [x] **Stealth Mode** — Enabled; host does not respond to ICMP echo or TCP/UDP port scans.
- [x] **Automatic signed-software allowance** — Disabled; manual approval required.
- [x] **Verification:**
  ```bash
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
  ```

### Gatekeeper & Notarization

- [x] **Gatekeeper** — Enabled; only App Store and identified developers allowed.
- [x] **Notarization check** — Required for all downloaded software.
- [x] **Quarantine** — Preserved for internet-downloaded files (`com.apple.quarantine` extended attribute).
- [x] **Verification:**
  ```bash
  spctl --status
  # Expected: assessments enabled
  ```

### Software Update & Patch Management

- [x] **Automatic macOS updates** — Enabled.
- [x] **Automatic security responses** — Enabled (rapid-response patches without full OS update).
- [x] **Application updates** — Homebrew `brew upgrade` run weekly via cron (`healthcheck:update-status`).
- [x] **XProtect + MRT** — Apple's built-in anti-malware; updates automatically.

### User Account Security

- [x] **Standard user for daily use** — Admin escalation via `sudo` only when required.
- [x] **Password policy** — Minimum 15 characters, 1Password-generated.
- [x] **Touch ID** — Enabled for local auth; not used for `sudo` (password required).
- [x] **Screen lock** — Immediate on sleep; 5-minute inactivity timer.
- [x] **Find My Mac** — Enabled for remote lock/wipe if stolen.

### Network Privacy

- [x] **Private Wi-Fi Address** — Enabled; MAC address randomization per network.
- [x] **Limit IP Address Tracking** — Enabled (iCloud Private Relay lite for Safari/Safari-related services).
- [x] **Location Services** — Disabled (not needed for lab operation).
- [x] **Bluetooth** — Disabled when not in use.

## Application-Level Hardening

### OpenClaw Gateway

- [x] **Loopback binding** — `ws://127.0.0.1:18789` only; no `0.0.0.0`.
- [x] **Workspace sandbox** — Enforced by runtime; agents cannot read arbitrary user files.
- [x] **Exec approval** — Shell commands require explicit user approval for destructive operations.
- [x] **Plugin signature** — Plugins installed from npm registry with checksum verification.
- [x] **Config backup** — `openclaw.json` backed up before any manual edit.

### Secret Management

- [x] **1Password CLI** — All API keys, tokens, and passwords stored in vault; injected at runtime.
- [x] **No secrets in git** — `.gitignore` blocks: `*.pem`, `.env`, `config.yaml`, `*.json` (data files).
- [x] **SSH keys** — Ed25519 keys with passphrase; stored in 1Password, injected via `ssh-add`.
- [x] **Key rotation** — Kalshi API key rotated 2026-05-19 after credential generation.
- [x] **Regular audit** — `secrets-audit.py` runs weekly to scan for accidental hardcoding.

### Automation Hardening

- [x] **Cron job isolation** — Default `sessionTarget: isolated` for agentTurn jobs; fresh context per run.
- [x] **Timeout enforcement** — All cron jobs specify `timeoutSeconds` (0 = no timeout is avoided).
- [x] **Model cost control** — Worker crons locked to `kimi/kimi-code` (cheap); orchestrator uses Sonnet only for interactive tasks.
- [x] **Gateway restart safety** — No `doctor --fix` or plugin install while subagents are mid-flight.
- [x] **Self-wake crons** — Multi-agent batches register a fallback cron to recover if completion events drop.

### Data Handling

- [x] **Synthetic data policy** — All health, nutrition, and financial demo data is fabricated.
- [x] **PHI awareness** — Author is CPhT with HIPAA training; real health data stays in encrypted Apple Health / Cronometer.
- [x] **Log permissions** — Gateway logs: `600` (owner read/write only).
- [x] **Git hygiene** — `git status` checked before commits; no large files (>100MB); sensitive files excluded.

### Backup & Recovery

- [x] **Time Machine** — Enabled to encrypted external SSD.
- [x] **Workspace git backup** — Pushed to private GitHub repo (`workspace-backup`) daily.
- [x] **Config versioning** — `openclaw.json` changes committed with descriptive messages.
- [x] **Disaster recovery tested** — Simulated restore from git clone + 1Password re-auth (verified working).

## Hardening Scorecard

| Category | Items | Complete | Percentage |
|----------|-------|----------|------------|
| macOS System | 8 | 8 | 100% |
| Application (Gateway) | 5 | 5 | 100% |
| Secret Management | 5 | 5 | 100% |
| Automation | 5 | 5 | 100% |
| Data Handling | 5 | 5 | 100% |
| Backup & Recovery | 4 | 4 | 100% |
| **Total** | **32** | **32** | **100%** |

## Planned (Not Yet Implemented)

These are documented as aspirational hardening steps for the roadmap:

- [ ] **Full Disk Access audit** — Review which apps have FDA; principle of least privilege.
- [ ] **Kernel Extension inventory** — Audit `systemextensionsctl list` for unnecessary drivers.
- [ ] **DNS over HTTPS** — Configure `cloudflared` or macOS native DoH.
- [ ] **Outbound firewall (Little Snitch / Lulu)** — Per-application network filtering beyond macOS built-in.
- [ ] **File Integrity Monitoring (FIM)** — `osquery` or `aide` to detect unauthorized config changes.
- [ ] **Container sandboxing** — Docker for service isolation (future Linux VM / Raspberry Pi migration).

## Verification Command Reference

```bash
# FileVault
fdesetup status

# Firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode

# Gatekeeper
spctl --status

# Software Update
softwareupdate --list

# Full Disk Access list (requires manual review in System Settings)
tccutil.py --list  # if tccutil installed, else GUI

# SSH config hardening check
grep -E "^(PasswordAuthentication|PermitRootLogin|Protocol)" /etc/ssh/sshd_config

# Log permissions
ls -la ~/Library/Logs/openclaw/
```
