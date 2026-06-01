# Threat Model: Phishing Simulation & Awareness Toolkit

> A structured analysis of the threats this toolkit addresses, the threats it could create, and the mitigations that keep it defensive.

---

## 1. Threats Addressed (Defensive Value)

### 1.1 Credential Harvesting via Email

**Description:** Attackers send emails that impersonate trusted services (Microsoft 365, banking, HR portals) to trick users into entering credentials on fake login pages.

**How this toolkit addresses it:**
- The analyzer detects lookalike domains, IP-based URLs, and credential-harvesting language patterns
- Training templates demonstrate real-world credential-harvesting techniques in a safe environment
- The awareness guide teaches users to never enter passwords via email links

**Severity:** Critical — credential compromise is the #1 path to lateral movement and data exfiltration.

### 1.2 Business Email Compromise (BEC)

**Description:** Attackers spoof executive identities to request wire transfers, invoice payments, or sensitive data. BEC losses exceeded $2.9 billion in 2023 (FBI IC3).

**How this toolkit addresses it:**
- CEO fraud template demonstrates the psychological pressure tactics used in BEC
- Analyzer flags display-name spoofing and out-of-band payment requests
- Awareness guide includes a "CEO fraud" scenario with clear verification steps

**Severity:** Critical — direct financial impact, often not caught by technical controls alone.

### 1.3 Malware Delivery via Email

**Description:** Attackers attach malicious files (macros, scripts, executables) or link to malware downloads, disguised as invoices, shipping notifications, or IT patches.

**How this toolkit addresses it:**
- Analyzer scores attachment risk based on extension analysis
- Training templates include a fake "IT security patch" that mimics real malware delivery
- Awareness guide teaches users to verify unexpected attachments

**Severity:** High — one opened attachment can lead to full network compromise.

### 1.4 Invoice and Payment Fraud

**Description:** Attackers send fake overdue invoices or payment requests to accounts payable, exploiting process gaps and urgency pressure.

**How this toolkit addresses it:**
- Urgent invoice template demonstrates time-pressure tactics
- Analyzer flags financial urgency language and suspicious sender domains
- Awareness guide emphasizes verifying payment requests through known channels

**Severity:** High — significant financial losses, especially in small-to-medium businesses.

### 1.5 Healthcare-Specific Phishing

**Description:** Attackers target healthcare workers with HIPAA-related scare tactics, knowing that fear of compliance violations overrides critical thinking.

**How this toolkit addresses it:**
- Healthcare insurance template demonstrates PHI-related social engineering
- Analyzer is tuned to detect healthcare-specific pressure language
- Awareness guide includes a healthcare scenario with realistic context

**Severity:** Critical in healthcare — PHI breaches carry regulatory penalties (OCR fines) and reputational damage.

---

## 2. Threats Created If Misused (Offensive Risk)

This toolkit is designed for **defense**. However, like any security tool, it could be misused. The following analysis documents those risks and the mitigations in place.

### 2.1 Unauthorized Phishing Campaigns

**Risk:** A malicious actor could use the synthetic templates as starting points for real phishing attacks against individuals without consent.

**Likelihood:** Medium — the templates are realistic and ready-to-use.

**Impact:** High — credential theft, financial fraud, identity theft.

**Mitigations:**
- ✅ **No email-sending capability** is built into the toolkit
- ✅ Every template includes a prominent `TRAINING USE ONLY` header
- ✅ README includes an explicit ethical-use disclaimer with legal warnings
- ✅ Synthetic data only — no real PII, PHI, or credentials embedded

### 2.2 Reputation Damage via Fake Training

**Risk:** An organization could claim to be conducting "authorized training" while actually using the exercise to punish or surveil employees without genuine educational intent.

**Likelihood:** Low — requires insider threat within an organization.

**Impact:** Medium — erodes trust in security teams, creates legal liability.

**Mitigations:**
- ✅ Documentation emphasizes debriefing participants after exercises
- ✅ Awareness guide positions the user as "the first line of defense," not a scapegoat
- ✅ Ethical disclaimer requires transparent communication with participants

### 2.3 Supply Chain Risk (Future Roadmap)

**Risk:** If future versions integrate with email APIs (Microsoft Graph, Gmail), compromised API credentials could be used to send real phishing emails at scale.

**Likelihood:** Low — currently no API integration exists.

**Impact:** High — mass email sending from a trusted domain.

**Mitigations:**
- ✅ Current version has **zero external dependencies** — no API keys, no network calls
- ✅ Future API integration will require explicit opt-in and scoped permissions
- ✅ Any email-sending module will be documented with consent-check workflows

### 2.4 Data Leakage from Analysis

**Risk:** If deployed as a web service, analyzed emails (which may contain real PII) could be logged, cached, or exposed.

**Likelihood:** Low — current version is local-only.

**Impact:** High — PII exposure violates GDPR, HIPAA, and other regulations.

**Mitigations:**
- ✅ Analyzer runs entirely offline — no data transmission
- ✅ No logging of email content to external services
- ✅ If a web version is built in the future, it will use client-side processing only

---

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY: User's Local Machine                        │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │ Email Input  │───→│ Analyzer     │───→│ Score/Report │   │
│  │ (local file) │    │ (local code) │    │ (stdout)     │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│                                                              │
│  NO NETWORK TRAFFIC. NO EXTERNAL APIs. NO DATA EXFILTRATION. │
└─────────────────────────────────────────────────────────────┘
```

The analyzer operates entirely within a single trust boundary: the user's local machine. There are no subprocesses that call out to the network, no telemetry, no cloud services, and no persistent storage of analyzed content.

---

## 4. Attack Surface Summary

| Component | Attack Surface | Risk Level | Mitigation |
|-----------|---------------|------------|------------|
| Template files | Could be copied for real phishing | Medium | Watermarked headers, no real data, no sending capability |
| Analyzer code | Could be modified to score emails incorrectly | Low | Open source, auditable, tests verify correctness |
| CLI interface | Command injection via malicious filenames | Low | Input sanitized, no shell execution |
| Synthetic data | Accidental use of real data in demos | Low | All templates use fictional names, domains, and data |

---

## 5. Risk Acceptance

The residual risk — that someone could copy the templates and manually send them as real phishing emails — is **accepted** because:

1. The same information is publicly available in security research blogs, phishing databases (OpenPhish, PhishTank), and academic papers
2. Removing the templates would reduce the training value without meaningfully reducing real-world phishing capability
3. The explicit ethical-use documentation makes intent clear
4. No sending capability is provided, creating friction for misuse

**The defensive value of awareness training outweighs the marginal offensive risk of public synthetic templates.**

---

## 6. Future Threat Model Updates

This threat model should be reviewed when:
- Email-sending capabilities are added
- ML models are integrated (training data poisoning risk)
- Web deployment is considered (new attack surface)
- API integrations are implemented (credential and scope risks)

Last reviewed: 2026-06-01
