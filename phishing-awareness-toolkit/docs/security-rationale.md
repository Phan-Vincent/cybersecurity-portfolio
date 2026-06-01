# Security Rationale: Design Decisions and Limitations

> Why the toolkit is built the way it is — and where it falls short. Honest technical documentation for hiring managers and security practitioners.

---

## 1. Why Heuristics Instead of Machine Learning?

### The Decision

The phishing classifier uses **hand-crafted heuristic rules** rather than a trained ML model. This was a deliberate architectural choice, not a limitation of skill or resources.

### The Rationale

| Factor | Heuristic Model | ML Model |
|--------|----------------|----------|
| **Auditability** | Analyst can read every rule and understand why an email scored 73 | Black box — "the model says 73" with no explanation |
| **Offline operation** | Runs without internet, APIs, or model weights | Requires model hosting, inference infrastructure, or cloud calls |
| **Supply chain risk** | Zero external dependencies | Model weights, training data, and inference libraries are supply-chain vectors |
| **Speed** | Milliseconds per email | Depends on model size — could be seconds |
| **Novel attack detection** | Poor — rules must be manually updated | Potentially better — if the model was trained on similar patterns |
| **False positive rate** | Higher on edge cases | Potentially lower with sufficient training data |
| **Maintenance** | Rules must be updated as TTPs evolve | Model must be retrained — but this can be automated |

### The Verdict

For a **portfolio project** demonstrating SOC-analyst thinking, a heuristic model is the right choice. It reflects how junior analysts actually think: structured observation, weighted indicators, and clear thresholds. It is also fully auditable — a hiring manager can read `src/scoring.py` and understand every decision.

For a **production deployment** at enterprise scale, an ML model (or a hybrid approach) would likely outperform heuristics. The roadmap acknowledges this.

---

## 2. Scoring Dimension Weights

### Total: 100 points across 5 dimensions

| Dimension | Weight | Rationale |
|-----------|--------|-----------|
| **Sender Authenticity (25%)** | 25 pts | The sender is the strongest signal. A perfectly crafted body from `google.com` is different from `gooogle.com`. Display-name spoofing is the #1 BEC technique. |
| **URL Risk (25%)** | 25 pts | URLs are where the damage happens — credential forms, malware downloads, tracking pixels. IP-based URLs, lookalike domains, and suspicious TLDs are high-confidence indicators. |
| **Content Pressure (20%)** | 20 pts | Urgency and fear bypass rational thinking. "24 hours" and "legal action" are classic social engineering hooks. However, legitimate security alerts also use urgency, so this is weighted lower than sender/URL. |
| **Credential Harvesting (15%)** | 15 pts | Direct credential requests are extremely strong signals, but they appear in a minority of emails. When present, they are almost certainly phishing — but their absence doesn't mean safety. |
| **Attachment Risk (15%)** | 15 pts | Suspicious extensions and macro-enabled documents are clear threats. Weighted moderately because many phishing emails are link-based, not attachment-based. |

### Why These Weights?

The weights reflect a **triage mindset** common in SOC operations:

1. **Identity verification first** (Sender) — Who is this actually from?
2. **Destination analysis second** (URL) — Where does this want me to go?
3. **Intent analysis third** (Content, Credentials, Attachments) — What is this trying to make me do?

This ordering mirrors the OODA loop (Observe → Orient → Decide → Act) used in incident response.

---

## 3. Known False Positive Risks

A false positive occurs when a legitimate email is flagged as phishing. This erodes trust in the tool and trains users to ignore warnings.

### Scenarios That May Trigger False Positives

| Scenario | Why It Triggers | Mitigation in Tool |
|----------|----------------|-------------------|
| **Legitimate security alert** | Real IT departments use urgency language ("critical patch," "expires in 24 hours") | Scoring caps urgency at 60% of max for this dimension; legitimate alerts rarely have lookalike senders |
| **Marketing email with short URL** | `bit.ly` links in promotional emails | Shortened URLs score moderately, not maximally; combined with clean sender, total stays below 50 |
| **Invoice from new vendor** | Unfamiliar domain, payment language, first-time sender | New vendor invoices should trigger "review recommended" (26–50) — which is correct behavior |
| **Password reset you requested** | Password-reset language, link to login page | Self-requested resets from legitimate domains will score low on sender; user context matters |

### False Positive Rate Estimate

Without a labeled dataset, we estimate the false positive rate as follows:
- **Conservative estimate:** 5–10% of legitimate emails score 26–50 (suspicious)
- **Optimistic estimate:** <2% of legitimate emails score 51+ (likely phishing)
- **These are guesses** — a real assessment requires a labeled corpus

### Recommended Usage

The tool is designed as a **triage aid**, not a definitive verdict:
- **0–25**: Process normally
- **26–50**: Quick manual review — most will be legitimate
- **51–75**: Do not interact — investigate before acting
- **76–100**: Treat as confirmed phishing — report and quarantine

---

## 4. Known False Negative Risks

A false negative occurs when a real phishing email is scored as legitimate. This is the more dangerous failure mode.

### Scenarios That May Trigger False Negatives

| Scenario | Why It Evades Detection | Limitation |
|----------|------------------------|------------|
| **Compromised legitimate account** | Email comes from a real, trusted domain (e.g., a hacked vendor's Gmail) | Tool cannot distinguish compromised legitimate accounts from legitimate use — requires behavioral analysis |
| **Highly targeted spear-phishing** | Custom-crafted with no urgency, proper grammar, legitimate-looking links | Tool catches broad patterns; 1:1 tailored attacks may evade |
| **Zero-day lookalike domain** | Domain registered hours ago, not yet in blocklists | Heuristics check for obvious lookalikes (`gooogle.com`) but may miss creative homoglyphs (`gοοgle.com` with Greek omicron) |
| **Image-based phishing** | Entire message is an image with no analyzable text | Tool analyzes text content; image-based attacks require OCR or visual analysis |
| **QR code phishing** | QR code in email that links to malicious URL | Tool does not analyze QR codes (requires image processing + URL extraction) |

### False Negative Rate Estimate

- **Broad phishing campaigns:** <5% false negative rate — these reuse known TTPs
- **Targeted spear-phishing:** 20–40% false negative rate — custom attacks evade pattern-based detection
- **These are educated guesses** — a real assessment requires a red-team exercise with labeled phishing corpus

---

## 5. Why No Email Sending?

### The Decision

The toolkit intentionally does **not** include email-sending functionality. Users who want to run phishing simulations must build or integrate a separate email delivery system.

### The Rationale

| Concern | Mitigation via No Sending |
|---------|--------------------------|
| **Legal liability** | Without built-in sending, the toolkit is a detection + education tool — not a weapon |
| **Consent enforcement** | Adding sending would require complex consent workflows; separating them keeps the core tool safe |
| **Abuse friction** | A malicious actor must write or integrate a sender — this is a barrier that filters out casual misuse |
| **Focus** | The portfolio demonstrates analysis and education skills — not email infrastructure skills |

### Future Consideration

A future version may include an **optional, explicitly opt-in** email-sending module with:
- Consent tracking (who agreed to participate)
- Rate limiting (prevent mass abuse)
- Audit logging (who sent what, when)
- Domain safelisting (only send to pre-approved domains)

This would be a separate component with its own threat model.

---

## 6. Why Synthetic Data in Templates?

### The Decision

All training templates use entirely fictional:
- Names (Marcus Chen, Derek Holloway, James Whitfield)
- Companies (Apex Consulting Group, NexaData Systems)
- Addresses, phone numbers, and account numbers
- Domains (all are lookalike domains, not real company domains)

### The Rationale

| Risk | Mitigation |
|------|-----------|
| **Accidental PII exposure** | No real data means no GDPR/HIPAA violations if templates are shared |
| **Credential stuffing** | Fake credentials (`Nexa2026!`) cannot be used in real attacks |
| **Social engineering rehearsal** | Fictional scenarios are clearly training materials, not real reconnaissance |
| **Legal clarity** | Synthetic data makes the educational purpose unambiguous |

**Even the "healthcare" template uses fictional patient records, fictional prescription numbers, and a fictional compliance officer.** No real CVS data, no real patient information, no real DEA numbers.

---

## 7. Testing Strategy

### What Is Tested

| Component | Test Coverage | Purpose |
|-----------|--------------|---------|
| `scoring.py` | Unit tests for each dimension | Verify that known phishing patterns score high, known legitimate patterns score low |
| `analyzer.py` | Integration tests | Verify end-to-end pipeline: parse → score → verdict |
| CLI interface | Smoke tests | Verify argument parsing, file reading, stdin handling |
| Template compatibility | Each template is analyzed | Verify all training templates score in the "likely phishing" (51–100) range |

### What Is NOT Tested (Yet)

| Component | Why Not Tested | Priority |
|-----------|---------------|----------|
| False positive rate on real inbox | Requires large labeled dataset | High — needed for production claims |
| False negative rate on real phishing corpus | Requires access to phishing datasets (OpenPhish, Cofense) | High — needed for accuracy claims |
| Performance on large volumes | Not relevant for portfolio/demo | Medium — needed for production deployment |
| Unicode homoglyph detection | Not yet implemented | Low — future enhancement |

---

## 8. Honest Limitations

This section exists because **hiring managers value honesty over hype**.

### Current Limitations

1. **No ML component** — accuracy on novel attacks is lower than a trained model would achieve
2. **No email parsing library** — relies on regex/header extraction, which may fail on malformed or MIME-encoded emails
3. **No attachment analysis** — only checks file extensions, not macro detection, sandboxing, or YARA rules
4. **No behavioral analysis** — cannot detect compromised legitimate accounts
5. **No QR code analysis** — rising attack vector not addressed
6. **No homoglyph detection** — Unicode lookalike characters evade domain checks
7. **English-only** — non-English phishing emails are not analyzed

### These Limitations Are Documented Because...

A security professional who understands their tool's limitations is more valuable than one who pretends their tool is perfect. Every SOC analyst knows that **no single control catches everything** — defense is about layered controls, not silver bullets.

This toolkit is one layer. It is documented, tested, and honest about where it fits in a broader security program.

---

*Last updated: 2026-06-01*
