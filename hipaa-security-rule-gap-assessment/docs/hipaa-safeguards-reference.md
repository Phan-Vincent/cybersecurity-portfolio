# HIPAA Security Rule — CFR Cross-Reference

Every control in `controls/hipaa_security_controls.json`, grouped by safeguard and mapped to its 45 CFR Part 164 Subpart C citation.

- **R / A** — Required or Addressable implementation specification. *Addressable* does not mean optional: the entity must implement it, implement an equivalent alternative, or document why neither is reasonable and appropriate (§164.306(d)(3)).
- **PHI** — how much ePHI the control protects; drives the scoring multiplier (High 1.5 / Medium 1.25 / Low 1.0).
- **Maturity** — typical implementation level for a small pharmacy (1 = ad hoc, 5 = optimized), used as a planning reference.

## §164.308 — Administrative Safeguards

| Control | CFR | Standard | R / A | PHI | Maturity |
|---|---|---|---|---|---:|
| ADM-1.1 | 164.308(a)(1)(i) | Security Management Process | R | High | 3 |
| ADM-1.2 | 164.308(a)(1)(ii)(A) | Security Management Process | R | High | 3 |
| ADM-1.3 | 164.308(a)(1)(ii)(B) | Security Management Process | R | Medium | 2 |
| ADM-1.4 | 164.308(a)(1)(ii)(D) | Security Management Process | R | High | 3 |
| ADM-2.1 | 164.308(a)(2) | Assigned Security Responsibility | R | High | 1 |
| ADM-3.1 | 164.308(a)(3)(i) | Workforce Security | A | High | 3 |
| ADM-3.2 | 164.308(a)(3)(ii)(A) | Workforce Security | A | Medium | 2 |
| ADM-3.3 | 164.308(a)(3)(ii)(B) | Workforce Security | A | High | 4 |
| ADM-3.4 | 164.308(a)(3)(ii)(C) | Workforce Security | A | High | 3 |
| ADM-4.1 | 164.308(a)(4)(i) | Information Access Management | R | High | 4 |
| ADM-4.2 | 164.308(a)(4)(ii)(A) | Information Access Management | A | High | 3 |
| ADM-4.3 | 164.308(a)(4)(ii)(B) | Information Access Management | A | High | 4 |
| ADM-4.4 | 164.308(a)(4)(ii)(C) | Information Access Management | A | High | 3 |
| ADM-5.1 | 164.308(a)(5)(i) | Security Awareness and Training | A | Medium | 2 |
| ADM-5.2 | 164.308(a)(5)(ii)(A) | Security Awareness and Training | A | High | 4 |
| ADM-5.3 | 164.308(a)(5)(ii)(B) | Security Awareness and Training | A | High | 3 |
| ADM-5.4 | 164.308(a)(5)(ii)(C) | Security Awareness and Training | A | High | 4 |
| ADM-5.5 | 164.308(a)(5)(ii)(D) | Security Awareness and Training | A | Medium | 3 |
| ADM-6.1 | 164.308(a)(6)(i) | Security Incident Procedures | R | High | 4 |
| ADM-6.2 | 164.308(a)(6)(ii) | Security Incident Procedures | R | High | 4 |
| ADM-7.1 | 164.308(a)(7)(i) | Contingency Plan | R | High | 4 |
| ADM-7.2 | 164.308(a)(7)(ii)(A) | Contingency Plan | A | High | 4 |
| ADM-7.3 | 164.308(a)(7)(ii)(B) | Contingency Plan | A | Medium | 3 |
| ADM-7.4 | 164.308(a)(7)(ii)(C) | Contingency Plan | A | Medium | 3 |
| ADM-7.5 | 164.308(a)(7)(ii)(D) | Contingency Plan | A | Medium | 2 |
| ADM-7.6 | 164.308(a)(7)(ii)(E) | Contingency Plan | A | Medium | 2 |
| ADM-8.1 | 164.308(a)(8) | Evaluation | R | Medium | 2 |
| ADM-9.1 | 164.308(b)(1) | Business Associate Contracts | R | High | 3 |
| ADM-9.2 | 164.308(b)(3) | Business Associate Contracts | R | High | 2 |
| ADM-9.3 | 164.308(b)(4) | Business Associate Contracts | R | Medium | 2 |

## §164.310 — Physical Safeguards

| Control | CFR | Standard | R / A | PHI | Maturity |
|---|---|---|---|---|---:|
| PHY-1.1 | 164.310(a)(1) | Facility Access Controls | A | High | 4 |
| PHY-1.2 | 164.310(a)(2)(i) | Facility Access Controls | A | High | 3 |
| PHY-1.3 | 164.310(a)(2)(ii) | Facility Access Controls | A | Medium | 3 |
| PHY-1.4 | 164.310(a)(2)(iii) | Facility Access Controls | A | Low | 2 |
| PHY-1.5 | 164.310(a)(2)(iv) | Facility Access Controls | A | Low | 2 |
| PHY-2.1 | 164.310(b) | Workstation Use | R | Medium | 3 |
| PHY-3.1 | 164.310(c) | Workstation Security | R | High | 4 |
| PHY-4.1 | 164.310(d)(1) | Device and Media Controls | R | High | 3 |
| PHY-4.2 | 164.310(d)(2)(i) | Device and Media Controls | A | High | 3 |
| PHY-4.3 | 164.310(d)(2)(ii) | Device and Media Controls | A | Medium | 3 |
| PHY-4.4 | 164.310(d)(2)(iii) | Device and Media Controls | A | High | 4 |
| PHY-4.5 | 164.310(d)(2)(iv) | Device and Media Controls | A | High | 3 |

## §164.312 — Technical Safeguards

| Control | CFR | Standard | R / A | PHI | Maturity |
|---|---|---|---|---|---:|
| TEC-1.1 | 164.312(a)(1) | Access Control | R | High | 4 |
| TEC-1.2 | 164.312(a)(2)(i) | Access Control | R | High | 3 |
| TEC-1.3 | 164.312(a)(2)(ii) | Access Control | R | High | 4 |
| TEC-1.4 | 164.312(a)(2)(iii) | Access Control | A | High | 4 |
| TEC-1.5 | 164.312(a)(2)(iv) | Access Control | A | High | 3 |
| TEC-2.1 | 164.312(b) | Audit Controls | R | High | 4 |
| TEC-3.1 | 164.312(c)(1) | Integrity | R | High | 3 |
| TEC-3.2 | 164.312(c)(2) | Integrity | A | Medium | 2 |
| TEC-4.1 | 164.312(d) | Person or Entity Authentication | R | High | 4 |
| TEC-5.1 | 164.312(e)(1) | Transmission Security | R | High | 4 |
| TEC-5.2 | 164.312(e)(2)(i) | Transmission Security | A | High | 4 |
| TEC-5.3 | 164.312(e)(2)(ii) | Transmission Security | A | High | 4 |

## §164.316 — Policies, Procedures and Documentation

| Control | CFR | Standard | R / A | PHI | Maturity |
|---|---|---|---|---|---:|
| DOC-1.1 | 164.316(a) | Documentation Requirements | R | Low | 2 |
| DOC-1.2 | 164.316(b)(1)(i) | Documentation Requirements | R | Low | 2 |
| DOC-1.3 | 164.316(b)(1)(ii) | Documentation Requirements | R | Low | 2 |
| DOC-1.4 | 164.316(b)(2)(i) | Documentation Requirements | R | Low | 2 |

## Primary Sources

- 45 CFR Part 164 Subpart C — Security Standards for the Protection of Electronic Protected Health Information (eCFR)
- HHS Office for Civil Rights — Security Rule Guidance Material
- NIST SP 800-66 Rev. 2 — Implementing the HIPAA Security Rule: A Cybersecurity Resource Guide

*Regenerate this table whenever the controls catalog changes; `tests/test_docs.py` fails if they drift.*
