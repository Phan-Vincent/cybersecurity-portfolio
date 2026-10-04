# Ransomware Incident Response Playbook — Independent Pharmacy / Small Clinic

> A complete, healthcare-specific incident-response playbook for a ransomware attack on a small independent pharmacy, built around NIST SP 800-61 Rev. 2 and HIPAA Breach Notification requirements — paired with runnable triage tooling and a tabletop exercise.

**Author:** Vincent Phan — CVS Pharmacy Technician (CPhT, since 2020); BS Information Systems, Cybersecurity concentration, CSU San Bernardino (Fall 2026). Career target: SOC analyst / security engineer.

---

## Why this project

Most ransomware playbooks are written for enterprises with a 24/7 SOC, a CISO, and a legal department. A neighborhood pharmacy has none of that — it has one IT contractor, a pharmacy manager, an exhausted staff, refrigerated insulin that *cannot* warm up, and patients who need their heart and seizure medications dispensed **tomorrow morning** regardless of what the attacker did tonight.

I spent four+ years as a pharmacy technician handling PHI, insurance billing, controlled-substance workflows, and cold-chain inventory. This project applies that real operational knowledge to a security problem: **what does ransomware response actually look like when patient safety and HIPAA deadlines are both on the clock, and there's no enterprise safety net?**

That intersection — real pharmacy operations + NIST-aligned IR + HIPAA breach law — is the differentiator here.

## What this demonstrates

- **NIST SP 800-61 fluency** — the playbook is structured by the four NIST IR phases (Preparation; Detection & Analysis; Containment, Eradication & Recovery; Post-Incident Activity).
- **Healthcare regulatory knowledge** — HIPAA Breach Notification Rule (45 CFR §164.404–§164.408), the 500-individual threshold, HHS Secretary and media-notice rules, business-associate obligations (§164.504(e)), and state pharmacy-board reporting.
- **Patient-safety-aware security** — downtime dispensing, paper-backup workflows, cold-chain monitoring, and insurance-billing continuity are treated as first-class containment constraints, not afterthoughts.
- **Practical tooling** — Python/Bash triage scripts that run on an air-gapped IR laptop with the standard library only.
- **Threat modeling** — the realistic small-pharmacy attack surface mapped to MITRE ATT&CK with a risk matrix.
- **Secure-by-default mindset** — synthetic data throughout, evidence preservation, least-privilege isolation, and explicit rollback paths.

## Repository layout

```
ransomware-ir-playbook/
├── README.md                          # you are here
├── docs/
│   ├── playbook.md                    # full NIST 800-61 IR playbook (healthcare-specific)
│   ├── quick-reference.md             # one-page first-24-hours runbook (print + tape to wall)
│   ├── tabletop-exercise.md           # Saturday-night ransomware scenario + injects + facilitator guide
│   └── threat-model.md                # attack-surface model, MITRE ATT&CK mapping, risk matrix
├── scripts/
│   ├── generate_sample_logs.py        # synthesize attack-progression Windows Event Log XML + JSON
│   ├── analyze_logs.py                # detect 12 ransomware indicator categories, score, MITRE-map
│   ├── check_iocs.py                  # match hashes/IPs/domains vs local IOC DB (air-gapped)
│   ├── hipaa_notification_calculator.py  # compute all HIPAA/state breach-notification deadlines
│   └── network_isolation.sh           # rapid segmentation (pfSense/OPNsense/UniFi/nftables) + rollback
├── data/                              # all synthetic, clearly flagged
│   ├── sample_network_topology.json
│   ├── sample_system_inventory.json
│   ├── sample_phi_records.json        # fictional patients, "_synthetic": true on every record
│   └── known_ransomware_iocs.json     # LockBit/BlackCat/Hive/Royal TTP profiles (indicator values are placeholders)
├── tests/                             # pytest: deadline math, IOC matching, generate -> detect pipeline
├── LICENSE                            # MIT
└── templates/
    ├── hipaa_breach_notification_template.md
    ├── business_associate_notification_template.md
    ├── press_release_template.md
    └── incident_ticket_template.md
```

## How to run

All scripts use the **Python 3 standard library only** — no `pip install`, so they run on an isolated/air-gapped incident-response laptop.

```bash
cd scripts

# 1. Generate a synthetic ransomware attack log set (Windows Event Log XML + JSON timeline)
python3 generate_sample_logs.py            # writes sample_logs.xml + sample_logs_timeline.json (--out-dir to redirect)

# 2. Analyze those logs for ransomware indicators -> JSON timeline + Markdown IR report
python3 analyze_logs.py sample_logs.xml

# 3. Cross-reference observed hashes/IPs/domains against the local IOC database (synthetic demo)
python3 check_iocs.py

# 4. Calculate HIPAA breach-notification deadlines for a hypothetical incident
python3 hipaa_notification_calculator.py --date 2026-06-15 --count 1200 --state CA

# 5. (Review only — do not run live) network isolation playbook script
bash -n network_isolation.sh   # syntax check; the script is documentation-grade and gated by pre-flight checks

# Tests (from the project root; pytest is the only non-stdlib dependency and is test-only)
cd .. && pip install pytest && pytest tests/ -v
```

Run any script with `-h` for full options. `generate_sample_logs.py` and `check_iocs.py` run straight from synthetic data; `analyze_logs.py` takes a log file and `hipaa_notification_calculator.py` takes incident parameters.

## Threat model / security rationale (summary)

The full model is in [`docs/threat-model.md`](docs/threat-model.md). In short, the modeled pharmacy's highest-risk exposures are:

| Exposure | Example | MITRE ATT&CK |
|---|---|---|
| RDP reachable over VPN | Initial access via stolen/phished creds | T1133, T1078 |
| Legacy Win7 pill-counter | Unpatched EOL host, no EDR | T1210 |
| IoT temp sensors, default creds | Pivot + cold-chain sabotage | T1078.001 |
| Backup drive on same LAN | Backups encrypted with production | T1490 |
| Phishing-prone staff | Macro/credential phishing | T1566 |

The playbook's phases are explicitly justified against these: e.g., containment prioritizes pulling the VPN and isolating the IoT VLAN *before* wiping, because cold-chain telemetry is both an attack vector and patient-safety evidence.

## Skills demonstrated

`Incident Response` · `NIST SP 800-61` · `HIPAA Breach Notification Rule` · `Healthcare security & PHI handling` · `MITRE ATT&CK mapping` · `Threat modeling` · `Windows Event Log / Sysmon analysis` · `IOC hunting` · `Python (stdlib)` · `Bash / network segmentation` · `Tabletop exercise design` · `Technical writing for non-technical stakeholders`

## Honest scope notes

- **This is a student portfolio project**, not a production-certified IR plan. A real pharmacy should have counsel and a qualified IR firm review any plan before adopting it.
- **All data is synthetic.** No real PHI, patient names, NPIs, employer data, or secrets appear anywhere. Patient records carry an explicit `"_synthetic": true` flag.
- **IOC data is illustrative.** Family profiles, TTPs and defenses in `data/known_ransomware_iocs.json` are summarized from public CISA/FBI advisories, but the hash, domain and IP values are placeholders shaped like real indicators — not verified intelligence. `check_iocs.py` ships with an embedded, explicitly fabricated demo database.
- I am a CPhT and a cybersecurity student. I do **not** hold a security certification yet, and nothing here claims otherwise. The healthcare/PHI/HIPAA operational knowledge is grounded in my actual pharmacy-technician experience; the security framing is applied coursework + self-study.
- The tooling is intentionally simple and stdlib-only so it's auditable and runnable on a clean IR laptop — it is not a replacement for commercial EDR/DFIR tooling.

---

*Built as part of my transition from pharmacy operations into cybersecurity. Companion project: [Privacy-First LLM-Driven Bodybuilding Auditor](https://github.com/Phan-Vincent) (secure key management, local encryption, input validation, least-privilege, AI data-leakage mitigation).*
