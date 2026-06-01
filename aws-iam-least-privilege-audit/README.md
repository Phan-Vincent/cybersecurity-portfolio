# AWS IAM Least-Privilege Auditor

A Python security tool that audits AWS IAM configurations for overly permissive permissions, stale credentials, weak authentication, and over-privileged roles. Designed for SOC analysts and security engineers who need fast, actionable IAM posture assessments.

**Author:** Vincent Phan  
**Background:** CVS Pharmacy Technician (CPhT) 2020–present, transitioning to BS IS Cybersecurity at CSU San Bernardino (Fall 2026). Built this tool to demonstrate practical cloud security skills for remote SOC analyst / security engineer roles.

---

## Problem Statement

AWS IAM is the front door to every AWS resource. Misconfigured IAM policies are a leading cause of cloud breaches — from the 2019 Capital One incident (overly permissive WAF role) to countless S3 bucket leaks caused by `s3:*` wildcards. Yet many organizations lack a lightweight, repeatable way to audit IAM configurations.

In healthcare environments (HIPAA), IAM misconfigurations are especially dangerous because they can expose Protected Health Information (PHI) stored in S3, DynamoDB, or RDS. As a pharmacy technician who handles PHI daily under strict HIPAA protocols, I designed this tool with the same least-privilege mindset I apply to patient data access.

## What This Project Demonstrates

This project shows four things a hiring manager cares about:

1. **Cloud Security Domain Knowledge:** I understand IAM policy grammar, trust policies, cross-account risks, and the principle of least privilege.
2. **Python + boto3 Proficiency:** Real API calls, pagination, error handling, and data transformation — not toy scripts.
3. **Security Tooling Mindset:** Severity scoring, remediation guidance, multiple output formats (CLI, JSON, CSV) for different stakeholders.
4. **Safe Development Practices:** Mock mode for CI/CD, read-only operations, no production secrets in code, synthetic data only.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLI Entry Point                            │
│                    scripts/run_audit.py                              │
│                    (argparse: --mock, --format, --output)            │
└─────────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
            ┌──────────────┐      ┌──────────────┐
            │   Live AWS   │      │  Mock Mode   │
            │   (boto3)    │      │  (JSON files)│
            └──────────────┘      └──────────────┘
                    │                       │
                    └───────────┬───────────┘
                                ▼
            ┌───────────────────────────────────────┐
            │        aws_iam_auditor/auditor.py     │
            │   Orchestrator: collects data, runs   │
            │   all checks, returns findings list   │
            └───────────────────────────────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            │                   │                   │
            ▼                   ▼                   ▼
   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
   │  checks.py   │   │  checks.py   │   │  checks.py   │
   │ wildcard_actions│  │ unused_keys │   │ users_wo_mfa │
   └──────────────┘   └──────────────┘   └──────────────┘
            │                   │                   │
            ▼                   ▼                   ▼
   ┌──────────────┐   ┌──────────────────────────────────┐
   │  checks.py   │   │        report.py                 │
   │over_perm_roles│  │  Console table │ JSON │ CSV    │
   └──────────────┘   └──────────────────────────────────┘
```

### Data Flow

1. **Data Collection** (`auditor.py`): Either fetches live IAM data via `boto3` paginators or loads synthetic JSON from `data/`.
2. **Security Checks** (`checks.py`): Four independent check functions, each returning a list of `Finding` objects with severity and remediation.
3. **Report Generation** (`report.py`): Formats findings into console tables (color-coded), JSON (machine-readable), or CSV (spreadsheet-friendly).
4. **CLI** (`scripts/run_audit.py`): Orchestrates the whole flow with `argparse`.

---

## How to Run

### Prerequisites

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Mock Mode (No AWS Account Needed)

```bash
# Console table output (default)
python scripts/run_audit.py --mock

# JSON output
python scripts/run_audit.py --mock --format json

# CSV output to file
python scripts/run_audit.py --mock --format csv --output audit_report.csv
```

### Live AWS Mode (Read-Only)

Requires an AWS IAM user or role with **read-only IAM permissions**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListPolicies",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListVirtualMFADevices",
        "iam:ListAttachedRolePolicies",
        "iam:GetPolicyVersion",
        "iam:ListUserPolicies"
      ],
      "Resource": "*"
    }
  ]
}
```

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-west-2

python scripts/run_audit.py --format json --output live_audit.json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Audit passed, no critical findings |
| 1 | Runtime error (credentials missing, API failure) |
| 2 | Critical findings detected (useful for CI/CD gating) |

---

## Security Checks

| Check | What It Finds | Severity |
|-------|---------------|----------|
| **Wildcard Actions** | Policies with `Action: "*"` or `Action: "s3:*"` | CRITICAL / HIGH |
| **Unused Access Keys** | Keys >90 days old with no recent usage | HIGH / CRITICAL (>180d) |
| **Users Without MFA** | Human users lacking MFA devices | HIGH (CRITICAL for root) |
| **Over-Permissioned Roles** | Roles with broad trust policies or >5 attached policies | CRITICAL / HIGH / MEDIUM |

Each finding includes:
- **Severity:** Critical → Info, based on blast radius
- **Resource:** Exact IAM resource name
- **Message:** Human-readable description of the issue
- **Details:** Structured metadata (e.g., key age, last used service, policy ARN)
- **Remediation:** Specific, actionable fix guidance

---

## Skills Demonstrated

| Skill | Evidence |
|-------|----------|
| **Cloud Security (AWS IAM)** | Policy document parsing, trust policy analysis, cross-account risk assessment, MFA enforcement patterns |
| **Python Development** | boto3 API usage, dataclasses, type hints, pagination, error handling, CLI design with argparse |
| **Security Tooling** | Severity scoring, remediation guidance, multi-format reporting (JSON/CSV/console), CI/CD exit codes |
| **Least-Privilege Design** | The auditor itself uses read-only IAM permissions; mock mode prevents accidental production changes |
| **Testing & Quality** | pytest unit tests for all checks and report formats, synthetic test data, edge case coverage |
| **Documentation** | README with architecture diagram, threat model, honest scope notes, setup instructions |

---

## Honest Scope Notes

**What this tool does NOT do (yet):**
- Does not remediate findings automatically — it is read-only and audit-only.
- Does not check IAM policy conditions beyond ExternalId detection.
- Does not analyze resource-based policies (S3 bucket policies, KMS key policies, etc.).
- Does not integrate with AWS IAM Access Analyzer or AWS Config.
- Does not perform historical trend analysis or drift detection.

**Plausible next steps:**
- Add SCP (Service Control Policy) analysis for AWS Organizations.
- Integrate with AWS IAM Access Analyzer to flag unused permissions.
- Add Terraform/state file parsing to audit IaC-defined IAM before deployment.
- Build a GitHub Actions workflow that runs this on PRs containing IAM changes.

---

## Candidate Background Context

I'm a pharmacy technician (CPhT) at CVS with 5+ years of experience handling PHI under HIPAA. I've seen firsthand how over-permissioned access leads to compliance incidents — whether it's a pharmacist accessing records outside their shift or a temp contractor retaining credentials after their contract ends. That same zero-trust, least-privilege mindset drives this tool.

I'm also a self-taught builder: I run an OpenClaw AI home lab on Apple Silicon, maintain a public GitHub project on privacy-first LLM auditing (secure key management, local encryption, input validation), and I'm starting a BS in Information Systems with Cybersecurity concentration at CSU San Bernardino in Fall 2026. My goal is a remote SOC analyst or security engineer role where I can apply this combination of hands-on healthcare compliance experience and cloud security tooling.

---

## License

MIT License — free to use, modify, and learn from.
