# Threat Model: AWS IAM Least-Privilege Auditor

## 1. Risks Addressed

This tool directly addresses four high-frequency, high-impact IAM misconfiguration risks that appear in real-world cloud breaches and compliance audits:

### 1.1 Overly Permissive IAM Policies (Wildcard Actions)
**Risk:** Policies with `Action: "*"` or `Action: "s3:*"` grant far more permissions than the principal needs. If a credential with such a policy is compromised, the attacker gains broad access — not just to the intended resource, but to everything in the account.

**Healthcare Context:** In a HIPAA environment, a `dynamodb:*` or `s3:*` policy on an application role could allow an attacker to read, modify, or delete entire patient databases. Even a well-intentioned developer testing locally with admin credentials creates a persistent attack surface.

**Detection:** The auditor parses every policy statement's `Action` field and flags exact `*` and service-level `:*` wildcards.

### 1.2 Stale / Unused Access Keys
**Risk:** Long-lived access keys that haven't been used in months or years are easy to forget about. If leaked (via a committed `.env` file, a compromised laptop, or a supply-chain attack), they provide stealthy, persistent access because no one is monitoring them.

**Healthcare Context:** A service account key created for a one-time ETL job in 2022 and never rotated could still access PHI-containing S3 buckets in 2025. The 90-day threshold aligns with AWS's own security best practices and PCI-DSS requirement 8.2.4.

**Detection:** The auditor checks key age and `LastUsedDate`, flagging keys >90 days unused with escalating severity for >180 days.

### 1.3 Missing Multi-Factor Authentication (MFA)
**Risk:** Password-only authentication is vulnerable to phishing, credential stuffing, and brute-force attacks. A single compromised developer password without MFA can lead to full account takeover.

**Healthcare Context:** NIST 800-63 and HIPAA both strongly recommend MFA for any access to systems containing PHI. A root account without MFA is a single point of total failure for the entire AWS organization.

**Detection:** The auditor cross-references users against registered virtual MFA devices and flags any user without MFA. Root accounts are flagged CRITICAL; regular users are HIGH.

### 1.4 Overly Broad Trust Policies (Role Assumption)
**Risk:** A role with `Principal: { AWS: "*" }` or `Principal: { Service: "*" }` can be assumed by any AWS principal or service, respectively. This enables cross-account lateral movement, confused-deputy attacks, and unintended privilege escalation.

**Healthcare Context:** A third-party analytics vendor integration with a broad trust policy and no `ExternalId` condition could allow an attacker who compromises the vendor's AWS account to assume the role and access the healthcare organization's PHI datasets.

**Detection:** The auditor inspects `AssumeRolePolicyDocument` statements for `Principal: "*"`, `Principal.AWS: "*"`, `Principal.Service: "*"`, and missing `ExternalId` on cross-account trusts. It also flags role policy bloat (>5 attached policies) as a MEDIUM finding.

---

## 2. How Mock Mode Protects Against Accidental Changes

The `--mock` flag is not just a demo feature — it is a **safety control**:

- **No Network Calls:** Mock mode loads local JSON files from `data/` and never initializes a boto3 client. There is zero risk of accidental API calls.
- **No AWS Credentials Required:** You can run this in CI/CD pipelines, on a fresh laptop, or in a classroom lab without configuring AWS credentials at all.
- **Deterministic Output:** Synthetic data is fixed, so tests produce the same results every time. This is essential for regression testing and for teaching/demonstrating the tool's behavior without exposing real account data.
- **Read-Only by Design:** Even in live mode, the auditor only uses IAM **List** and **Get** API calls. No `Create`, `Delete`, `Put`, or `Update` operations are ever called. The tool is architecturally incapable of modifying IAM state.
- **No Real Data Exfiltration:** The tool outputs to stdout or local files only. No telemetry, no third-party APIs, no cloud logging services. Findings never leave the machine unless the user explicitly copies the output.

---

## 3. Least-Privilege Principle Applied to the Auditor Itself

The auditor practices what it preaches:

### 3.1 Minimal IAM Permissions (Live Mode)
The auditor requires only the following **read-only** IAM permissions:

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

No `iam:*` wildcard. No `s3:`, `ec2:`, or other service permissions. The auditor cannot read data, modify resources, or escalate privileges.

### 3.2 No Credential Storage
The tool never stores AWS credentials. It relies on the standard boto3 credential chain (environment variables, `~/.aws/credentials`, or IAM instance profiles). No hardcoded keys, no config files committed to the repo, no secrets in logs.

### 3.3 Synthetic Data Only
All test data in `data/` is fictional:
- Fake AWS account IDs (`123456789012`, `999999999999`)
- Fake access key IDs (`AKIAIOSFODNN7EXAMPLE*`)
- Fake user names (`admin-sarah`, `dev-jake`)
- No real PHI, no real PII, no real credentials

### 3.4 Safe Defaults
- `--mock` is **not** the default, but the tool fails gracefully with a clear error if AWS credentials are missing, guiding the user toward mock mode.
- Exit code `2` signals critical findings, which CI/CD pipelines can gate on without risking automatic remediation.
- Console output uses `--no-color` for log ingestion systems that don't support ANSI codes.

---

## 4. Attack Scenarios This Tool Helps Prevent

| Scenario | How the Auditor Helps |
|----------|----------------------|
| **Credential leak from old dev laptop** | Flags unused access keys for deletion |
| **Compromised developer password** | Flags missing MFA; recommends IAM policy enforcement |
| **Third-party vendor breach** | Flags roles without `ExternalId` on cross-account trusts |
| **S3/DynamoDB data leak** | Flags `s3:*` / `dynamodb:*` wildcards in policies |
| **Lateral movement via assumed role** | Flags `Principal: "*"` and broad service principals |
| **Policy accumulation over time** | Flags roles with >5 attached policies (policy bloat) |

---

## 5. Known Limitations & Trust Boundaries

- **Trust Boundary:** The auditor assumes the machine running it is trusted. If the machine is compromised, the output (which lists vulnerable IAM resources) could aid an attacker. Run this on a secure, hardened workstation.
- **False Negatives:** The auditor does not check resource-based policies (S3 bucket policies, KMS key policies, Lambda resource policies). A locked-down IAM role can still be bypassed by a permissive bucket policy.
- **Scope:** This is a point-in-time assessment, not continuous monitoring. IAM drift can happen between audits. For production, pair this with AWS IAM Access Analyzer and AWS Config.
- **No Remediation:** The tool detects but does not fix. Remediation requires human judgment — especially in production, where removing a policy might break a critical service.
