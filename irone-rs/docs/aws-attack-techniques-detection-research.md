# AWS Attack Techniques & Detection Opportunities

Research notes from [hackingthe.cloud](https://hackingthe.cloud/) — AWS section only.

Goal: identify detection rules we should build for irone, mapped against what we already have.

---

## Current Detection Coverage (17 rules)

| Rule File | What It Detects |
|---|---|
| `access-key-created.yaml` | New IAM access key creation |
| `api-permission-enumeration.yaml` | Bulk API call patterns (enumerate-iam style) |
| `canary-lambda-invoke.yaml` | Canary Lambda invoked |
| `canary-sts-identity.yaml` | Canary STS GetCallerIdentity |
| `cognito-auth-failure-spike.yaml` | Cognito authentication failures |
| `console-login-new-ip.yaml` | Console login from new IP |
| `dns-tunneling.yaml` | DNS tunneling patterns |
| `github-oidc-unexpected-repo.yaml` | Unexpected GitHub OIDC federation |
| `iam-privilege-escalation.yaml` | IAM privilege escalation API calls |
| `lambda-execution-failure.yaml` | Lambda execution failures |
| `lambda-invocation-spike.yaml` | Lambda invocation spikes |
| `large-outbound-transfer.yaml` | Large data transfers (exfil) |
| `mfa-device-change.yaml` | MFA device modifications |
| `nxdomain-spike.yaml` | NXDOMAIN spikes |
| `port-scan-detection.yaml` | Port scanning activity |
| `root-console-login.yaml` | Root account console login |
| `security-hub-critical.yaml` | Security Hub critical findings |

---

## Gap Analysis: Techniques Not Covered

### Priority 1 — High Impact, Feasible to Detect

#### 1. GuardDuty Tampering
**Technique**: Attacker disables GuardDuty detector, adds their IP to trusted IP list, creates suppression filters, or deletes publishing destinations. This is Defense Evasion at its most direct — blinding the monitoring.

**API calls to detect**:
- `guardduty:UpdateDetector` (especially with `--no-enable`)
- `guardduty:CreateIPSet` / `guardduty:UpdateIPSet`
- `guardduty:CreateFilter` (suppression rules)
- `guardduty:DeletePublishingDestination`
- `events:PutRule` / `events:RemoveTargets` (disabling CloudWatch alerting rules)

**Detection approach**: Any modification to GuardDuty configuration should be rare and alarming. Simple OCSF event_class filter on these API names. Threshold: 1 (any occurrence is suspicious).

**MITRE**: Defense Evasion (T1562.001 — Impair Defenses: Disable or Modify Tools)

---

#### 2. CloudTrail Tampering (expanded)
**Technique**: Attacker stops logging, deletes trails, modifies event selectors to exclude specific event sources. We annotate this in narrative context but have no detection rule.

**API calls to detect**:
- `cloudtrail:StopLogging`
- `cloudtrail:DeleteTrail`
- `cloudtrail:PutEventSelectors` (reducing scope)
- `cloudtrail:UpdateTrail` (redirecting to attacker bucket)

**Detection approach**: Any of these calls is an immediate high-severity alert. Threshold: 1.

**MITRE**: Defense Evasion (T1562.008 — Impair Defenses: Disable or Modify Cloud Logs)

---

#### 3. S3 Replication Exfiltration
**Technique**: Attacker configures bucket replication to copy data to an attacker-controlled bucket in another account. Works for both future objects (continuous) and existing objects (via S3 Batch).

**API calls to detect**:
- `s3:PutBucketReplication`
- `s3:PutBucketVersioning` (prerequisite — suspicious if not already enabled)
- S3 Batch `CreateJob` with replication operations

**Detection approach**: `PutBucketReplication` is almost never called in normal operations. Any occurrence on a data bucket warrants investigation. Cross-account destination is especially suspicious.

**MITRE**: Exfiltration (T1537 — Transfer Data to Cloud Account)

---

#### 4. Role Chain Juggling (Persistence via Repeated AssumeRole)
**Technique**: Attacker chains `sts:AssumeRole` calls in a loop, each refreshing credential expiration. Can use circular trust policies (Role A trusts Role B trusts Role A) to maintain indefinite access even after original credentials are revoked.

**API calls to detect**:
- Repeated `sts:AssumeRole` from the same principal within short windows
- AssumeRole targeting the same role repeatedly
- Circular patterns: A assumes B, B assumes A

**Detection approach**: Count AssumeRole calls per principal per hour. Threshold: > 10 in 1 hour from same source suggests juggling. Also flag any principal assuming the same role > 3 times in 1 hour.

**MITRE**: Persistence (T1078.004 — Valid Accounts: Cloud Accounts)

---

#### 5. GetFederationToken Persistence
**Technique**: Attacker calls `sts:GetFederationToken` to generate temporary credentials that survive access key deletion. Even after the compromised key is deactivated, the federation token remains valid.

**API calls to detect**:
- `sts:GetFederationToken`

**Detection approach**: This API is rarely used in normal operations. Any call warrants investigation, especially with `--duration-seconds` > 3600 or with `AdministratorAccess` policy attachment. Threshold: 1.

**MITRE**: Persistence (T1078.004), also Credential Access (T1550.001 — Use Alternate Authentication Material)

---

#### 6. Rogue OIDC Identity Provider
**Technique**: Attacker registers their own OIDC provider in the victim's account, then modifies role trust policies to allow assumption via attacker-controlled tokens.

**API calls to detect**:
- `iam:CreateOpenIDConnectProvider` (new OIDC provider — rare event)
- `iam:UpdateAssumeRolePolicy` with OIDC principal

**Detection approach**: New OIDC provider creation is extremely rare. Alert on any `CreateOpenIDConnectProvider` call. Also flag `UpdateAssumeRolePolicy` changes that add external OIDC providers.

**MITRE**: Persistence (T1098.001 — Account Manipulation: Additional Cloud Credentials)

---

#### 7. IAM Roles Anywhere Abuse
**Technique**: Attacker registers a malicious Certificate Authority as a trust anchor, creates a profile, and generates AWS credentials from outside AWS using X.509 certificates.

**API calls to detect**:
- `rolesanywhere:CreateTrustAnchor`
- `rolesanywhere:CreateProfile`
- `iam:UpdateAssumeRolePolicy` adding `rolesanywhere.amazonaws.com`

**Detection approach**: Trust anchor creation is rare infrastructure provisioning. Any occurrence outside of known deployment windows is suspicious.

**MITRE**: Persistence (T1098.001)

---

### Priority 2 — Medium Impact, Moderate Detection Complexity

#### 8. ECR Image Poisoning (Lateral Movement)
**Technique**: Attacker pulls Docker image from ECR, injects malicious code, pushes back with same tag ("latest"). Next deployment pulls the compromised image.

**API calls to detect**:
- `ecr:PutImage` from unexpected principals
- Tag overwrites (same tag, different digest)
- `ecr:GetDownloadUrlForLayer` followed shortly by `ecr:PutImage` from same principal

**Detection approach**: Monitor for image push events from non-CI/CD principals. Flag any tag that's overwritten within a short window. Requires knowing which principals are authorized pushers.

**MITRE**: Lateral Movement (T1525 — Implant Internal Image)

---

#### 9. SSM Command Execution (Post-Exploitation)
**Technique**: Attacker uses SSM SendCommand to execute shell commands on EC2 instances. Critically, the actual command content is hidden in CloudTrail (`HIDDEN_DUE_TO_SECURITY_REASONS`).

**API calls to detect**:
- `ssm:SendCommand` from non-automation principals
- `ssm:StartSession` from unexpected sources
- Use of alternative SSM documents: `AWS-RunSaltState`, `AWS-ApplyAnsiblePlaybooks`, `AWS-RunRemoteScript`, `AWS-RunDocument`

**Detection approach**: SSM commands from human IAM users (not automation roles) are suspicious. Alert on SendCommand from principals that don't normally use it.

**MITRE**: Execution (T1059 — Command and Scripting Interpreter)

---

#### 10. S3 ACL Backdoor
**Technique**: Attacker modifies bucket or object ACLs to grant cross-account access, maintaining persistent data access even after IAM policy remediation.

**API calls to detect**:
- `s3:PutBucketAcl`
- `s3:PutObjectAcl`
- `s3:PutObjectVersionAcl`

**Detection approach**: ACL modifications are rare in modern AWS (ACLs disabled by default since April 2023). Any ACL write is suspicious. Especially flag grants to external accounts or "AuthenticatedUsers" / "AllUsers" groups.

**MITRE**: Persistence (T1098)

---

#### 11. Console Session from Stolen Credentials
**Technique**: Attacker converts CLI credentials to console access via federation URL signing. Creates interactive session for manual exploration.

**API calls to detect**:
- `sts:GetFederationToken` followed by `ConsoleLogin` event
- `ConsoleLogin` from unusual user agents
- Console access from principals that normally only use API/CLI

**Detection approach**: Correlate GetFederationToken calls with subsequent ConsoleLogin events. Flag console access from service roles or automation accounts.

**MITRE**: Defense Evasion (T1550.001 — Use Alternate Authentication Material)

---

#### 12. S3 Server Access Log Exfiltration
**Technique**: Attacker encodes data in S3 GetObject request keys, which get logged even on 403 failures. Logs route to attacker-controlled bucket.

**API calls to detect**:
- Repeated `s3:GetObject` 403s with unusual key patterns
- `s3:PutBucketLogging` pointing to external buckets

**Detection approach**: Alert on PutBucketLogging changes. Flag high-volume GetObject failures with long/unusual key names from the same source.

**MITRE**: Exfiltration (T1567 — Exfiltration Over Web Service)

---

#### 13. AWS CLI Endpoint Hijacking (Living off the Land)
**Technique**: Attacker uses `aws s3 --endpoint-url https://attacker.com` to redirect S3 operations to attacker-controlled MinIO/S3-compatible stores for C2 and exfil. Blends with normal AWS CLI usage.

**API calls to detect**: Difficult via CloudTrail alone (the redirected calls don't hit AWS). Better detected via:
- VPC flow logs showing S3-like traffic to non-AWS IPs
- Network firewall rules for S3 endpoint traffic

**Detection approach**: Network-level — flag S3 API traffic (port 443, S3 TLS SNI) to non-AWS IP ranges. Requires VPC Flow Log or DNS query analysis.

**MITRE**: Command and Control (T1102 — Web Service)

---

### Priority 3 — Good to Have, Lower Frequency

#### 14. Organizations Pivoting via OrganizationAccountAccessRole
**Technique**: Compromising the management account grants `AdministratorAccess` to every member account via the default `OrganizationAccountAccessRole`.

**API calls to detect**:
- `sts:AssumeRole` with role name `OrganizationAccountAccessRole`
- Rapid sequential AssumeRole across multiple accounts

**Detection approach**: This role should rarely be assumed manually. Alert on any assumption from non-automation sources.

**MITRE**: Lateral Movement (T1021.007 — Remote Services: Cloud Services)

---

#### 15. Cognito Self-Signup Abuse
**Technique**: Attacker discovers Cognito Client ID in frontend code and programmatically creates accounts when self-signup isn't disabled.

**API calls to detect**:
- `cognito-idp:SignUp` from non-application sources
- Rapid account creation patterns

**Note**: We already have `cognito-auth-failure-spike.yaml` which partially covers this. Could extend to also flag unusual signup volume.

**MITRE**: Initial Access (T1078.004)

---

#### 16. Lambda Runtime Persistence
**Technique**: Attacker modifies Lambda runtime files (`bootstrap.py`, `runtime.rb`) in the execution environment to backdoor subsequent invocations. Persists until container goes cold (5-15 min idle).

**API calls to detect**: Not directly visible in CloudTrail. Detection requires:
- Lambda function code hash changes without corresponding `UpdateFunctionCode` calls
- Unusual outbound network connections from Lambda
- Runtime API anomalies

**Detection approach**: Compare Lambda code SHA256 at deploy vs at execution. Hard to detect purely from CloudTrail.

**MITRE**: Persistence (T1546 — Event Triggered Execution)

---

#### 17. Permission Boundary Removal
**Technique**: Attacker removes permission boundaries that restrict their access, effectively elevating privileges.

**API calls to detect**:
- `iam:DeleteRolePermissionsBoundary`
- `iam:DeleteUserPermissionsBoundary`
- `iam:PutRolePermissionsBoundary` / `iam:PutUserPermissionsBoundary` (replacing with permissive boundary)

**Note**: Partially covered by `iam-privilege-escalation.yaml` depending on its current filter set. Worth checking.

**MITRE**: Privilege Escalation (T1548)

---

## Detection Evasion Techniques to Be Aware Of

These are harder to detect but important for understanding attacker tradecraft:

| Technique | How It Works | Why It's Hard to Detect |
|---|---|---|
| User-Agent spoofing | Change `AWS_EXECUTION_ENV` to avoid pentest tool fingerprinting | GuardDuty key-based, easily spoofed |
| Tor bridges | Use unlisted Tor bridge nodes instead of public Tor network | GuardDuty only checks public node list |
| VPC endpoint credential use | Stolen EC2 creds used from another EC2 via VPC endpoints | GuardDuty now detects for 26+ services (as of Oct 2024), but not all |
| SSM command hiding | SSM command content marked `HIDDEN_DUE_TO_SECURITY_REASONS` in CloudTrail | Can detect the SendCommand event, but not the payload |
| SQS for whoami | `sqs:ListQueues` reveals account info without CloudTrail logging | Not all services log to CloudTrail |

---

## Recommended Implementation Order

Based on impact, feasibility, and gap severity:

1. ~~**GuardDuty Tampering**~~ — **IMPLEMENTED** → `guardduty-tampering.yaml`
2. ~~**CloudTrail Tampering**~~ — **IMPLEMENTED** → `cloudtrail-tampering.yaml`
3. ~~**S3 Replication Exfiltration**~~ — **IMPLEMENTED** → `s3-replication-exfil.yaml`
4. ~~**GetFederationToken Persistence**~~ — **IMPLEMENTED** → `get-federation-token.yaml`
5. ~~**Role Chain Juggling**~~ — **IMPLEMENTED** → `role-chain-juggling.yaml`
6. ~~**Rogue OIDC Provider**~~ — **IMPLEMENTED** → `rogue-oidc-provider.yaml`
7. ~~**IAM Roles Anywhere Abuse**~~ — **IMPLEMENTED** → `iam-roles-anywhere-abuse.yaml`
8. **ECR Image Poisoning** — important for container workloads
9. **SSM Command Execution** — post-exploitation detection
10. **S3 ACL Backdoor** — persistence mechanism

---

## Source

All techniques documented from [hackingthe.cloud](https://hackingthe.cloud/) AWS section, authored primarily by Nick Frichette and community contributors. Cross-referenced with MITRE ATT&CK Cloud Matrix.
