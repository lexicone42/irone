# Scenario 1: Compromised IAM Access Keys

## Situation

**Alert**: `detect-cross-account-role-assumption` fired at 14:47 UTC
**Severity**: High
**MITRE**: T1078.004 (Valid Accounts: Cloud Accounts)

A developer's access key (`AKIA3EXAMPLE1234`) was compromised via a phishing email
containing a fake AWS SSO login page. The attacker used the stolen credentials from
an IP in Romania (ASN AS9009, M247 Ltd) to assume cross-account roles and enumerate
the environment.

## Timeline of Events

```
14:32 UTC  AKIA3EXAMPLE1234 authenticates from 185.220.101.42 (Romania, M247)
           → Previously only seen from 10.0.0.0/8 (corporate VPN)
14:33      sts:GetCallerIdentity (reconnaissance — "who am I?")
14:34      iam:ListRoles, iam:ListPolicies (enumeration)
14:35      iam:ListAttachedUserPolicies (checking own permissions)
14:36      sts:AssumeRole → role/production-data-reader (cross-account)
14:37      s3:ListBuckets (discovering targets in prod account)
14:38      s3:GetObject × 47 (exfil from prod-analytics-data bucket)
14:39      s3:GetObject × 12 (customer-pii-exports bucket)
14:41      iam:CreateAccessKey (creating persistence — new key AKIA7BACKDOOR)
14:42      iam:AttachUserPolicy → AdministratorAccess (privilege escalation)
14:43      cloudtrail:PutEventSelectors (reducing logging scope — defense evasion)
14:47      Detection fires on cross-account role assumption
```

## Investigation Graph

```
Nodes (18):
  Principals:  dev-user-alice (IAMUser), role/production-data-reader (AssumedRole)
  IPs:         185.220.101.42 (Romania, M247), 10.0.1.15 (historical VPN)
  Resources:   prod-analytics-data (S3), customer-pii-exports (S3),
               AdministratorAccess (IAMPolicy), CloudTrail trail/main
  Operations:  GetCallerIdentity, ListRoles, ListPolicies, AssumeRole,
               ListBuckets, GetObject, CreateAccessKey, AttachUserPolicy,
               PutEventSelectors

Edges (24):
  dev-user-alice → AUTHENTICATED_FROM → 185.220.101.42
  dev-user-alice → CALLED_API → GetCallerIdentity, ListRoles, ListPolicies
  dev-user-alice → CALLED_API → AssumeRole → ACCESSED_RESOURCE → production-data-reader
  production-data-reader → CALLED_API → ListBuckets, GetObject
  GetObject → ACCESSED_RESOURCE → prod-analytics-data (47 events)
  GetObject → ACCESSED_RESOURCE → customer-pii-exports (12 events)
  dev-user-alice → CALLED_API → CreateAccessKey (persistence)
  dev-user-alice → CALLED_API → AttachUserPolicy → AdministratorAccess
  dev-user-alice → CALLED_API → PutEventSelectors → CloudTrail trail/main
```

## Graph Patterns Detected

1. **PrivilegeFanout** (severity: 0.85)
   - `dev-user-alice` accessed 7 distinct services (IAM, STS, S3, CloudTrail, etc.)
   - Analysis hint: "Principal accessed 7 services in 11 minutes. Typical for
     automated enumeration; legitimate developers rarely touch IAM + CloudTrail
     + S3 in a single short session."

2. **MultiSourceAuth** (severity: 0.95)
   - `dev-user-alice` authenticated from both 185.220.101.42 and 10.0.1.15
   - Analysis hint: "Principal has authentication from 2 external IPs including
     new geo (Romania). Check for impossible travel."

## Anomaly Scores (MAD-based)

```
dev-user-alice  (user)  events: 74  median: 12  MAD: 4.2  z-score: 9.95 [OUTLIER]
185.220.101.42  (ip)    events: 74  median: 3   MAD: 1.5  z-score: 31.9 [OUTLIER]
```

## Attack Path Narrative

**Path 1: Credential Theft → Enumeration → Data Exfil → Persistence**
- Phases: Initial Access → Discovery → Collection → Persistence → Defense Evasion
- Entry point: 185.220.101.42 (Romania)
- Actor: dev-user-alice (compromised)
- Impact: 59 objects exfiltrated from 2 S3 buckets (including PII),
  AdministratorAccess policy attached, new access key created for persistent access,
  CloudTrail logging reduced

## Claude AI Analysis (expected output)

```json
{
  "verdict": "true_positive",
  "confidence": 0.96,
  "mitre_techniques": ["T1078.004", "T1087.004", "T1530", "T1098.001", "T1562.008"],
  "kill_chain_phases": [
    "Initial Access",
    "Discovery",
    "Collection",
    "Persistence",
    "Defense Evasion"
  ],
  "blast_radius": "2 AWS accounts (dev + prod), 2 S3 buckets with PII, IAM admin access",
  "executive_summary": "High-confidence credential compromise of dev-user-alice. An attacker operating from Romania used stolen access keys to enumerate IAM, assume a cross-account production role, exfiltrate data from S3 buckets containing PII, establish persistence via a new access key and admin policy, and reduce CloudTrail logging scope.",
  "key_findings": [
    "New source IP 185.220.101.42 (Romania, M247) — never seen for this user",
    "Full MITRE kill chain from Initial Access through Defense Evasion in 11 minutes",
    "59 S3 objects exfiltrated including customer-pii-exports bucket",
    "Persistence established: new access key AKIA7BACKDOOR + AdministratorAccess",
    "Defense evasion: CloudTrail PutEventSelectors reduced logging scope"
  ],
  "recommended_actions": [
    {
      "priority": 1,
      "action": "Deactivate both access keys for dev-user-alice (AKIA3EXAMPLE1234 and AKIA7BACKDOOR)",
      "rationale": "Original key is compromised, backdoor key was created by attacker",
      "automatable": true
    },
    {
      "priority": 2,
      "action": "Detach AdministratorAccess policy from dev-user-alice",
      "rationale": "Attacker elevated to admin — revert to original permissions",
      "automatable": true
    },
    {
      "priority": 3,
      "action": "Restore CloudTrail event selectors to full logging",
      "rationale": "Attacker reduced logging to hide subsequent activity",
      "automatable": true
    },
    {
      "priority": 4,
      "action": "Invalidate all sessions for production-data-reader role",
      "rationale": "Role was assumed by compromised credentials — may have active sessions",
      "automatable": true
    },
    {
      "priority": 5,
      "action": "Initiate data breach assessment for customer-pii-exports bucket",
      "rationale": "PII was accessed — may trigger notification obligations",
      "automatable": false
    }
  ],
  "follow_up_questions": [
    "Was 185.220.101.42 seen in any other account or user's authentication logs?",
    "What specific objects were downloaded from customer-pii-exports?",
    "Did the phishing email target other employees?",
    "Were there any API calls after PutEventSelectors that we're now missing?"
  ],
  "detection_improvements": [
    "Add impossible-travel detection (IP geo-distance + time delta)",
    "Create correlation rule: AssumeRole + CreateAccessKey within 10 minutes",
    "Alert on PutEventSelectors regardless of severity (always defense evasion)"
  ]
}
```

## Playbook Triggered

**pb-credential-compromise** (auto-triggered by severity=High + tag=credential-access)

| Step | Action | Approval | Status |
|------|--------|----------|--------|
| 1 | Notify security team (PagerDuty) | Auto | Executed |
| 2 | Snapshot evidence (CloudTrail logs) | Auto | Executed |
| 3 | Revoke access keys | Auto | Executed |
| 4 | Isolate resource (detach admin policy) | **Manual** | Awaiting approval |

## Interview Talking Points

### Architecture Decisions
- **Why MAD over z-scores?** Standard z-scores are influenced by outliers. In security
  data with power-law distributions (service accounts with 100K events), z-scores suppress
  detection of human users with 200 events. MAD resists this — it's based on the median,
  not the mean.

- **Why OCSF?** The detection rule (`detect-cross-account-role-assumption`) works identically
  for AWS CloudTrail and GCP Audit Logs because OCSF normalizes both into the same schema.
  The rule filters on `api.operation` which maps to both `AssumeRole` (AWS) and
  `google.iam.v1.SetIamPolicy` (GCP).

- **Why graph-based investigation?** Traditional SIEM gives you a list of events. The
  graph shows *relationships* — the fact that the same principal touched IAM, S3, and
  CloudTrail in sequence, from a new IP, with privilege escalation in between. That
  topology is what makes this clearly malicious vs. a developer doing legitimate work.

- **Why playbook approval gates?** The first three actions (notify, snapshot, revoke) are
  low-risk and reversible — they can auto-execute. Isolation (step 4) has blast radius
  implications (could break production if the user's permissions are needed for running
  services), so it requires human approval.

### How to Narrate This

"I saw the cross-account role assumption alert fire. First thing I checked was the source
IP — 185.220.101.42, Romania, M247 hosting. This user has never authenticated from outside
our VPN. That immediately moves this from 'check it out' to 'active incident.'

The graph showed a textbook kill chain: recon (GetCallerIdentity), enumeration (ListRoles),
lateral movement (AssumeRole to production), collection (59 S3 GetObject calls including
our PII bucket), persistence (new access key + admin policy), and defense evasion
(PutEventSelectors to reduce logging). All in 11 minutes.

The pattern detector flagged PrivilegeFanout — 7 services in one session — and
MultiSourceAuth from the new Romanian IP. The MAD anomaly scorer gave this user a z-score
of 9.95, meaning they're almost 10 standard deviations from the median activity level.

Response was automated via playbook: PagerDuty notification went out immediately, evidence
was snapshotted, and both access keys were deactivated within 30 seconds of the playbook
triggering. The isolation step (detaching admin policy) was held for manual approval because
it could affect running services."
