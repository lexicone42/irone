# Scenario 3: Insider Data Exfiltration

## Situation

**Alert**: `detect-s3-data-collection` fired at 22:14 UTC
**Severity**: Medium (initially - upgraded after investigation)
**MITRE**: T1530 (Data from Cloud Storage Object)

A senior engineer with legitimate S3 access begins downloading large volumes of
proprietary data 2 weeks before their resignation date. The activity is technically
authorized (their IAM role grants read access) but the pattern is anomalous: late-night
bulk downloads from buckets they haven't accessed in months.

This is the hardest scenario type for automated detection because every individual
API call is authorized. Only the aggregate pattern is suspicious.

## Timeline of Events

```
22:01 UTC  engineer-bob authenticates from home IP 203.0.113.55 (US, Comcast)
           Normal - remote work pattern matches historical
22:02      s3:ListBuckets - 23 buckets enumerated (first time in 4 months)
22:04      s3:ListObjectsV2 on ml-training-datasets (first access ever)
22:05      s3:GetObject x 340 from ml-training-datasets (2.1 GB)
22:15      s3:ListObjectsV2 on product-roadmap-docs
22:16      s3:GetObject x 89 from product-roadmap-docs (450 MB)
22:23      s3:ListObjectsV2 on customer-contracts
22:24      s3:GetObject x 156 from customer-contracts (1.8 GB)
22:31      s3:ListObjectsV2 on source-code-archives
22:32      s3:GetObject x 412 from source-code-archives (5.2 GB)
22:40      s3:ListObjectsV2 on employee-compensation-data
22:41      s3:GetObject x 23 from employee-compensation-data (120 MB)
           Total: 1,020 objects, 9.67 GB across 5 buckets in 40 minutes
22:14      Detection fires on S3 data collection pattern
```

## Investigation Graph

```
Nodes (14):
  Principals:  engineer-bob (IAMUser, team: ml-platform)
  IPs:         203.0.113.55 (US, Comcast, residential - matches history)
  Resources:   ml-training-datasets, product-roadmap-docs, customer-contracts,
               source-code-archives, employee-compensation-data (all S3)
  Operations:  ListBuckets, ListObjectsV2, GetObject

Edges (18):
  engineer-bob - AUTHENTICATED_FROM - 203.0.113.55
  engineer-bob - CALLED_API - ListBuckets
  engineer-bob - CALLED_API - ListObjectsV2 (5x, one per bucket)
  engineer-bob - CALLED_API - GetObject
  GetObject - ACCESSED_RESOURCE - ml-training-datasets (340 events)
  GetObject - ACCESSED_RESOURCE - product-roadmap-docs (89 events)
  GetObject - ACCESSED_RESOURCE - customer-contracts (156 events)
  GetObject - ACCESSED_RESOURCE - source-code-archives (412 events)
  GetObject - ACCESSED_RESOURCE - employee-compensation-data (23 events)
```

## Graph Patterns Detected

1. **PrivilegeFanout** (severity: 0.75)
   - `engineer-bob` accessed 5 distinct S3 buckets across different data domains
   - Analysis hint: "Single principal accessing 5 buckets spanning ML data, roadmap,
     contracts, source code, and compensation in one session. Typical engineers
     access 1-2 buckets related to their team."

## Anomaly Scores (MAD-based)

```
engineer-bob    (user)  events: 1020  median: 45  MAD: 18.5  z-score: 35.6  [OUTLIER]
203.0.113.55    (ip)    events: 1020  median: 45  MAD: 18.5  z-score: 35.6  [OUTLIER]
```

The z-score of 35.6 is extreme. Engineer-bob's typical daily S3 activity is ~45 GetObject
calls against 1 bucket (ml-training-datasets). 1,020 calls across 5 buckets in 40 minutes
is a 22x deviation.

## Attack Path Narrative

**Path 1: Authorized Access - Anomalous Collection**
- Phases: Collection (no other kill chain phases - that's the problem)
- Entry point: 203.0.113.55 (legitimate home IP)
- Actor: engineer-bob (legitimate credentials, authorized access)
- Impact: 9.67 GB of proprietary data potentially exfiltrated including ML training data,
  product roadmap, customer contracts, source code, and compensation data

## Claude AI Analysis (expected output)

```json
{
  "verdict": "suspicious",
  "confidence": 0.82,
  "mitre_techniques": ["T1530"],
  "kill_chain_phases": ["Collection"],
  "blast_radius": "9.67 GB across 5 high-value data buckets, including PII (compensation, contracts)",
  "executive_summary": "Anomalous bulk data download by engineer-bob, a legitimate user with authorized access. 1,020 S3 objects (9.67 GB) downloaded across 5 buckets in 40 minutes, including datasets outside their normal work scope. No credential compromise indicators - this appears to be authorized access used for unauthorized purposes.",
  "technical_narrative": "At 22:01 UTC, engineer-bob authenticated from their known home IP and began systematically enumerating and downloading data from 5 S3 buckets. The pattern is methodical: ListObjectsV2 followed by bulk GetObject for each bucket, moving sequentially through ml-training-datasets, product-roadmap-docs, customer-contracts, source-code-archives, and employee-compensation-data. This breadth of access is unprecedented for this user whose typical pattern is 45 objects/day from ml-training-datasets only.",
  "key_findings": [
    "Volume anomaly: 1,020 objects vs median of 45 (z-score 35.6)",
    "Breadth anomaly: 5 buckets vs typical 1 (first time accessing 4 of the 5)",
    "Timing: 10 PM local time, outside normal work hours",
    "No credential compromise indicators (known IP, valid MFA, no suspicious auth events)",
    "Data sensitivity: includes customer contracts, compensation data, and source code",
    "Methodical enumeration pattern: ListObjects then bulk GetObject for each bucket"
  ],
  "recommended_actions": [
    {
      "priority": 1,
      "action": "Check HR systems for engineer-bob resignation status or PIP",
      "rationale": "Bulk data hoarding before departure is the most common insider threat pattern",
      "automatable": false
    },
    {
      "priority": 2,
      "action": "Preserve CloudTrail logs and S3 access logs for this session",
      "rationale": "Evidence preservation before any confrontation or access revocation",
      "automatable": true
    },
    {
      "priority": 3,
      "action": "Review DLP logs for this user (email, USB, cloud storage uploads)",
      "rationale": "The download is collection - exfiltration may happen via a different channel",
      "automatable": false
    },
    {
      "priority": 4,
      "action": "Scope access: reduce S3 permissions to team-relevant buckets only",
      "rationale": "Principle of least privilege - this user should not need access to compensation data",
      "automatable": true
    }
  ],
  "follow_up_questions": [
    "Is engineer-bob on a performance improvement plan or planning to leave?",
    "Has this user accessed these buckets before (historical baseline)?",
    "Were any of these objects uploaded to external storage (Dropbox, Drive, etc.)?",
    "Is there a legitimate business reason for this access pattern (e.g., migration project)?"
  ],
  "detection_improvements": [
    "Add user-specific baseline to S3 collection rule (alert on >3x personal median)",
    "Create cross-bucket anomaly rule (access to >3 distinct buckets in 1 hour)",
    "Add data classification tagging to S3 buckets for risk-weighted alerting",
    "Correlate with HR data feed for departing employee monitoring"
  ]
}
```

## Why This Scenario Is Important for the Interview

This is the scenario that best demonstrates why AI-powered investigation matters.

**Traditional SIEM fails here** because:
- Every API call is authorized (no policy violations to alert on)
- The source IP is legitimate (no geo anomaly)
- MFA was used (no credential compromise)
- S3 GetObject is the most common API call in any AWS environment

**Rule-based detection is weak** because:
- Fixed thresholds (>100 objects) generate false positives from ETL jobs
- Cross-bucket rules generate false positives from data engineers
- Time-based rules miss legitimate late-night work

**What catches it is the combination**:
- MAD anomaly score: 35.6 standard deviations from this user's personal baseline
- PrivilegeFanout pattern: accessing 5 data domains in one session
- Claude's contextual analysis: "methodical enumeration pattern" + "includes PII"

### How to Narrate This

"This is the hardest type of detection - insider threat with legitimate access. Every
individual API call passes authorization. The source IP is the user's known home IP with
valid MFA. There's no credential compromise.

What caught it was the statistical anomaly: 1,020 S3 objects versus a personal median of
45, giving a MAD z-score of 35.6. That's not a noisy alert - that's a 22x deviation from
baseline. The graph pattern detector also flagged it: 5 distinct S3 buckets spanning ML
data, product roadmap, contracts, source code, and compensation in a single 40-minute
session. Normal engineers stay in their lane.

The Claude analysis classified this as 'suspicious' rather than 'true_positive' - and
that's the right call. We can't determine malicious intent from logs alone. But the
recommended actions are exactly right: check HR status first (is this person leaving?),
preserve evidence, check DLP logs for exfiltration, and scope down the permissions.

This is where the AI adds the most value - it knows that bulk data hoarding before
departure is the most common insider threat pattern, and it recommends the right
investigation sequence: HR check before access revocation, evidence preservation
before confrontation. A junior analyst might revoke access immediately and tip off
the user."
