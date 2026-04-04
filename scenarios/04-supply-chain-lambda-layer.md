# Scenario 4: Supply Chain Attack via Lambda Layer Injection

## Situation

**Alert**: `detect-lambda-layer-backdoor` fired at 08:42 UTC
**Severity**: Critical
**MITRE**: T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)

An attacker compromised a CI/CD service account and injected a malicious Lambda layer
into the deployment pipeline. The layer intercepts all function invocations, exfiltrates
environment variables (including secrets), and opens a reverse shell. Because Lambda
layers are shared across functions, a single layer compromise affects every function
that uses it.

## Timeline of Events

```
08:15 UTC  cicd-deployer SA authenticates from 192.0.2.50 (GitHub Actions runner IP)
           Normal for this SA - runs on every push to main
08:16      lambda:PublishLayerVersion "shared-utils" version 47
           Previous version 46 was published 3 days ago by cicd-deployer
           But version 47 has a different SHA256 than what git log shows
08:17      lambda:UpdateFunctionConfiguration on 12 Lambda functions
           All 12 updated to use shared-utils:47
08:18      lambda:GetFunction on api-handler, auth-service, data-processor
           (the attacker verifying the layer is active)
08:20      First invocations of instrumented functions begin
08:21      CloudWatch: outbound HTTPS to 93.184.216.34:8443 from api-handler
           Not in any VPC - public Lambda, can reach internet freely
08:22      CloudWatch: same outbound pattern from auth-service, data-processor
08:23      ssm:GetParameter /prod/database-url, /prod/api-key, /prod/stripe-secret
           Called by auth-service (the layer is extracting env vars and
           resolving SSM references at runtime)
08:30      Unusual: lambda:GetLayerVersion called by data-processor at runtime
           Layers don't normally call the Lambda API - the malicious layer is
           pulling additional payloads
08:42      Detection fires on Lambda layer modification pattern
```

## Investigation Graph

```
Nodes (20):
  Principals:  cicd-deployer (IAMRole, OIDC-federated from GitHub)
               lambda/api-handler, lambda/auth-service, lambda/data-processor
               (9 more Lambda execution roles)
  IPs:         192.0.2.50 (GitHub Actions), 93.184.216.34 (C2/exfil endpoint)
  Resources:   layer/shared-utils:47, layer/shared-utils:46,
               /prod/database-url (SSM), /prod/api-key (SSM),
               /prod/stripe-secret (SSM)
  Operations:  PublishLayerVersion, UpdateFunctionConfiguration, GetFunction,
               GetParameter, GetLayerVersion, Invoke

Edges (32):
  cicd-deployer - AUTHENTICATED_FROM - 192.0.2.50
  cicd-deployer - CALLED_API - PublishLayerVersion - shared-utils:47
  cicd-deployer - CALLED_API - UpdateFunctionConfiguration (12 functions)
  api-handler - COMMUNICATED_WITH - 93.184.216.34 (C2)
  auth-service - COMMUNICATED_WITH - 93.184.216.34 (C2)
  auth-service - CALLED_API - GetParameter - /prod/stripe-secret
  data-processor - CALLED_API - GetLayerVersion (runtime payload fetch)
```

## Graph Patterns Detected

1. **ResourceConvergence** (severity: 0.90)
   - `layer/shared-utils:47` is accessed/used by 12 Lambda functions
   - Analysis hint: "Single resource consumed by 12 principals. A compromised shared
     layer is a force multiplier - every function becomes a vector."

2. **PrivilegeFanout** (severity: 0.80)
   - `cicd-deployer` modified 12 Lambda functions + 1 layer in one session
   - Analysis hint: "CI/CD identity touched 13 resources in 2 minutes. Verify this
     matches expected deployment pattern and that layer content matches source control."

## Anomaly Scores (MAD-based)

```
cicd-deployer       (user)  events: 26    median: 14   MAD: 3.2  z-score: 2.53
93.184.216.34       (ip)    events: 45    median: 0    MAD: 0.0  z-score: inf   [OUTLIER]
shared-utils:47     (resource) events: 12 median: 1    MAD: 0.0  z-score: inf   [OUTLIER]
```

Note: cicd-deployer itself is NOT anomalous (z-score 2.53) - it deploys regularly.
The anomaly is in the *content* of what was deployed, not the deployment pattern.
This is why content integrity checks matter more than behavioral anomalies for
supply chain attacks.

## Attack Path Narrative

**Path 1: CI/CD Compromise - Layer Injection - Secrets Exfiltration**
- Phases: Initial Access - Persistence - Collection - Exfiltration - C2
- Entry point: GitHub Actions OIDC federation (compromised workflow file)
- Actor: cicd-deployer (legitimate role, compromised pipeline)
- Impact: 12 Lambda functions running malicious code, SSM secrets (database URL,
  API key, Stripe secret) exfiltrated, persistent reverse shell on all invocations

## Claude AI Analysis (expected output)

```json
{
  "verdict": "true_positive",
  "confidence": 0.94,
  "mitre_techniques": ["T1195.002", "T1059.004", "T1552.005", "T1041"],
  "kill_chain_phases": [
    "Initial Access",
    "Persistence",
    "Collection",
    "Exfiltration",
    "Command and Control"
  ],
  "blast_radius": "12 Lambda functions, 3 SSM secrets (including Stripe), all API traffic through compromised functions",
  "executive_summary": "Supply chain attack via malicious Lambda layer injection. The CI/CD pipeline published a tampered version of shared-utils layer, which was automatically applied to 12 functions. The layer exfiltrates environment variables (including production secrets) and opens C2 connections to 93.184.216.34. All functions using this layer are compromised.",
  "key_findings": [
    "Lambda layer shared-utils:47 SHA256 does not match source control",
    "12 Lambda functions updated to use the malicious layer version",
    "Outbound C2 traffic to 93.184.216.34:8443 from multiple functions",
    "SSM secrets accessed at runtime: database-url, api-key, stripe-secret",
    "Runtime GetLayerVersion call indicates dynamic payload loading",
    "CI/CD deployer behavior itself was not anomalous - attack is in the content"
  ],
  "recommended_actions": [
    {
      "priority": 1,
      "action": "Roll back all 12 functions to use shared-utils:46",
      "rationale": "Version 46 is the last known-good layer version",
      "automatable": true
    },
    {
      "priority": 2,
      "action": "Delete layer version shared-utils:47",
      "rationale": "Prevent any function from referencing the malicious layer",
      "automatable": true
    },
    {
      "priority": 3,
      "action": "Rotate all secrets: database-url, api-key, stripe-secret",
      "rationale": "These were exfiltrated via the malicious layer - assume compromised",
      "automatable": false
    },
    {
      "priority": 4,
      "action": "Audit GitHub Actions workflow files for unauthorized changes",
      "rationale": "Initial access was through the CI/CD pipeline - find and fix the injection point",
      "automatable": false
    },
    {
      "priority": 5,
      "action": "Add Lambda layer content hashing to deployment pipeline",
      "rationale": "Compare layer SHA256 against source control before allowing publish",
      "automatable": true
    }
  ],
  "follow_up_questions": [
    "When was the GitHub Actions workflow file last modified and by whom?",
    "What data was sent to 93.184.216.34? Is this a known C2 infrastructure?",
    "Were any API requests processed by compromised functions that included sensitive user data?",
    "Does the CI/CD role have permissions to modify other infrastructure beyond Lambda?"
  ],
  "detection_improvements": [
    "Add layer content integrity check (SHA256 against signed manifest)",
    "Detect Lambda functions making outbound connections to unknown IPs",
    "Alert on runtime GetLayerVersion calls (layers should not self-reference)",
    "Monitor CI/CD identity for deployments outside normal git-push-triggered pattern"
  ]
}
```

## Playbook Triggered

**pb-supply-chain** (auto-triggered by severity=Critical + tag=supply-chain)

| Step | Action | Approval | Status |
|------|--------|----------|--------|
| 1 | Notify security team + engineering lead | Auto | Executed |
| 2 | Snapshot evidence (layer content, CloudWatch logs) | Auto | Executed |
| 3 | Roll back Lambda functions to last known-good | Auto | Executed |
| 4 | Rotate compromised secrets | **Manual** | Awaiting (service impact) |

## Interview Talking Points

### Architecture Decisions

- **Why behavioral anomaly detection misses supply chain attacks**: The CI/CD deployer's
  behavior (publish layer, update functions) is indistinguishable from a legitimate
  deployment. The z-score was only 2.53 - below any reasonable threshold. Supply chain
  attacks exploit *trusted processes*. You need content integrity verification, not just
  behavioral baselining.

- **Why the ResourceConvergence pattern is critical here**: The graph pattern detector
  identified that a single resource (the layer) is consumed by 12 functions. This is
  the "blast radius amplifier" of supply chain attacks. The pattern's analysis_hint
  specifically calls out shared dependencies as force multipliers.

- **Why this matters for Anthropic specifically**: Anthropic runs significant infrastructure
  on AWS Lambda and likely uses shared layers/dependencies. Their CI/CD pipeline is a
  high-value target because compromising it gives persistent access to production without
  needing to compromise individual developer credentials. The Detection Platform team
  needs to monitor the entire software delivery pipeline, not just runtime behavior.

### How to Narrate This

"This is the subtlest scenario because the initial deployment activity looks completely
normal. The CI/CD service account publishes layers and updates functions every time code
is pushed to main. That's its job. The MAD anomaly scorer gave it a z-score of only
2.53 - well within normal range.

What caught it was downstream: the Lambda layer backdoor detection rule fired when it
saw layer modifications affecting more than 10 functions simultaneously. But even that
rule needs context to triage properly.

The graph tells the real story: ResourceConvergence pattern shows one layer feeding 12
functions, and those functions are now making outbound connections to an IP that has
never appeared in our network before (z-score infinity). The layer is also accessing
SSM secrets at runtime and calling GetLayerVersion on itself - layers don't normally
need to call the Lambda API.

The key insight for supply chain attacks is that you can't rely on behavioral anomaly
detection for the initial compromise. The deployer behaves normally. The anomaly shows
up in the *downstream effects* - runtime behavior of the deployed code. This is why we
need both: rules for known-bad patterns (layer modification + outbound C2) and graph
analysis for structural anomalies (single resource consumed by 12 principals)."

### Connection to Anthropic's D&R Mission

This scenario directly connects to Anthropic's stated goal of using Claude to enhance
detection: traditional detection misses the initial compromise because the CI/CD
deployer behaves normally. But Claude, looking at the full investigation graph, can
reason about the causal chain: "this layer was published by CI/CD (normal), but the
layer's runtime behavior (C2, secret access, self-referencing API calls) is abnormal,
and the blast radius is 12 functions." That kind of multi-hop reasoning across the
graph is exactly what LLMs excel at and rule engines struggle with.
