# Detection Rule Code Review Prep

## Interview Format
- 40 minutes, open-ended
- Review a detection rule written by a "colleague" before merge
- Treat as a real code review — ask questions, suggest improvements
- They want to see how you THINK about detections, not just whether you can spot bugs

## What to Look For in Any Detection Rule

### 1. Logic Correctness
- Does the query actually match the behavior described?
- Are the filter conditions correct (AND vs OR, equals vs contains)?
- Does the threshold make sense for the environment scale?
- Is the time window appropriate (too short = misses slow attacks, too long = noisy)?

### 2. False Positive Risk
- What legitimate activity would trigger this?
- Are AWS/GCP service-to-service calls excluded?
- Are automation tools (Terraform, CI/CD, Config) accounted for?
- Is the threshold low enough to be useful but high enough to avoid alert fatigue?

### 3. False Negative Risk
- Can an attacker evade this detection?
- Does the rule only match exact strings (vs. patterns)?
- Are there alternative API calls that achieve the same result?
- Does the rule handle both CLI and console activity?

### 4. MITRE Mapping
- Is the technique ID correct?
- Does the rule actually detect the technique or just a correlating behavior?
- Are related sub-techniques also covered?

### 5. Operational Concerns
- Query performance (does it scan too much data?)
- Alert fatigue (will the SOC team ignore this after a week?)
- Severity calibration (is this really critical, or more of a medium?)
- Actionability (when this fires, does the analyst know what to do?)

### 6. Detection Engineering Best Practices
- Is the description clear about what the rule catches and WHY it matters?
- Are there test cases?
- Is the rule composable with other rules (correlation)?
- Does it degrade gracefully if a data source is missing?

---

## Practice Exercise 1: IAM Policy Change Detection

Review this Sigma-style rule written by a colleague:

```yaml
title: AWS IAM Policy Attached to User
id: aws-iam-policy-attached
status: experimental
description: Detects when an IAM policy is attached directly to a user
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName:
            - AttachUserPolicy
            - PutUserPolicy
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1098
```

### Issues to Identify

**Good things to acknowledge first** (always start positive in a code review):
- Catches both managed policy attachment and inline policy creation
- Correct MITRE mapping (T1098 Account Manipulation)
- Reasonable severity level

**Issues:**

1. **No exclusion for legitimate admin activity**
   - Every Terraform run, CloudFormation stack, and CDK deploy will trigger this
   - Need to exclude known automation role ARNs or at least source IP ranges
   - Question to ask: "What's the volume of IAM changes in your environment? Do you use IaC?"

2. **Missing AttachGroupPolicy and AttachRolePolicy**
   - An attacker could attach policies to groups or roles instead of users
   - If we only alert on user policies, we miss the most common attack vector
   - Question: "Are we intentionally scoping to users only? Do we have separate rules for roles?"

3. **No severity differentiation based on which policy**
   - `AttachUserPolicy` with `AdministratorAccess` is critical
   - `AttachUserPolicy` with `ReadOnlyAccess` is informational
   - Question: "Should we grade severity based on the policy being attached?"

4. **Missing context fields**
   - No `userIdentity.type` filter — should exclude `AWSService` callers
   - No information about WHICH policy was attached (need `requestParameters`)
   - The alert is not actionable without knowing the policy name

5. **No test cases**
   - Should have positive test (attacker attaches admin policy)
   - Should have negative test (CloudFormation attaches read-only policy)

6. **"experimental" status without plan to promote**
   - What's the criteria for moving to "production"?
   - How long will it run in experimental before review?

---

## Practice Exercise 2: SSH Brute Force Detection

```yaml
title: SSH Brute Force Attempt
id: ssh-brute-force
status: production
description: Detects SSH brute force attacks based on failed login attempts
logsource:
    product: aws
    service: vpc-flow-logs
detection:
    selection:
        dstport: 22
        action: REJECT
    timeframe: 5m
    condition: selection | count() > 10
level: critical
tags:
    - attack.credential_access
    - attack.t1110
```

### Issues to Identify

**Good:**
- Using VPC flow logs for network-level detection
- Threshold-based with time window

**Issues:**

1. **Critical severity is too high for SSH brute force**
   - SSH brute force is incredibly common on the internet — every public IP gets scanned
   - This should be medium at most, or high only if the source is internal
   - Question: "What percentage of your SSH-facing instances are public? This will be extremely noisy."

2. **VPC flow logs don't show authentication success/failure**
   - `REJECT` means the NACL/SG blocked the traffic, not that SSH auth failed
   - If the SG already blocks port 22, these are just rejected connection attempts
   - Real SSH brute force detection needs CloudWatch Logs from the SSH daemon, not flow logs
   - Question: "Can we correlate this with OS-level auth logs?"

3. **Threshold of 10 in 5 minutes is too low**
   - A single nmap scan generates hundreds of connection attempts
   - Automated scanners like Masscan can hit thousands per minute
   - Need at least 100+ to distinguish targeted brute force from background noise
   - Question: "What's the baseline of rejected port-22 traffic?"

4. **Missing source IP aggregation**
   - `count() > 10` counts total events, not per-source-IP
   - 10 different IPs each sending 1 packet = false positive
   - Should be `count() by srcaddr > 10`

5. **Doesn't exclude known scanner IPs**
   - Shodan, Censys, Greynoise — known scanners hit every IP
   - Should have a whitelist of known research scanners or correlate with threat intel

6. **No response guidance**
   - When this fires, what should the analyst do? Block the IP? Check auth logs?
   - The description doesn't explain what a true positive looks like

7. **MITRE mapping could be more specific**
   - T1110 is generic "Brute Force" — T1110.001 (Password Guessing) or T1110.004 (Credential Stuffing) would be more precise

---

## Practice Exercise 3: Kubernetes Suspicious Activity (harder)

```python
# Detection: Suspicious K8s API calls
# Author: security-team
# Last updated: 2025-12-15

import json

def detect(event):
    if event.get('verb') in ['create', 'update', 'patch']:
        resource = event.get('objectRef', {}).get('resource', '')
        if resource in ['secrets', 'configmaps', 'roles', 'clusterroles',
                        'rolebindings', 'clusterrolebindings', 'pods',
                        'daemonsets', 'deployments', 'cronjobs']:
            user = event.get('user', {}).get('username', '')
            if not user.startswith('system:'):
                return {
                    'severity': 'high',
                    'title': f'Suspicious K8s mutation by {user}',
                    'mitre': 'T1078',
                    'user': user,
                    'resource': resource
                }
    return None
```

### Issues to Identify

**Good:**
- Covers broad set of security-sensitive resources
- Excludes system accounts
- Returns structured alert data

**Issues:**

1. **WAY too broad — this will fire on every deployment**
   - Every `kubectl apply`, Helm install, ArgoCD sync, and operator reconciliation
     creates/updates deployments, configmaps, and secrets
   - This is not a detection rule, it's an audit log
   - Question: "What's the expected volume? How many K8s mutations per hour?"

2. **`system:` prefix exclusion is insufficient**
   - Legitimate operators use service accounts like `argo-cd`, `cert-manager`, `external-secrets`
   - These don't start with `system:` but are benign
   - Need an allowlist of known service accounts, or better: alert on accounts NOT in the allowlist

3. **No namespace filtering**
   - Mutations in `kube-system`, `kube-public`, `monitoring` are usually operator-driven
   - Mutations in production namespaces by unexpected users are more interesting
   - Question: "Are there namespaces that should be more tightly controlled?"

4. **Treating all resources as equal severity**
   - Creating a ConfigMap is very different from creating a ClusterRoleBinding
   - Secrets and RBAC resources should be higher severity than deployments
   - Should tier: critical (clusterroles/bindings) > high (secrets, roles) > medium (pods, deployments)

5. **No temporal or behavioral context**
   - A single `create deployment` is normal ops
   - `create clusterrolebinding` + `create daemonset` + `get secrets` in sequence from the same user within 5 minutes is an attack
   - This rule can't do correlation — it fires on individual events

6. **Python detection function without tests**
   - No unit tests
   - The `event.get()` chain is fragile — what if `objectRef` is missing?
   - No error handling for malformed events

7. **MITRE T1078 (Valid Accounts) is wrong**
   - T1078 is about using stolen/compromised credentials
   - This rule detects resource mutations, not credential use
   - Should map to specific techniques per resource: T1053.007 for scheduled tasks,
     T1078.001 for RBAC, T1552.007 for secrets

8. **Missing key context: what changed?**
   - For update/patch operations, the diff matters more than the verb
   - `patch deployment` to change the image tag is a deploy
   - `patch deployment` to add a privileged container is an attack
   - Request body inspection is needed for meaningful detection

---

## Your Code Review Framework

When you sit down for the 40-minute exercise, use this mental model:

### First 5 minutes: Understand Intent
- What is this rule trying to detect?
- What attack does this map to?
- Who is the expected attacker (external, insider, compromised automation)?

### Next 10 minutes: Logic Review
- Does the query logic actually catch the described attack?
- What are the edge cases and evasion paths?
- Are the filters correct and sufficient?

### Next 10 minutes: Operational Review
- What's the expected alert volume?
- What does a true positive look like vs. a false positive?
- Is the severity calibrated correctly?
- What should the analyst DO when this fires?

### Next 10 minutes: Improvement Suggestions
- How would you reduce false positives while keeping true positive coverage?
- What additional data sources or correlations would help?
- How does this fit into the broader detection strategy?

### Final 5 minutes: Summary
- Verdict: approve, approve with changes, or request changes
- Top 3 most important changes
- One thing the author did well (always end positive)

---

## Key Phrases for the Interview

- "What's the expected volume in your environment?" (shows you think about operability)
- "Can an attacker evade this by..." (shows adversarial thinking)
- "This would correlate well with..." (shows detection engineering depth)
- "The MITRE mapping could be more specific..." (shows framework knowledge)
- "In my experience tuning rules against real data..." (connects to irone experience)
- "Have you considered the IaC/automation noise?" (shows production awareness)
- "What does the response playbook look like for this?" (shows full-lifecycle thinking)

## Your Secret Weapon

You've DONE this. You tuned 226 false positives from production irone data:
- IMDS stolen credentials firing on AWS service traffic
- Cognito auth failures from AWS Config probing
- Secrets enumeration from CloudFormation inventory scans

When they show you a rule, you'll see these patterns immediately because you've debugged them in production. That real-world experience is what they're looking for.
