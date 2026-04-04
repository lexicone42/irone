# Scenario 2: Kubernetes Container Escape to Cluster Takeover

## Situation

**Alert**: `detect-eks-privileged-pod` fired at 03:17 UTC (off-hours)
**Severity**: Critical
**MITRE**: T1611 (Escape to Host), T1610 (Deploy Container)

An attacker compromised a web application running in EKS through an SSRF vulnerability.
From within the container, they accessed the node's metadata service (IMDSv1) to steal
the node IAM role credentials, then used those to create a privileged DaemonSet that runs
on every node in the cluster. They escalated to cluster-admin via RBAC manipulation.

## Timeline of Events

```
02:45 UTC  webapp-frontend pod: unusual outbound traffic to metadata endpoint
           GET to 169.254.169.254/latest/meta-data/iam/security-credentials/
02:46      Node IAM role assumed from pod IP (eks-node-role, temporary STS creds)
02:48      eks-audit: create pods/exec into webapp-frontend (interactive shell)
02:51      eks-audit: list secrets (all namespaces) - 47 secrets enumerated
02:53      eks-audit: get secret/aws-creds (production namespace)
02:55      eks-audit: create serviceaccounts/token (system:node, kube-system)
02:58      eks-audit: create clusterrolebindings - cluster-admin binding
03:01      eks-audit: create daemonsets (kube-system, name: "kube-proxy-helper")
           Image: attacker-registry.io/proxy:latest
           Mounts: hostPath / (full node filesystem access)
           SecurityContext: privileged=true
03:05      ECR: PullThroughCache request for attacker-registry.io/proxy
03:10      VPC flow: outbound connections from all nodes to 45.33.32.1:443 (C2)
03:17      Detection fires on privileged pod creation
```

## Investigation Graph

```
Nodes (22):
  Principals:  system:serviceaccount:default:webapp-frontend
               system:node:ip-10-0-1-42
               AROAEXAMPLEROLE (eks-node-role)
               system:anonymous (attacker's cluster-admin identity)
  IPs:         10.0.1.42 (node), 169.254.169.254 (IMDS), 45.33.32.1 (C2 server)
  Resources:   secret/aws-creds, clusterrolebinding/backdoor-admin,
               daemonset/kube-proxy-helper, node/ip-10-0-1-42
  Operations:  pods/exec(create), secrets(list), secrets(get),
               serviceaccounts/token(create), clusterrolebindings(create),
               daemonsets(create)

Edges (28):
  webapp-frontend SA - AUTHENTICATED_FROM - 10.0.1.42
  webapp-frontend SA - CALLED_API - pods/exec(create)
  system:node - CALLED_API - secrets(list), secrets(get)
  system:node - CALLED_API - serviceaccounts/token(create)
  system:anonymous - CALLED_API - clusterrolebindings(create) - cluster-admin
  system:anonymous - CALLED_API - daemonsets(create) - kube-proxy-helper
  kube-proxy-helper - COMMUNICATED_WITH - 45.33.32.1 (C2)
```

## Graph Patterns Detected

1. **PrivilegeFanout** (severity: 0.90)
   - `system:node:ip-10-0-1-42` accessed secrets, RBAC, service accounts, daemonsets
   - Analysis hint: "Node identity accessing cluster-wide RBAC resources is abnormal.
     Nodes should only manage their own pods, not create cluster-admin bindings."

2. **ServiceBridge** (severity: 0.85)
   - `system:node:ip-10-0-1-42` is the sole link between the webapp namespace
     and the kube-system namespace
   - Analysis hint: "This node identity bridges two otherwise disconnected service
     clusters. Node identities should not be the vector for cross-namespace access."

3. **ResourceConvergence** (severity: 0.70)
   - `secret/aws-creds` accessed by both webapp-frontend SA and system:node
   - Analysis hint: "Multiple identities accessing the same secret suggests
     credential sharing or theft."

## Anomaly Scores (MAD-based)

```
system:node:ip-10-0-1-42  (user)  events: 89  median: 5   MAD: 2.1  z-score: 27.0 [OUTLIER]
45.33.32.1                 (ip)    events: 34  median: 0   MAD: 0.0  z-score: inf  [OUTLIER]
```

## Attack Path Narrative

**Path 1: SSRF - IMDS - Node Compromise - Cluster Takeover**
- Phases: Initial Access - Credential Access - Privilege Escalation - Persistence - C2
- Entry point: SSRF in webapp-frontend (metadata endpoint access)
- Actor: system:node:ip-10-0-1-42 (compromised node identity)
- Impact: Full cluster compromise. DaemonSet on all nodes with host filesystem
  access and C2 callback. Cluster-admin RBAC binding means attacker can deploy
  any workload, access any secret, and survive pod/deployment deletion.

## Claude AI Analysis (expected output)

```json
{
  "verdict": "true_positive",
  "confidence": 0.98,
  "mitre_techniques": ["T1552.007", "T1611", "T1610", "T1078.001", "T1053.007"],
  "kill_chain_phases": [
    "Initial Access",
    "Credential Access",
    "Privilege Escalation",
    "Persistence",
    "Command and Control"
  ],
  "blast_radius": "Full EKS cluster - all nodes running attacker DaemonSet with host access",
  "executive_summary": "Critical cluster compromise. Attacker exploited SSRF to steal node IAM credentials via IMDSv1, escalated to cluster-admin through RBAC manipulation, and deployed a privileged DaemonSet on all nodes with C2 callback to 45.33.32.1. The cluster should be considered fully compromised.",
  "key_findings": [
    "IMDSv1 metadata access from webapp pod - SSRF exploitation confirmed",
    "Node IAM role credentials stolen and used for K8s API access",
    "47 secrets enumerated across all namespaces including production AWS creds",
    "cluster-admin ClusterRoleBinding created - full cluster control",
    "Privileged DaemonSet kube-proxy-helper deployed to all nodes from external registry",
    "Outbound C2 traffic to 45.33.32.1:443 from all cluster nodes"
  ],
  "recommended_actions": [
    {
      "priority": 1,
      "action": "Delete the malicious DaemonSet kube-proxy-helper from kube-system",
      "rationale": "Active C2 on all nodes - every minute increases data exposure",
      "automatable": true
    },
    {
      "priority": 2,
      "action": "Delete the backdoor ClusterRoleBinding and service account tokens",
      "rationale": "Attacker persistent access path - removing this cuts their API access",
      "automatable": true
    },
    {
      "priority": 3,
      "action": "Block outbound traffic to 45.33.32.1 via network policy and NACL",
      "rationale": "Sever C2 channel while cleanup is in progress",
      "automatable": true
    },
    {
      "priority": 4,
      "action": "Rotate all secrets accessed by the compromised identities",
      "rationale": "47 secrets were enumerated and aws-creds was read - assume all leaked",
      "automatable": false
    },
    {
      "priority": 5,
      "action": "Enforce IMDSv2 on all EKS nodes (hop limit = 1)",
      "rationale": "IMDSv1 is what made the SSRF to credential theft possible",
      "automatable": true
    }
  ],
  "follow_up_questions": [
    "What is the webapp SSRF vulnerability? Has it been patched?",
    "What data did the attacker exfiltrate via the C2 channel?",
    "Is 45.33.32.1 associated with known threat groups?",
    "Were any other clusters or accounts accessed using the stolen aws-creds secret?"
  ],
  "detection_improvements": [
    "Add IMDS metadata access detection (pod to 169.254.169.254)",
    "Alert on DaemonSet creation in kube-system from non-system service accounts",
    "Detect images pulled from non-approved registries",
    "Create pod security admission policy to block privileged containers"
  ]
}
```

## Playbook Triggered

**pb-k8s-container-escape** (auto-triggered by rule_id=detect-eks-privileged-pod)

| Step | Action | Approval | Status |
|------|--------|----------|--------|
| 1 | Quarantine pod (network policy deny-all) | Auto | Executed |
| 2 | Disable compromised service account | Auto | Executed |
| 3 | Scale deployment to zero | **Manual** | Awaiting (blast radius) |

## Interview Talking Points

### Architecture Decisions
- **Why graph patterns catch this when event rules don't**: The individual K8s audit
  events (create secret, create DaemonSet) are each individually explainable. It's the
  *topology* that's malicious - a node identity bridging webapp and kube-system namespaces,
  with privilege fanout across RBAC/secrets/workloads. The `ServiceBridge` pattern detector
  catches this structural anomaly.

- **Why K8s detection is hard and why this matters for Anthropic**: K8s audit logs are
  noisy - controllers, operators, and reconciliation loops generate thousands of benign
  mutations per minute. You can't just alert on "pod created" - you need to understand
  *who* created it, *what* security context it has, and *whether that identity should
  be doing this*. This is exactly where LLM-powered triage adds value: Claude can look
  at the full context (graph + timeline + patterns) and distinguish a legitimate deployment
  from an attacker's DaemonSet.

- **Why playbook approval gates matter for K8s**: "Scale deployment to zero" could take
  down a production service. The playbook auto-executes containment (quarantine the pod)
  but holds on destructive actions until a human confirms. This mirrors real SOC workflow.

### How to Narrate This

"The privileged pod alert fired at 3 AM. First red flag - who's creating privileged pods
at 3 AM? Second, the DaemonSet name `kube-proxy-helper` in `kube-system` is a classic
adversary technique - name your malware after system components.

Looking at the graph, I traced backwards: the DaemonSet was created by an identity that
escalated from a node service account, which was in turn stolen via IMDS metadata access
from a webapp pod. The ServiceBridge pattern detector caught something a human analyst
might miss - this node identity was the only link between two namespaces that should
never be connected.

The full kill chain is SSRF then IMDS cred theft then K8s secret enumeration then RBAC
escalation then DaemonSet persistence then C2. Classic container breakout, well-documented
in the MITRE Container Matrix.

Containment was fast: playbook quarantined the source pod with a deny-all network policy
and disabled the compromised service account within 30 seconds. The DaemonSet deletion
and deployment scale-down were held for manual approval because they affect running
workloads."
