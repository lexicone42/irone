use std::collections::{HashSet, VecDeque};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::models::{Direction, EdgeType, GraphEdge, NodeType, SecurityGraph};

/// MITRE ATT&CK kill chain phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackPhase {
    Reconnaissance,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    Exfiltration,
    Impact,
    /// Edge/operation doesn't map cleanly to a single phase.
    Unknown,
}

impl AttackPhase {
    /// Canonical ordering in the kill chain (lower = earlier).
    #[must_use]
    pub fn ordinal(self) -> u8 {
        match self {
            Self::Reconnaissance => 0,
            Self::InitialAccess => 1,
            Self::Execution => 2,
            Self::Persistence => 3,
            Self::PrivilegeEscalation => 4,
            Self::DefenseEvasion => 5,
            Self::CredentialAccess => 6,
            Self::Discovery => 7,
            Self::LateralMovement => 8,
            Self::Collection => 9,
            Self::Exfiltration => 10,
            Self::Impact => 11,
            Self::Unknown => 12,
        }
    }
}

impl std::fmt::Display for AttackPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reconnaissance => write!(f, "Reconnaissance"),
            Self::InitialAccess => write!(f, "Initial Access"),
            Self::Execution => write!(f, "Execution"),
            Self::Persistence => write!(f, "Persistence"),
            Self::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            Self::DefenseEvasion => write!(f, "Defense Evasion"),
            Self::CredentialAccess => write!(f, "Credential Access"),
            Self::Discovery => write!(f, "Discovery"),
            Self::LateralMovement => write!(f, "Lateral Movement"),
            Self::Collection => write!(f, "Collection"),
            Self::Exfiltration => write!(f, "Exfiltration"),
            Self::Impact => write!(f, "Impact"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// A single step in a reconstructed attack path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    /// MITRE ATT&CK phase this step belongs to.
    pub phase: AttackPhase,
    /// When this step occurred (`first_seen` on the edge or node).
    pub timestamp: Option<DateTime<Utc>>,
    /// The acting principal (user/role label), if identifiable.
    pub actor: Option<String>,
    /// Human-readable action description (e.g. "Called iam:CreateAccessKey").
    pub action: String,
    /// The target of the action (resource label, IP, etc.).
    pub target: Option<String>,
    /// Edge type that connects the nodes in this step.
    pub edge_type: Option<EdgeType>,
    /// Graph node IDs involved in this step.
    pub node_ids: Vec<String>,
    /// One-sentence IR analyst narrative.
    pub narrative: String,
    /// How many times this action was observed (edge `event_count`).
    pub event_count: u64,
}

/// Complete reconstructed attack narrative from graph analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackNarrative {
    /// The finding that seeded this narrative.
    pub finding_id: String,
    /// Finding label (rule name).
    pub finding_label: String,
    /// Chronologically ordered attack steps.
    pub steps: Vec<AttackStep>,
    /// Multi-sentence executive summary.
    pub summary: String,
    /// Kill chain phases observed, in order.
    pub phases_observed: Vec<AttackPhase>,
    /// Unique principals involved, ordered by first appearance.
    pub actors: Vec<String>,
    /// Entry point (first IP or authentication source).
    pub entry_point: Option<String>,
    /// Assessment of impact/risk.
    pub impact_assessment: String,
    /// Total unique nodes in the attack subgraph.
    pub node_count: usize,
    /// Total edges in the attack subgraph.
    pub edge_count: usize,
}

/// Map a MITRE ATT&CK technique ID (e.g. "T1078.004") to a kill chain phase.
///
/// Handles both top-level techniques and sub-techniques by matching on the
/// parent ID (prefix before the dot). This covers the 27 detection rules in
/// `irone-rs/rules/` plus the broader ATT&CK Enterprise Cloud matrix.
#[must_use]
pub fn technique_to_phase(technique_id: &str) -> AttackPhase {
    // Normalize: match the parent technique for sub-techniques
    let parent = technique_id.split('.').next().unwrap_or(technique_id);

    match parent {
        // ── Reconnaissance ──────────────────────────
        "T1580" | "T1526" | "T1538" | "T1595" | "T1592" | "T1589" | "T1590" | "T1591" | "T1598"
        | "T1597" | "T1596" | "T1593" => AttackPhase::Reconnaissance,

        // ── Initial Access ──────────────────────────
        "T1078" | "T1190" | "T1195" | "T1199" | "T1566" | "T1133" => AttackPhase::InitialAccess,

        // ── Execution ───────────────────────────────
        "T1059" | "T1203" | "T1204" | "T1609" | "T1648" => AttackPhase::Execution,

        // ── Persistence ─────────────────────────────
        "T1098" | "T1136" | "T1197" | "T1543" | "T1547" | "T1546" | "T1037" | "T1556" => {
            AttackPhase::Persistence
        }

        // ── Privilege Escalation ────────────────────
        "T1134" | "T1548" | "T1611" | "T1068" => AttackPhase::PrivilegeEscalation,

        // ── Defense Evasion ─────────────────────────
        "T1562" | "T1578" | "T1550" | "T1070" | "T1036" | "T1535" | "T1606" => {
            AttackPhase::DefenseEvasion
        }

        // ── Credential Access ───────────────────────
        "T1110" | "T1187" | "T1528" | "T1552" | "T1555" | "T1621" | "T1040" => {
            AttackPhase::CredentialAccess
        }

        // ── Discovery ───────────────────────────────
        "T1087" | "T1069" | "T1082" | "T1518" | "T1049" | "T1016" | "T1007" | "T1033" | "T1046"
        | "T1135" | "T1201" | "T1010" | "T1217" => AttackPhase::Discovery,

        // ── Lateral Movement ────────────────────────
        "T1021" | "T1570" => AttackPhase::LateralMovement,

        // ── Collection ──────────────────────────────
        "T1530" | "T1119" | "T1213" | "T1005" => AttackPhase::Collection,

        // ── Exfiltration ────────────────────────────
        "T1020" | "T1030" | "T1048" | "T1567" | "T1537" => AttackPhase::Exfiltration,

        // ── Impact ──────────────────────────────────
        "T1486" | "T1531" | "T1485" | "T1561" | "T1489" | "T1529" | "T1498" | "T1499" => {
            AttackPhase::Impact
        }

        _ => AttackPhase::Unknown,
    }
}

// ─── Public API ─────────────────────────────────────────────────────

/// Extract attack path narratives from a security investigation graph.
///
/// Finds all `SecurityFinding` nodes, then for each one traces backwards
/// and forwards through the graph to reconstruct the kill chain. Returns
/// one `AttackNarrative` per finding, sorted by severity (highest first).
#[must_use]
pub fn extract_attack_paths(graph: &SecurityGraph) -> Vec<AttackNarrative> {
    let findings = graph.get_nodes_by_type(&NodeType::SecurityFinding);
    if findings.is_empty() {
        return Vec::new();
    }

    let mut narratives = Vec::new();
    for finding in &findings {
        let narrative = build_narrative_for_finding(graph, &finding.id, &finding.label);
        if !narrative.steps.is_empty() {
            narratives.push(narrative);
        }
    }

    narratives
}

/// Classify an AWS API operation into a MITRE ATT&CK phase.
///
/// Uses the operation name (e.g. "`CreateAccessKey`") to determine the
/// most likely kill chain phase. Operations that span multiple phases
/// (like `AssumeRole`) are classified by their primary intent.
#[must_use]
pub fn classify_operation(operation: &str) -> AttackPhase {
    match operation {
        // ── Persistence ──────────────────────────────
        "CreateAccessKey" | "CreateUser" | "CreateLoginProfile" | "CreateServiceLinkedRole" => {
            AttackPhase::Persistence
        }

        // ── Privilege Escalation ─────────────────────
        "AttachUserPolicy"
        | "AttachRolePolicy"
        | "PutUserPolicy"
        | "PutRolePolicy"
        | "AttachGroupPolicy"
        | "PutGroupPolicy"
        | "CreatePolicyVersion"
        | "SetDefaultPolicyVersion"
        | "AddUserToGroup" => AttackPhase::PrivilegeEscalation,

        // ── Defense Evasion ──────────────────────────
        "StopLogging" | "DeleteTrail" | "PutEventSelectors" | "UpdateTrail" => {
            AttackPhase::DefenseEvasion
        }
        "DeactivateMFADevice"
        | "DeleteVirtualMFADevice"
        | "DeleteFlowLogs"
        | "DisableAlarmActions" => AttackPhase::DefenseEvasion,

        // ── Credential Access ────────────────────────
        "AssumeRole"
        | "AssumeRoleWithSAML"
        | "AssumeRoleWithWebIdentity"
        | "GetSessionToken"
        | "GetFederationToken" => AttackPhase::CredentialAccess,

        // ── Discovery ────────────────────────────────
        "ListBuckets"
        | "ListUsers"
        | "ListRoles"
        | "ListGroups"
        | "ListPolicies"
        | "DescribeInstances"
        | "DescribeSecurityGroups"
        | "DescribeSubnets"
        | "DescribeVpcs"
        | "GetCallerIdentity"
        | "ListAccessKeys"
        | "GetAccountSummary"
        | "DescribeTrails"
        | "GetBucketAcl"
        | "GetBucketPolicy"
        | "ListQueues"
        | "DescribeDBInstances"
        | "ListFunctions20150331"
        | "ListTables"
        | "DescribeAlarms"
        | "ListStreams" => AttackPhase::Discovery,

        // ── Collection ───────────────────────────────
        "GetObject"
        | "SelectObjectContent"
        | "DownloadDBLogFilePortion"
        | "GetSecretValue"
        | "GetParameter"
        | "GetParameters"
        | "BatchGetItem"
        | "Query"
        | "Scan" => AttackPhase::Collection,

        // ── Execution ────────────────────────────────
        "Invoke" | "InvokeFunction" | "RunInstances" | "StartExecution" | "SendCommand"
        | "RunTask" | "StartBuild" => AttackPhase::Execution,

        // ── Exfiltration ─────────────────────────────
        "PutObject"
        | "CopyObject"
        | "CreateSnapshot"
        | "CopySnapshot"
        | "ShareSnapshot"
        | "ModifySnapshotAttribute" => AttackPhase::Exfiltration,

        // ── Impact ───────────────────────────────────
        "DeleteBucket" | "TerminateInstances" | "DeleteDBInstance" | "DeleteTable"
        | "PutBucketPolicy" | "PutBucketAcl" | "DeleteSnapshot" | "StopInstances" => {
            AttackPhase::Impact
        }

        // ── Network security changes (Impact/Defense Evasion) ──
        "AuthorizeSecurityGroupIngress"
        | "AuthorizeSecurityGroupEgress"
        | "RevokeSecurityGroupIngress" => AttackPhase::Impact,

        _ => AttackPhase::Unknown,
    }
}

// ─── Internal Implementation ────────────────────────────────────────

/// BFS from a seed node, collecting all reachable node IDs within `max_depth` hops.
fn bfs_reachable(graph: &SecurityGraph, seed: &str, max_depth: usize) -> HashSet<String> {
    let mut visited = HashSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    queue.push_back((seed.to_string(), 0));
    visited.insert(seed.to_string());

    while let Some((node_id, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        for neighbor in graph.get_neighbors(&node_id, Direction::Both) {
            if visited.insert(neighbor.id.clone()) {
                queue.push_back((neighbor.id.clone(), depth + 1));
            }
        }
    }

    visited
}

/// Build a narrative for a single finding by tracing its attack subgraph.
fn build_narrative_for_finding(
    graph: &SecurityGraph,
    finding_id: &str,
    finding_label: &str,
) -> AttackNarrative {
    // 1. Find all nodes reachable from the finding (max 5 hops)
    let reachable = bfs_reachable(graph, finding_id, 5);

    // 2. Extract MITRE phase from the finding node's metadata
    let mitre_phase = graph
        .get_node(finding_id)
        .and_then(|n| n.properties.get("mitre_attack"))
        .and_then(serde_json::Value::as_array)
        .and_then(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(technique_to_phase)
                .find(|p| *p != AttackPhase::Unknown)
        });

    // 3. Collect all edges within the reachable subgraph
    let subgraph_edges: Vec<&GraphEdge> = graph
        .edges
        .iter()
        .filter(|e| reachable.contains(&e.source_id) && reachable.contains(&e.target_id))
        .collect();

    // 4. Classify each edge into an attack step
    let mut steps: Vec<AttackStep> = Vec::new();
    let mut seen_edges = HashSet::new();

    for edge in &subgraph_edges {
        if !seen_edges.insert(&edge.id) {
            continue;
        }
        if let Some(mut step) = classify_edge(edge, graph) {
            // If the step couldn't be classified by API operation alone,
            // inherit the phase from the detection rule's MITRE mapping.
            if step.phase == AttackPhase::Unknown
                && let Some(phase) = mitre_phase
            {
                step.phase = phase;
            }
            steps.push(step);
        }
    }

    // 5. Sort by timestamp, then by kill chain phase ordinal
    steps.sort_by(|a, b| {
        a.timestamp
            .cmp(&b.timestamp)
            .then_with(|| a.phase.ordinal().cmp(&b.phase.ordinal()))
    });

    // 6. Deduce observed phases (preserving first-seen order)
    let mut phases_observed = Vec::new();
    let mut seen_phases = HashSet::new();
    // Include the MITRE-derived phase first if present
    if let Some(phase) = mitre_phase
        && seen_phases.insert(phase)
    {
        phases_observed.push(phase);
    }
    for step in &steps {
        if step.phase != AttackPhase::Unknown && seen_phases.insert(step.phase) {
            phases_observed.push(step.phase);
        }
    }

    // 6. Extract actor chain (ordered by first appearance)
    let mut actors = Vec::new();
    let mut seen_actors = HashSet::new();
    for step in &steps {
        if let Some(ref actor) = step.actor
            && seen_actors.insert(actor.clone())
        {
            actors.push(actor.clone());
        }
    }

    // 7. Identify entry point (first IP node with AuthenticatedFrom edge)
    let entry_point = find_entry_point(graph, &steps);

    // 8. Assess impact
    let impact_assessment = assess_impact(graph, &steps, &reachable);

    // 9. Generate executive summary
    let summary = generate_summary(
        finding_label,
        &steps,
        &phases_observed,
        &actors,
        entry_point.as_ref(),
    );

    AttackNarrative {
        finding_id: finding_id.to_string(),
        finding_label: finding_label.to_string(),
        steps,
        summary,
        phases_observed,
        actors,
        entry_point,
        impact_assessment,
        node_count: reachable.len(),
        edge_count: subgraph_edges.len(),
    }
}

/// Classify a graph edge into an attack step with phase and narrative.
fn classify_edge(edge: &GraphEdge, graph: &SecurityGraph) -> Option<AttackStep> {
    let source = graph.get_node(&edge.source_id);
    let target = graph.get_node(&edge.target_id);

    let source_label = source.map_or_else(|| edge.source_id.clone(), |n| n.label.clone());
    let target_label = target.map_or_else(|| edge.target_id.clone(), |n| n.label.clone());

    let (phase, action, narrative) = match edge.edge_type {
        EdgeType::AuthenticatedFrom => classify_authentication(edge, &source_label, &target_label),
        EdgeType::CalledApi => classify_api_call(edge, &source_label, &target_label),
        EdgeType::AccessedResource => classify_resource_access(&source_label, &target_label),
        EdgeType::CommunicatedWith => {
            classify_network_flow(edge, graph, &source_label, &target_label)
        }
        EdgeType::ResolvedTo => (
            AttackPhase::Discovery,
            format!("DNS resolution to {target_label}"),
            format!("{source_label} resolved {target_label}."),
        ),
        EdgeType::TriggeredBy | EdgeType::RelatedTo => return None,
        EdgeType::OriginatedFrom => (
            AttackPhase::InitialAccess,
            format!("Activity from {target_label}"),
            format!("Event originated from {target_label}."),
        ),
        EdgeType::PerformedBy => (
            AttackPhase::Unknown,
            format!("Performed by {target_label}"),
            format!("Action performed by {target_label}."),
        ),
        EdgeType::Targeted => (
            AttackPhase::Unknown,
            format!("Targeted {target_label}"),
            format!("{source_label} targeted {target_label}."),
        ),
    };

    let actor = source
        .filter(|n| n.node_type == NodeType::Principal)
        .map(|n| n.label.clone());

    let target_str = target
        .filter(|n| {
            matches!(
                n.node_type,
                NodeType::Resource | NodeType::IPAddress | NodeType::APIOperation
            )
        })
        .map(|n| n.label.clone());

    Some(AttackStep {
        phase,
        timestamp: edge.first_seen,
        actor,
        action,
        target: target_str,
        edge_type: Some(edge.edge_type.clone()),
        node_ids: vec![edge.source_id.clone(), edge.target_id.clone()],
        narrative,
        event_count: edge.event_count,
    })
}

/// Classify an `AuthenticatedFrom` edge.
fn classify_authentication(
    edge: &GraphEdge,
    principal: &str,
    ip: &str,
) -> (AttackPhase, String, String) {
    let phase = if edge.event_count > 10 {
        // Many auth events from same IP could indicate brute force
        AttackPhase::CredentialAccess
    } else {
        AttackPhase::InitialAccess
    };

    let action = format!("Authenticated from {ip}");
    let narrative = if edge.event_count > 1 {
        format!(
            "{principal} authenticated from {ip} ({} times).",
            edge.event_count
        )
    } else {
        format!("{principal} authenticated from {ip}.")
    };

    (phase, action, narrative)
}

/// Classify a `CalledApi` edge by looking up the operation name.
fn classify_api_call(
    _edge: &GraphEdge,
    principal: &str,
    api_label: &str,
) -> (AttackPhase, String, String) {
    // API node labels are "service:operation" (e.g. "s3:GetObject")
    let operation = api_label.split(':').nth(1).unwrap_or(api_label);

    let phase = classify_operation(operation);

    let action = format!("Called {api_label}");
    let narrative = match phase {
        AttackPhase::Persistence => {
            format!("{principal} called {api_label} — establishing persistence.")
        }
        AttackPhase::PrivilegeEscalation => {
            format!("{principal} called {api_label} — escalating privileges.")
        }
        AttackPhase::DefenseEvasion => {
            format!("{principal} called {api_label} — evading detection.")
        }
        AttackPhase::CredentialAccess => {
            format!("{principal} called {api_label} — obtaining new credentials.")
        }
        AttackPhase::Discovery => {
            format!("{principal} called {api_label} — enumerating the environment.")
        }
        AttackPhase::Collection => {
            format!("{principal} called {api_label} — collecting data.")
        }
        AttackPhase::Execution => {
            format!("{principal} called {api_label} — executing code.")
        }
        AttackPhase::Exfiltration => {
            format!("{principal} called {api_label} — moving data out.")
        }
        AttackPhase::Impact => {
            format!("{principal} called {api_label} — modifying or destroying resources.")
        }
        _ => {
            format!("{principal} called {api_label}.")
        }
    };

    (phase, action, narrative)
}

/// Classify an `AccessedResource` edge.
fn classify_resource_access(
    api_label: &str,
    resource_label: &str,
) -> (AttackPhase, String, String) {
    // If the API operation is a collection/exfiltration op, propagate that phase.
    // Otherwise default to Collection (accessing a resource is inherently collection).
    let operation = api_label.split(':').nth(1).unwrap_or(api_label);
    let phase = match classify_operation(operation) {
        AttackPhase::Unknown => AttackPhase::Collection,
        p => p,
    };

    let action = format!("Accessed {resource_label}");
    let narrative = format!("{api_label} accessed resource {resource_label}.");

    (phase, action, narrative)
}

/// Classify a `CommunicatedWith` (network flow) edge.
fn classify_network_flow(
    edge: &GraphEdge,
    _graph: &SecurityGraph,
    src_label: &str,
    dst_label: &str,
) -> (AttackPhase, String, String) {
    let bytes_out = edge
        .properties
        .get("bytes_out")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let bytes_in = edge
        .properties
        .get("bytes_in")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    let src_internal = is_internal_ip(src_label);
    let dst_internal = is_internal_ip(dst_label);

    // Large outbound to external → Exfiltration
    // Internal-to-internal → Lateral Movement
    // External inbound → could be C2
    let (phase, context) = if src_internal && !dst_internal && bytes_out > 10_000_000 {
        (
            AttackPhase::Exfiltration,
            format!(" — {} outbound to external host", format_bytes(bytes_out)),
        )
    } else if src_internal && dst_internal {
        (AttackPhase::LateralMovement, String::new())
    } else if !src_internal && dst_internal && bytes_in > 0 {
        (
            AttackPhase::InitialAccess,
            " — inbound from external".into(),
        )
    } else {
        (AttackPhase::Unknown, String::new())
    };

    let action = format!("Network flow to {dst_label}");
    let narrative = format!("{src_label} communicated with {dst_label}{context}.",);

    (phase, action, narrative)
}

/// Check if an IP label looks like an RFC1918 private address.
///
/// Delegates to [`super::models::IPAddressNode::is_rfc1918`] which correctly
/// parses 172.16-31.x.x (the prefix-matching approach got 172.32+ wrong).
fn is_internal_ip(label: &str) -> bool {
    super::models::IPAddressNode::is_rfc1918(label)
}

/// Format byte count for narrative use.
fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        #[allow(clippy::cast_precision_loss)]
        let gb = bytes as f64 / 1_000_000_000.0;
        format!("{gb:.1} GB")
    } else if bytes >= 1_000_000 {
        #[allow(clippy::cast_precision_loss)]
        let mb = bytes as f64 / 1_000_000.0;
        format!("{mb:.1} MB")
    } else if bytes >= 1_000 {
        #[allow(clippy::cast_precision_loss)]
        let kb = bytes as f64 / 1_000.0;
        format!("{kb:.1} KB")
    } else {
        format!("{bytes} B")
    }
}

/// Find the entry point IP from the attack steps.
fn find_entry_point(graph: &SecurityGraph, steps: &[AttackStep]) -> Option<String> {
    // Look for the earliest AuthenticatedFrom edge — its target is the entry IP
    for step in steps {
        if step.edge_type.as_ref() == Some(&EdgeType::AuthenticatedFrom)
            && let Some(target_id) = step.node_ids.get(1)
            && let Some(node) = graph.get_node(target_id)
            && node.node_type == NodeType::IPAddress
        {
            return Some(node.label.clone());
        }
    }
    None
}

/// Assess the impact of the attack based on observed steps.
fn assess_impact(
    _graph: &SecurityGraph,
    steps: &[AttackStep],
    _reachable: &HashSet<String>,
) -> String {
    let mut concerns = Vec::new();

    let has_persistence = steps.iter().any(|s| s.phase == AttackPhase::Persistence);
    let has_priv_esc = steps
        .iter()
        .any(|s| s.phase == AttackPhase::PrivilegeEscalation);
    let has_defense_evasion = steps.iter().any(|s| s.phase == AttackPhase::DefenseEvasion);
    let has_exfiltration = steps.iter().any(|s| s.phase == AttackPhase::Exfiltration);
    let has_impact = steps.iter().any(|s| s.phase == AttackPhase::Impact);
    let has_collection = steps.iter().any(|s| s.phase == AttackPhase::Collection);

    if has_defense_evasion {
        concerns.push("Audit logging may have been tampered with");
    }
    if has_persistence {
        concerns.push("Attacker may have established persistent access (new credentials/users)");
    }
    if has_priv_esc {
        concerns.push("Privileges were escalated — blast radius may exceed initial access scope");
    }
    if has_exfiltration {
        concerns.push("Data was transferred to external destinations");
    }
    if has_impact {
        concerns.push("Resources were modified or destroyed");
    }
    if has_collection {
        concerns.push("Sensitive data was accessed");
    }

    if concerns.is_empty() {
        "No high-risk activity patterns detected beyond the initial finding.".into()
    } else {
        concerns.join(". ") + "."
    }
}

/// Generate an executive summary from the attack steps.
fn generate_summary(
    finding_label: &str,
    steps: &[AttackStep],
    phases: &[AttackPhase],
    actors: &[String],
    entry_point: Option<&String>,
) -> String {
    use std::fmt::Write;

    let mut summary = String::new();

    // Opening: what triggered the investigation
    let _ = write!(
        summary,
        "Detection '{finding_label}' triggered an investigation"
    );

    if let Some(ip) = entry_point {
        let _ = write!(summary, " originating from {ip}");
    }

    if !actors.is_empty() {
        let actor_list = actors.join(", ");
        let _ = write!(summary, " involving {actor_list}");
    }
    summary.push('.');

    // Kill chain coverage
    if phases.len() > 1 {
        let phase_names: Vec<String> = phases.iter().map(ToString::to_string).collect();
        let _ = write!(
            summary,
            " The attack path spans {} kill chain phases: {}.",
            phases.len(),
            phase_names.join(" → ")
        );
    }

    // Highlight most concerning steps
    let high_concern: Vec<&AttackStep> = steps
        .iter()
        .filter(|s| {
            matches!(
                s.phase,
                AttackPhase::DefenseEvasion
                    | AttackPhase::Exfiltration
                    | AttackPhase::Impact
                    | AttackPhase::Persistence
            )
        })
        .collect();

    if !high_concern.is_empty() {
        let _ = write!(summary, " Key concerns:");
        for step in high_concern.iter().take(3) {
            let _ = write!(summary, " {}", step.narrative);
        }
    }

    summary
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;
    use crate::graph::models::{GraphEdge, GraphNode, NodeType};

    fn make_node(id: &str, node_type: NodeType, label: &str) -> GraphNode {
        GraphNode {
            id: id.to_string(),
            node_type,
            label: label.to_string(),
            properties: HashMap::new(),
            first_seen: None,
            last_seen: None,
            event_count: 0,
        }
    }

    fn make_edge(
        edge_type: EdgeType,
        source: &str,
        target: &str,
        timestamp: Option<DateTime<Utc>>,
    ) -> GraphEdge {
        let id = GraphEdge::create_id(&edge_type, source, target);
        GraphEdge {
            id,
            edge_type,
            source_id: source.to_string(),
            target_id: target.to_string(),
            properties: HashMap::new(),
            weight: 1.0,
            first_seen: timestamp,
            last_seen: timestamp,
            event_count: 1,
        }
    }

    /// Build a minimal attack graph:
    ///   Finding ← `RelatedTo` ← Principal → `AuthenticatedFrom` → IP
    ///   Principal → `CalledApi` → `APIOperation` → `AccessedResource` → Resource
    fn sample_attack_graph() -> SecurityGraph {
        let t1 = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2024, 1, 15, 10, 5, 0).unwrap();
        let t3 = Utc.with_ymd_and_hms(2024, 1, 15, 10, 10, 0).unwrap();
        let t4 = Utc.with_ymd_and_hms(2024, 1, 15, 10, 15, 0).unwrap();

        let mut graph = SecurityGraph::new();

        // Nodes
        let mut finding = make_node(
            "Finding:R001:20240115103000",
            NodeType::SecurityFinding,
            "IAM Privilege Escalation",
        );
        finding.first_seen = Some(t4);
        graph.add_node(finding);

        let mut principal = make_node("Principal:alice", NodeType::Principal, "alice");
        principal.first_seen = Some(t1);
        graph.add_node(principal);

        let mut ip = make_node("IPAddress:10.0.0.1", NodeType::IPAddress, "10.0.0.1");
        ip.first_seen = Some(t1);
        graph.add_node(ip);

        let mut api1 = make_node(
            "APIOperation:iam:AttachRolePolicy",
            NodeType::APIOperation,
            "iam:AttachRolePolicy",
        );
        api1.first_seen = Some(t2);
        graph.add_node(api1);

        let mut api2 = make_node(
            "APIOperation:s3:GetObject",
            NodeType::APIOperation,
            "s3:GetObject",
        );
        api2.first_seen = Some(t3);
        graph.add_node(api2);

        let mut resource = make_node("Resource:role:admin-role", NodeType::Resource, "admin-role");
        resource.first_seen = Some(t2);
        graph.add_node(resource);

        let mut bucket = make_node(
            "Resource:s3:sensitive-data",
            NodeType::Resource,
            "sensitive-data",
        );
        bucket.first_seen = Some(t3);
        graph.add_node(bucket);

        // Edges
        graph.add_edge(make_edge(
            EdgeType::RelatedTo,
            "Principal:alice",
            "Finding:R001:20240115103000",
            Some(t4),
        ));
        graph.add_edge(make_edge(
            EdgeType::AuthenticatedFrom,
            "Principal:alice",
            "IPAddress:10.0.0.1",
            Some(t1),
        ));
        graph.add_edge(make_edge(
            EdgeType::CalledApi,
            "Principal:alice",
            "APIOperation:iam:AttachRolePolicy",
            Some(t2),
        ));
        graph.add_edge(make_edge(
            EdgeType::CalledApi,
            "Principal:alice",
            "APIOperation:s3:GetObject",
            Some(t3),
        ));
        graph.add_edge(make_edge(
            EdgeType::AccessedResource,
            "APIOperation:iam:AttachRolePolicy",
            "Resource:role:admin-role",
            Some(t2),
        ));
        graph.add_edge(make_edge(
            EdgeType::AccessedResource,
            "APIOperation:s3:GetObject",
            "Resource:s3:sensitive-data",
            Some(t3),
        ));

        graph
    }

    // ── classify_operation tests ─────────────────────────────

    #[test]
    fn classify_persistence_operations() {
        assert_eq!(
            classify_operation("CreateAccessKey"),
            AttackPhase::Persistence
        );
        assert_eq!(classify_operation("CreateUser"), AttackPhase::Persistence);
        assert_eq!(
            classify_operation("CreateLoginProfile"),
            AttackPhase::Persistence
        );
    }

    #[test]
    fn classify_priv_esc_operations() {
        assert_eq!(
            classify_operation("AttachRolePolicy"),
            AttackPhase::PrivilegeEscalation
        );
        assert_eq!(
            classify_operation("PutUserPolicy"),
            AttackPhase::PrivilegeEscalation
        );
        assert_eq!(
            classify_operation("CreatePolicyVersion"),
            AttackPhase::PrivilegeEscalation
        );
    }

    #[test]
    fn classify_defense_evasion_operations() {
        assert_eq!(
            classify_operation("StopLogging"),
            AttackPhase::DefenseEvasion
        );
        assert_eq!(
            classify_operation("DeleteTrail"),
            AttackPhase::DefenseEvasion
        );
        assert_eq!(
            classify_operation("DeactivateMFADevice"),
            AttackPhase::DefenseEvasion
        );
    }

    #[test]
    fn classify_discovery_operations() {
        assert_eq!(classify_operation("ListBuckets"), AttackPhase::Discovery);
        assert_eq!(
            classify_operation("GetCallerIdentity"),
            AttackPhase::Discovery
        );
        assert_eq!(
            classify_operation("DescribeInstances"),
            AttackPhase::Discovery
        );
    }

    #[test]
    fn classify_collection_operations() {
        assert_eq!(classify_operation("GetObject"), AttackPhase::Collection);
        assert_eq!(
            classify_operation("GetSecretValue"),
            AttackPhase::Collection
        );
    }

    #[test]
    fn classify_execution_operations() {
        assert_eq!(classify_operation("RunInstances"), AttackPhase::Execution);
        assert_eq!(classify_operation("Invoke"), AttackPhase::Execution);
    }

    #[test]
    fn classify_impact_operations() {
        assert_eq!(classify_operation("DeleteBucket"), AttackPhase::Impact);
        assert_eq!(
            classify_operation("TerminateInstances"),
            AttackPhase::Impact
        );
    }

    #[test]
    fn classify_unknown_operation() {
        assert_eq!(
            classify_operation("GetCallerSomethingWeird"),
            AttackPhase::Unknown
        );
    }

    // ── technique_to_phase tests ──────────────────────────────

    #[test]
    fn technique_to_phase_maps_credential_access() {
        assert_eq!(technique_to_phase("T1110"), AttackPhase::CredentialAccess);
        assert_eq!(
            technique_to_phase("T1110.001"),
            AttackPhase::CredentialAccess
        );
    }

    #[test]
    fn technique_to_phase_maps_defense_evasion() {
        assert_eq!(technique_to_phase("T1562"), AttackPhase::DefenseEvasion);
        assert_eq!(technique_to_phase("T1562.001"), AttackPhase::DefenseEvasion);
    }

    #[test]
    fn technique_to_phase_maps_initial_access() {
        assert_eq!(technique_to_phase("T1078"), AttackPhase::InitialAccess);
        assert_eq!(technique_to_phase("T1078.004"), AttackPhase::InitialAccess);
    }

    #[test]
    fn technique_to_phase_maps_persistence() {
        assert_eq!(technique_to_phase("T1546"), AttackPhase::Persistence);
        assert_eq!(technique_to_phase("T1098"), AttackPhase::Persistence);
    }

    #[test]
    fn technique_to_phase_maps_impact() {
        assert_eq!(technique_to_phase("T1486"), AttackPhase::Impact);
    }

    #[test]
    fn technique_to_phase_maps_discovery() {
        assert_eq!(technique_to_phase("T1087"), AttackPhase::Discovery);
    }

    #[test]
    fn technique_to_phase_unknown_for_unrecognized() {
        assert_eq!(technique_to_phase("T9999"), AttackPhase::Unknown);
    }

    #[test]
    fn mitre_phase_propagates_to_narrative() {
        let t1 = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();

        let mut graph = SecurityGraph::new();

        // Finding with MITRE metadata
        let mut finding = make_node(
            "Finding:R001:20240115103000",
            NodeType::SecurityFinding,
            "Cognito Auth Failure Spike",
        );
        finding.first_seen = Some(t1);
        finding
            .properties
            .insert("mitre_attack".into(), serde_json::json!(["T1110"]));
        graph.add_node(finding);

        // Anonymous principal with OriginatedFrom edge (normally Unknown phase)
        graph.add_node(make_node(
            "IPAddress:66.235.45.23",
            NodeType::IPAddress,
            "66.235.45.23",
        ));
        graph.add_edge(make_edge(
            EdgeType::OriginatedFrom,
            "Finding:R001:20240115103000",
            "IPAddress:66.235.45.23",
            Some(t1),
        ));

        let narratives = extract_attack_paths(&graph);
        assert_eq!(narratives.len(), 1);

        let narrative = &narratives[0];
        // The OriginatedFrom step should inherit CredentialAccess from T1110
        assert!(
            narrative
                .phases_observed
                .contains(&AttackPhase::CredentialAccess),
            "MITRE T1110 should map to CredentialAccess, got: {:?}",
            narrative.phases_observed
        );
    }

    // ── Attack phase ordering ───────────────────────────────

    #[test]
    fn attack_phase_ordinals_increase() {
        assert!(AttackPhase::Reconnaissance.ordinal() < AttackPhase::InitialAccess.ordinal());
        assert!(AttackPhase::InitialAccess.ordinal() < AttackPhase::Persistence.ordinal());
        assert!(AttackPhase::Persistence.ordinal() < AttackPhase::Collection.ordinal());
        assert!(AttackPhase::Collection.ordinal() < AttackPhase::Exfiltration.ordinal());
        assert!(AttackPhase::Exfiltration.ordinal() < AttackPhase::Impact.ordinal());
    }

    #[test]
    fn attack_phase_display() {
        assert_eq!(AttackPhase::InitialAccess.to_string(), "Initial Access");
        assert_eq!(
            AttackPhase::PrivilegeEscalation.to_string(),
            "Privilege Escalation"
        );
        assert_eq!(AttackPhase::DefenseEvasion.to_string(), "Defense Evasion");
    }

    #[test]
    fn attack_phase_serde_roundtrip() {
        let phase = AttackPhase::PrivilegeEscalation;
        let json = serde_json::to_string(&phase).unwrap();
        assert_eq!(json, "\"privilege_escalation\"");
        let back: AttackPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(back, phase);
    }

    // ── Extract attack paths ────────────────────────────────

    #[test]
    fn extract_paths_from_sample_graph() {
        let graph = sample_attack_graph();
        let narratives = extract_attack_paths(&graph);

        assert_eq!(narratives.len(), 1, "expected 1 narrative for 1 finding");
        let narrative = &narratives[0];

        assert_eq!(narrative.finding_id, "Finding:R001:20240115103000");
        assert!(!narrative.steps.is_empty(), "expected attack steps");
        assert!(
            narrative.actors.contains(&"alice".to_string()),
            "alice should be in the actor chain"
        );
        assert_eq!(
            narrative.entry_point,
            Some("10.0.0.1".to_string()),
            "entry point should be 10.0.0.1"
        );
    }

    #[test]
    fn narrative_contains_priv_esc_phase() {
        let graph = sample_attack_graph();
        let narratives = extract_attack_paths(&graph);
        let narrative = &narratives[0];

        assert!(
            narrative
                .phases_observed
                .contains(&AttackPhase::PrivilegeEscalation),
            "should detect privilege escalation from AttachRolePolicy"
        );
    }

    #[test]
    fn narrative_contains_collection_phase() {
        let graph = sample_attack_graph();
        let narratives = extract_attack_paths(&graph);
        let narrative = &narratives[0];

        assert!(
            narrative.phases_observed.contains(&AttackPhase::Collection),
            "should detect collection from GetObject"
        );
    }

    #[test]
    fn narrative_steps_are_chronological() {
        let graph = sample_attack_graph();
        let narratives = extract_attack_paths(&graph);
        let steps = &narratives[0].steps;

        for window in steps.windows(2) {
            if let (Some(t1), Some(t2)) = (window[0].timestamp, window[1].timestamp) {
                assert!(t1 <= t2, "steps should be chronological: {t1} > {t2}");
            }
        }
    }

    #[test]
    fn narrative_summary_mentions_finding() {
        let graph = sample_attack_graph();
        let narratives = extract_attack_paths(&graph);
        let narrative = &narratives[0];

        assert!(
            narrative.summary.contains("IAM Privilege Escalation"),
            "summary should mention finding name: {}",
            narrative.summary
        );
    }

    #[test]
    fn narrative_impact_detects_priv_esc() {
        let graph = sample_attack_graph();
        let narratives = extract_attack_paths(&graph);
        let narrative = &narratives[0];

        assert!(
            narrative.impact_assessment.contains("escalated"),
            "impact should mention privilege escalation: {}",
            narrative.impact_assessment
        );
    }

    // ── Empty / edge cases ──────────────────────────────────

    #[test]
    fn extract_paths_empty_graph() {
        let graph = SecurityGraph::new();
        let narratives = extract_attack_paths(&graph);
        assert!(narratives.is_empty());
    }

    #[test]
    fn extract_paths_no_findings() {
        let mut graph = SecurityGraph::new();
        graph.add_node(make_node("Principal:alice", NodeType::Principal, "alice"));
        let narratives = extract_attack_paths(&graph);
        assert!(narratives.is_empty());
    }

    #[test]
    fn extract_paths_isolated_finding() {
        let mut graph = SecurityGraph::new();
        let mut finding = make_node(
            "Finding:R001:20240115103000",
            NodeType::SecurityFinding,
            "Test Rule",
        );
        finding.first_seen = Some(Utc::now());
        graph.add_node(finding);

        let narratives = extract_attack_paths(&graph);
        // Finding exists but has no edges → empty steps
        assert_eq!(narratives.len(), 0);
    }

    // ── Network flow classification ─────────────────────────

    #[test]
    fn classify_exfiltration_flow() {
        let mut graph = SecurityGraph::new();
        let t = Utc::now();

        graph.add_node(make_node(
            "IPAddress:10.0.0.1",
            NodeType::IPAddress,
            "10.0.0.1",
        ));
        graph.add_node(make_node(
            "IPAddress:203.0.113.50",
            NodeType::IPAddress,
            "203.0.113.50",
        ));

        let mut edge = make_edge(
            EdgeType::CommunicatedWith,
            "IPAddress:10.0.0.1",
            "IPAddress:203.0.113.50",
            Some(t),
        );
        edge.properties
            .insert("bytes_out".into(), json!(50_000_000_u64)); // 50 MB
        edge.properties.insert("bytes_in".into(), json!(1000_u64));
        graph.add_edge(edge);

        // No findings → no narratives, but we can test classify_edge directly
        let edge = &graph.edges[0];
        let step = classify_edge(edge, &graph).unwrap();
        assert_eq!(step.phase, AttackPhase::Exfiltration);
        assert!(step.narrative.contains("50.0 MB"));
    }

    #[test]
    fn classify_lateral_movement_flow() {
        let t = Utc::now();

        let edge = make_edge(
            EdgeType::CommunicatedWith,
            "IPAddress:10.0.0.1",
            "IPAddress:10.0.0.2",
            Some(t),
        );
        // Internal-to-internal with mock nodes
        let mut g = SecurityGraph::new();
        g.add_node(make_node(
            "IPAddress:10.0.0.1",
            NodeType::IPAddress,
            "10.0.0.1",
        ));
        g.add_node(make_node(
            "IPAddress:10.0.0.2",
            NodeType::IPAddress,
            "10.0.0.2",
        ));
        g.add_edge(edge);

        let step = classify_edge(&g.edges[0], &g).unwrap();
        assert_eq!(step.phase, AttackPhase::LateralMovement);
    }

    // ── Multi-actor graph ───────────────────────────────────

    #[test]
    fn narrative_captures_multiple_actors() {
        let t1 = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2024, 1, 15, 10, 5, 0).unwrap();

        let mut graph = SecurityGraph::new();

        let mut finding = make_node(
            "Finding:R001:20240115103000",
            NodeType::SecurityFinding,
            "Test",
        );
        finding.first_seen = Some(t2);
        graph.add_node(finding);
        graph.add_node(make_node("Principal:alice", NodeType::Principal, "alice"));
        graph.add_node(make_node("Principal:bob", NodeType::Principal, "bob"));
        graph.add_node(make_node(
            "IPAddress:10.0.0.1",
            NodeType::IPAddress,
            "10.0.0.1",
        ));

        graph.add_edge(make_edge(
            EdgeType::RelatedTo,
            "Principal:alice",
            "Finding:R001:20240115103000",
            Some(t2),
        ));
        graph.add_edge(make_edge(
            EdgeType::RelatedTo,
            "Principal:bob",
            "Finding:R001:20240115103000",
            Some(t2),
        ));
        graph.add_edge(make_edge(
            EdgeType::AuthenticatedFrom,
            "Principal:alice",
            "IPAddress:10.0.0.1",
            Some(t1),
        ));
        graph.add_edge(make_edge(
            EdgeType::AuthenticatedFrom,
            "Principal:bob",
            "IPAddress:10.0.0.1",
            Some(t1),
        ));

        let narratives = extract_attack_paths(&graph);
        assert_eq!(narratives.len(), 1);
        let narrative = &narratives[0];
        assert!(narrative.actors.contains(&"alice".to_string()));
        assert!(narrative.actors.contains(&"bob".to_string()));
        assert_eq!(narrative.actors.len(), 2);
    }

    // ── format_bytes ────────────────────────────────────────

    #[test]
    fn format_bytes_scales() {
        assert_eq!(format_bytes(42), "42 B");
        assert_eq!(format_bytes(1_500), "1.5 KB");
        assert_eq!(format_bytes(2_500_000), "2.5 MB");
        assert_eq!(format_bytes(1_500_000_000), "1.5 GB");
    }

    // ── is_internal_ip ──────────────────────────────────────

    #[test]
    fn internal_ip_detection() {
        assert!(is_internal_ip("10.0.0.1"));
        assert!(is_internal_ip("192.168.1.1"));
        assert!(is_internal_ip("172.16.0.1"));
        assert!(!is_internal_ip("8.8.8.8"));
        assert!(!is_internal_ip("203.0.113.50"));
    }
}
