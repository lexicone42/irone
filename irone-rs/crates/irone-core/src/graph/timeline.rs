use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::models::{NodeType, SecurityGraph};

/// Tags for categorizing timeline events during investigation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventTag {
    #[default]
    Unreviewed,
    Important,
    Suspicious,
    Benign,
    AttackPhase,
    InitialAccess,
    Persistence,
    PrivilegeEscalation,
    LateralMovement,
    DataExfiltration,
    Impact,
}

impl std::fmt::Display for EventTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreviewed => write!(f, "unreviewed"),
            Self::Important => write!(f, "important"),
            Self::Suspicious => write!(f, "suspicious"),
            Self::Benign => write!(f, "benign"),
            Self::AttackPhase => write!(f, "attack_phase"),
            Self::InitialAccess => write!(f, "initial_access"),
            Self::Persistence => write!(f, "persistence"),
            Self::PrivilegeEscalation => write!(f, "privilege_escalation"),
            Self::LateralMovement => write!(f, "lateral_movement"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::Impact => write!(f, "impact"),
        }
    }
}

/// Color mapping for event tags (hex CSS colors).
pub static TAG_COLORS: &[(EventTag, &str)] = &[
    (EventTag::Unreviewed, "#A0A0A0"),
    (EventTag::Important, "#FFD700"),
    (EventTag::Suspicious, "#FF6B6B"),
    (EventTag::Benign, "#4ECDC4"),
    (EventTag::AttackPhase, "#FF4757"),
    (EventTag::InitialAccess, "#FF6348"),
    (EventTag::Persistence, "#9B59B6"),
    (EventTag::PrivilegeEscalation, "#E74C3C"),
    (EventTag::LateralMovement, "#F39C12"),
    (EventTag::DataExfiltration, "#C0392B"),
    (EventTag::Impact, "#8E44AD"),
];

impl EventTag {
    /// Get the display color for this tag.
    #[must_use]
    pub fn color(&self) -> &'static str {
        TAG_COLORS
            .iter()
            .find(|(tag, _)| tag == self)
            .map_or("#A0A0A0", |(_, color)| *color)
    }

    /// Whether this tag indicates suspicious or attack-related activity.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        matches!(
            self,
            Self::Suspicious
                | Self::AttackPhase
                | Self::InitialAccess
                | Self::Persistence
                | Self::PrivilegeEscalation
                | Self::LateralMovement
                | Self::DataExfiltration
                | Self::Impact
        )
    }
}

/// A single event in the investigation timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub entity_type: String,
    pub entity_id: String,
    #[serde(default)]
    pub operation: String,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub tag: EventTag,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub properties: HashMap<String, Value>,
}

fn default_status() -> String {
    "success".into()
}

/// A temporal cluster of timeline events — a burst of activity separated from
/// other bursts by a configurable gap threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalCluster {
    pub id: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub event_count: usize,
    pub event_ids: Vec<String>,
    /// Dominant entity (most frequent `entity_id` in the cluster).
    pub dominant_entity: String,
    /// Source distribution: `source_name` → count.
    #[serde(default)]
    pub source_distribution: HashMap<String, usize>,
    /// Seconds of silence before this cluster (`None` for the first cluster).
    pub gap_seconds: Option<i64>,
}

/// Container for investigation timeline events with tagging support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationTimeline {
    #[serde(default)]
    pub investigation_id: String,
    #[serde(default)]
    pub events: Vec<TimelineEvent>,
    #[serde(default)]
    pub clusters: Vec<TemporalCluster>,
    #[serde(default)]
    pub ai_summary: String,
    #[serde(default)]
    pub analyst_summary: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Default for InvestigationTimeline {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            investigation_id: String::new(),
            events: Vec::new(),
            clusters: Vec::new(),
            ai_summary: String::new(),
            analyst_summary: String::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

impl InvestigationTimeline {
    /// Create a new timeline for an investigation.
    #[must_use]
    pub fn new(investigation_id: impl Into<String>) -> Self {
        Self {
            investigation_id: investigation_id.into(),
            ..Default::default()
        }
    }

    /// Add an event (auto-sorts by timestamp).
    pub fn add_event(&mut self, event: TimelineEvent) {
        self.events.push(event);
        self.events.sort_by_key(|e| e.timestamp);
        self.updated_at = Utc::now();
    }

    /// Tag an event with a category and optional notes.
    /// Returns `true` if the event was found and tagged.
    pub fn tag_event(&mut self, event_id: &str, tag: EventTag, notes: &str) -> bool {
        for event in &mut self.events {
            if event.id == event_id {
                event.tag = tag;
                if !notes.is_empty() {
                    event.notes = notes.to_string();
                }
                self.updated_at = Utc::now();
                return true;
            }
        }
        false
    }

    /// Get all events with a specific tag.
    #[must_use]
    pub fn get_events_by_tag(&self, tag: &EventTag) -> Vec<&TimelineEvent> {
        self.events.iter().filter(|e| &e.tag == tag).collect()
    }

    /// Get all unreviewed events.
    #[must_use]
    pub fn get_unreviewed_events(&self) -> Vec<&TimelineEvent> {
        self.get_events_by_tag(&EventTag::Unreviewed)
    }

    /// Get all events tagged as suspicious or attack-related.
    #[must_use]
    pub fn get_suspicious_events(&self) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.tag.is_suspicious())
            .collect()
    }

    /// Get the time range of events.
    #[must_use]
    pub fn time_range(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
        if self.events.is_empty() {
            return (None, None);
        }
        (
            Some(self.events[0].timestamp),
            Some(self.events[self.events.len() - 1].timestamp),
        )
    }

    /// Summary statistics.
    #[must_use]
    pub fn summary(&self) -> TimelineSummary {
        let mut tag_counts: HashMap<String, usize> = HashMap::new();
        for event in &self.events {
            *tag_counts.entry(event.tag.to_string()).or_default() += 1;
        }

        let (start, end) = self.time_range();
        #[allow(clippy::cast_precision_loss)]
        let duration_seconds = match (start, end) {
            (Some(s), Some(e)) => Some((e - s).num_seconds() as f64),
            _ => None,
        };

        TimelineSummary {
            total_events: self.events.len(),
            tag_counts,
            time_range_start: start,
            time_range_end: end,
            duration_seconds,
            has_ai_summary: !self.ai_summary.is_empty(),
            has_analyst_summary: !self.analyst_summary.is_empty(),
        }
    }
}

/// Summary statistics for a timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineSummary {
    pub total_events: usize,
    pub tag_counts: HashMap<String, usize>,
    pub time_range_start: Option<DateTime<Utc>>,
    pub time_range_end: Option<DateTime<Utc>>,
    pub duration_seconds: Option<f64>,
    pub has_ai_summary: bool,
    pub has_analyst_summary: bool,
}

/// Default gap threshold for temporal clustering (5 minutes).
const DEFAULT_GAP_THRESHOLD_SECS: i64 = 300;

/// Cluster timeline events into temporal groups separated by gaps.
///
/// Events must already be sorted by timestamp (which `InvestigationTimeline`
/// guarantees). A new cluster starts when the gap between consecutive events
/// exceeds `gap_threshold_secs`.
#[must_use]
pub fn cluster_timeline_events(
    events: &[TimelineEvent],
    gap_threshold_secs: i64,
) -> Vec<TemporalCluster> {
    if events.is_empty() {
        return Vec::new();
    }

    let mut clusters = Vec::new();
    let mut current_ids: Vec<String> = vec![events[0].id.clone()];
    let mut current_start = events[0].timestamp;
    let mut current_end = events[0].timestamp;
    let mut entity_counts: HashMap<String, usize> = HashMap::new();
    let mut source_counts: HashMap<String, usize> = HashMap::new();
    *entity_counts
        .entry(events[0].entity_id.clone())
        .or_default() += 1;
    if let Some(Value::String(src)) = events[0].properties.get("source_name") {
        *source_counts.entry(src.clone()).or_default() += 1;
    }
    let mut prev_cluster_end: Option<DateTime<Utc>> = None;

    for event in &events[1..] {
        let gap = (event.timestamp - current_end).num_seconds();

        if gap > gap_threshold_secs {
            // Finalize current cluster
            let dominant = dominant_entity(&entity_counts);
            let gap_secs = prev_cluster_end.map(|pe| (current_start - pe).num_seconds());
            clusters.push(TemporalCluster {
                id: format!("cluster-{}", clusters.len()),
                start: current_start,
                end: current_end,
                event_count: current_ids.len(),
                event_ids: current_ids.clone(),
                dominant_entity: dominant,
                source_distribution: source_counts.clone(),
                gap_seconds: gap_secs,
            });

            // Start new cluster
            prev_cluster_end = Some(current_end);
            current_ids.clear();
            entity_counts.clear();
            source_counts.clear();
            current_start = event.timestamp;
        }

        current_ids.push(event.id.clone());
        current_end = event.timestamp;
        *entity_counts.entry(event.entity_id.clone()).or_default() += 1;
        if let Some(Value::String(src)) = event.properties.get("source_name") {
            *source_counts.entry(src.clone()).or_default() += 1;
        }
    }

    // Finalize last cluster
    let dominant = dominant_entity(&entity_counts);
    let gap_secs = prev_cluster_end.map(|pe| (current_start - pe).num_seconds());
    clusters.push(TemporalCluster {
        id: format!("cluster-{}", clusters.len()),
        start: current_start,
        end: current_end,
        event_count: current_ids.len(),
        event_ids: current_ids,
        dominant_entity: dominant,
        source_distribution: source_counts,
        gap_seconds: gap_secs,
    });

    clusters
}

/// Find the entity with the highest count.
fn dominant_entity(counts: &HashMap<String, usize>) -> String {
    counts
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(entity, _)| entity.clone())
        .unwrap_or_default()
}

/// Extract a timeline from a [`SecurityGraph`].
///
/// Converts graph nodes and edges with timestamps into timeline events,
/// then clusters them by temporal proximity.
pub fn extract_timeline_from_graph(
    graph: &SecurityGraph,
    include_nodes: bool,
    include_edges: bool,
) -> InvestigationTimeline {
    let investigation_id = graph
        .metadata
        .get("investigation_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut timeline = InvestigationTimeline::new(investigation_id);

    if include_nodes {
        extract_node_events(graph, &mut timeline);
    }
    if include_edges {
        extract_edge_events(graph, &mut timeline);
    }

    // Cluster events by temporal proximity
    timeline.clusters = cluster_timeline_events(&timeline.events, DEFAULT_GAP_THRESHOLD_SECS);

    timeline
}

fn extract_node_events(graph: &SecurityGraph, timeline: &mut InvestigationTimeline) {
    let type_descriptions: HashMap<NodeType, &str> = [
        (NodeType::Principal, "User/Role activity"),
        (NodeType::IPAddress, "Network activity"),
        (NodeType::Resource, "Resource access"),
        (NodeType::APIOperation, "API call"),
        (NodeType::SecurityFinding, "Security alert"),
        (NodeType::Event, "Security event"),
    ]
    .into_iter()
    .collect();

    for node in graph.nodes.values() {
        let Some(timestamp) = node.first_seen.or(node.last_seen) else {
            continue;
        };

        let type_desc = type_descriptions
            .get(&node.node_type)
            .unwrap_or(&"Activity");
        let title = format!("{type_desc}: {}", node.label);

        // Generate narrative from properties if available, fall back to legacy
        let description = if node.properties.contains_key("class_uid") {
            generate_narrative(&node.properties)
        } else {
            build_node_description(node)
        };

        let operation = node
            .properties
            .get("operation")
            .or_else(|| node.properties.get("api_operation"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let mut event = TimelineEvent {
            id: format!("node:{}", node.id),
            timestamp,
            title,
            description,
            entity_type: node.node_type.to_string(),
            entity_id: node.id.clone(),
            operation,
            status: "success".into(),
            tag: EventTag::Unreviewed,
            notes: String::new(),
            properties: node.properties.clone(),
        };

        // Auto-tag security findings
        if node.node_type == NodeType::SecurityFinding {
            let severity = node
                .properties
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            event.tag = if severity == "critical" || severity == "high" {
                EventTag::Suspicious
            } else {
                EventTag::Important
            };
        }

        timeline.add_event(event);
    }
}

fn build_node_description(node: &super::models::GraphNode) -> String {
    let mut parts = Vec::new();
    match node.node_type {
        NodeType::Principal => {
            if let Some(Value::String(ut)) = node.properties.get("user_type") {
                parts.push(format!("Type: {ut}"));
            }
            if let Some(Value::String(acc)) = node.properties.get("account_id") {
                parts.push(format!("Account: {acc}"));
            }
        }
        NodeType::IPAddress => {
            if let Some(Value::Bool(internal)) = node.properties.get("is_internal") {
                parts.push(
                    if *internal {
                        "Internal IP"
                    } else {
                        "External IP"
                    }
                    .to_string(),
                );
            }
        }
        NodeType::APIOperation => {
            if let Some(Value::Number(n)) = node.properties.get("success_count") {
                parts.push(format!("Success: {n}"));
            }
            if let Some(Value::Number(n)) = node.properties.get("failure_count") {
                parts.push(format!("Failures: {n}"));
            }
        }
        NodeType::Resource => {
            if let Some(Value::String(rt)) = node.properties.get("resource_type") {
                parts.push(format!("Type: {rt}"));
            }
            if let Some(Value::String(region)) = node.properties.get("region") {
                parts.push(format!("Region: {region}"));
            }
        }
        NodeType::SecurityFinding => {
            if let Some(Value::String(sev)) = node.properties.get("severity") {
                parts.push(format!("Severity: {sev}"));
            }
        }
        NodeType::Event => {}
    }
    if node.event_count > 1 {
        parts.push(format!("Event count: {}", node.event_count));
    }
    parts.join(" | ")
}

fn extract_edge_events(graph: &SecurityGraph, timeline: &mut InvestigationTimeline) {
    use super::models::EdgeType;

    for edge in &graph.edges {
        // Skip structural edges that link findings to raw events — these add
        // noise to the timeline without analyst value. The Event nodes
        // themselves already appear in the timeline with full OCSF context.
        if edge.edge_type == EdgeType::TriggeredBy {
            continue;
        }

        let Some(timestamp) = edge.first_seen.or(edge.last_seen) else {
            continue;
        };

        let source_label = graph
            .get_node(&edge.source_id)
            .map_or(&edge.source_id, |n| &n.label);
        let target_label = graph
            .get_node(&edge.target_id)
            .map_or(&edge.target_id, |n| &n.label);

        let title = format!("{}: {source_label} -> {target_label}", edge.edge_type);

        // Generate narrative for edges with OCSF properties
        let description = if edge.properties.contains_key("class_uid") {
            generate_narrative(&edge.properties)
        } else if !edge.properties.is_empty()
            && (edge.properties.contains_key("bytes_in")
                || edge.properties.contains_key("bytes_out"))
        {
            // Network flow edge with byte counts (e.g. from seed graph)
            let mut flow_props = edge.properties.clone();
            // Inject src/dst from node labels for narrative
            flow_props
                .entry("src_endpoint_ip".to_string())
                .or_insert_with(|| Value::String(source_label.clone()));
            flow_props
                .entry("dst_endpoint_ip".to_string())
                .or_insert_with(|| Value::String(target_label.clone()));
            flow_props
                .entry("class_uid".to_string())
                .or_insert_with(|| Value::Number(4001.into()));
            generate_narrative(&flow_props)
        } else if edge.event_count > 1 {
            format!("Occurred {} times", edge.event_count)
        } else {
            String::new()
        };

        let event = TimelineEvent {
            id: format!("edge:{}", edge.id),
            timestamp,
            title,
            description,
            entity_type: "relationship".into(),
            entity_id: edge.id.clone(),
            operation: edge.edge_type.to_string(),
            status: "success".into(),
            tag: EventTag::Unreviewed,
            notes: String::new(),
            properties: edge.properties.clone(),
        };
        timeline.add_event(event);
    }
}

// ─── Narrative Generation ────────────────────────────────────────────

/// Helper: extract a string from a properties `HashMap`.
fn get_prop_str<'a>(props: &'a HashMap<String, Value>, key: &str) -> Option<&'a str> {
    props.get(key).and_then(Value::as_str)
}

/// Format a byte count as a human-readable string.
#[allow(clippy::cast_precision_loss)] // Precision loss is irrelevant for display formatting
fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{bytes} B")
    }
}

/// Generate a narrative description for a timeline event based on its OCSF `class_uid`.
///
/// Dispatches to class-specific narration functions that produce IR-analyst-style
/// descriptions (e.g. "User 'bryan' authenticated to AWS Console from 73.162.45.100").
#[must_use]
#[allow(clippy::implicit_hasher)]
pub fn generate_narrative(props: &HashMap<String, Value>) -> String {
    #[allow(clippy::cast_possible_truncation)] // OCSF class_uid always fits in u32
    let class_uid = props.get("class_uid").and_then(Value::as_u64).unwrap_or(0) as u32;

    let base = match class_uid {
        3002 => narrate_authentication(props),
        6003 | 3001 => narrate_api_activity(props),
        4001 => narrate_network_flow(props),
        4003 => narrate_dns_activity(props),
        _ => narrate_generic(props),
    };

    // Append IR context for sensitive operations
    let context = add_operation_context(props);
    if context.is_empty() {
        base
    } else {
        format!("{base} {context}")
    }
}

/// Narrate an authentication event (`class_uid` 3002).
fn narrate_authentication(props: &HashMap<String, Value>) -> String {
    use std::fmt::Write;

    let user = get_prop_str(props, "actor_user_name").unwrap_or("unknown");
    let user_type = get_prop_str(props, "actor_user_type").unwrap_or("unknown");
    let service = get_prop_str(props, "api_service_name").unwrap_or("AWS");
    let src_ip = get_prop_str(props, "src_endpoint_ip");
    let status = get_prop_str(props, "status").unwrap_or("unknown");

    let mut narrative = format!("User '{user}' ({user_type}) authenticated to {service}");
    if let Some(ip) = src_ip {
        let _ = write!(narrative, " from {ip}");
    }
    let _ = write!(narrative, ". Status: {status}.");
    narrative
}

/// Narrate an API activity event (`class_uid` 6003 / 3001).
fn narrate_api_activity(props: &HashMap<String, Value>) -> String {
    let user = get_prop_str(props, "actor_user_name").unwrap_or("unknown");
    let operation = get_prop_str(props, "api_operation").unwrap_or("unknown");
    let service = get_prop_str(props, "api_service_name").unwrap_or("");
    let resource = get_prop_str(props, "resource_arn");

    let qualified_op = if service.is_empty() {
        operation.to_string()
    } else {
        format!("{service}:{operation}")
    };

    let mut narrative = format!("User '{user}' called {qualified_op}");
    if let Some(arn) = resource {
        use std::fmt::Write;
        let _ = write!(narrative, " targeting {arn}");
    }
    narrative.push('.');
    narrative
}

/// Narrate a network flow event (`class_uid` 4001).
fn narrate_network_flow(props: &HashMap<String, Value>) -> String {
    use std::fmt::Write;

    let src = get_prop_str(props, "src_endpoint_ip").unwrap_or("unknown");
    let dst = get_prop_str(props, "dst_endpoint_ip").unwrap_or("unknown");
    let protocol = get_prop_str(props, "protocol_name").unwrap_or("TCP");

    let bytes_in = props.get("bytes_in").and_then(Value::as_u64).unwrap_or(0);
    let bytes_out = props.get("bytes_out").and_then(Value::as_u64).unwrap_or(0);

    let dst_port_str = props.get("dst_port").map(|v| {
        if let Some(arr) = v.as_array() {
            arr.iter()
                .filter_map(Value::as_u64)
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        } else if let Some(p) = v.as_u64() {
            p.to_string()
        } else {
            String::new()
        }
    });

    let mut narrative = format!("{src} communicated with {dst}");
    if let Some(ref ports) = dst_port_str
        && !ports.is_empty()
    {
        let _ = write!(narrative, " on {protocol}/{ports}");
    }

    if bytes_in > 0 || bytes_out > 0 {
        let _ = write!(
            narrative,
            " \u{2014} {} outbound, {} inbound",
            format_bytes(bytes_out),
            format_bytes(bytes_in)
        );
    }

    narrative
}

/// Narrate a DNS activity event (`class_uid` 4003).
fn narrate_dns_activity(props: &HashMap<String, Value>) -> String {
    let src = get_prop_str(props, "src_endpoint_ip").unwrap_or("unknown host");
    let hostname = get_prop_str(props, "query_hostname").unwrap_or("unknown domain");

    format!("Internal host {src} resolved {hostname}")
}

/// Generic narrative for events without a specific handler.
fn narrate_generic(props: &HashMap<String, Value>) -> String {
    let mut parts = Vec::new();

    if let Some(user) = get_prop_str(props, "actor_user_name") {
        parts.push(format!("User: {user}"));
    }
    if let Some(op) = get_prop_str(props, "api_operation") {
        let service = get_prop_str(props, "api_service_name").unwrap_or("");
        if service.is_empty() {
            parts.push(format!("Operation: {op}"));
        } else {
            parts.push(format!("Operation: {service}:{op}"));
        }
    }
    if let Some(ip) = get_prop_str(props, "src_endpoint_ip") {
        parts.push(format!("Source: {ip}"));
    }
    if let Some(status) = get_prop_str(props, "status") {
        parts.push(format!("Status: {status}"));
    }

    if parts.is_empty() {
        "Security event observed.".into()
    } else {
        parts.join(" | ")
    }
}

/// Append IR-analyst context annotations for sensitive API operations.
fn add_operation_context(props: &HashMap<String, Value>) -> String {
    let Some(operation) = get_prop_str(props, "api_operation") else {
        return String::new();
    };

    match operation {
        "CreateAccessKey" => "This created new programmatic credentials.".into(),
        "DeactivateMFADevice" | "DeleteVirtualMFADevice" => {
            "This removed multi-factor authentication protection.".into()
        }
        "StopLogging" | "DeleteTrail" | "PutEventSelectors" => {
            "This disabled audit logging \u{2014} potential anti-forensics.".into()
        }
        "AssumeRole" | "AssumeRoleWithSAML" | "AssumeRoleWithWebIdentity" => {
            "This assumed a different identity with potentially different permissions.".into()
        }
        "PutBucketPolicy" | "PutBucketAcl" => {
            "This modified access controls on the S3 bucket.".into()
        }
        "AuthorizeSecurityGroupIngress" | "AuthorizeSecurityGroupEgress" => {
            "This opened network access \u{2014} check for overly permissive rules.".into()
        }
        "RunInstances" => "This launched new compute resources.".into(),
        "CreateUser" | "CreateLoginProfile" => "This created a new IAM identity.".into(),
        "AttachUserPolicy" | "AttachRolePolicy" | "PutUserPolicy" | "PutRolePolicy" => {
            "This modified IAM permissions.".into()
        }
        _ => String::new(),
    }
}

/// Generate a prompt for AI timeline summarization.
#[must_use]
pub fn generate_timeline_summary_prompt(timeline: &InvestigationTimeline) -> String {
    let mut event_descriptions = Vec::new();
    for event in &timeline.events {
        let tag_info = if event.tag == EventTag::Unreviewed {
            String::new()
        } else {
            format!(" [{}]", event.tag)
        };
        let desc = if event.description.is_empty() {
            String::new()
        } else {
            format!(" - {}", event.description)
        };
        event_descriptions.push(format!(
            "- {}: {}{tag_info}{desc}",
            event.timestamp.format("%Y-%m-%d %H:%M:%S"),
            event.title,
        ));
    }

    let events_text = event_descriptions.join("\n");
    let summary = timeline.summary();

    let suspicious_tags = [
        "suspicious",
        "attack_phase",
        "initial_access",
        "persistence",
        "privilege_escalation",
        "lateral_movement",
        "data_exfiltration",
        "impact",
    ];
    let suspicious_count: usize = suspicious_tags
        .iter()
        .map(|tag| summary.tag_counts.get(*tag).unwrap_or(&0))
        .sum();

    format!(
        "Analyze this security investigation timeline and provide a concise \
summary for an incident response report.

**Timeline Statistics:**
- Total events: {total}
- Time range: {start} to {end}
- Suspicious/attack events: {suspicious_count}
- Tagged events breakdown: {tag_counts:?}

**Chronological Events:**
{events_text}

**Instructions:**
1. Summarize the key activities observed in chronological order
2. Identify any attack patterns or TTPs (Tactics, Techniques, and Procedures)
3. Highlight the most critical events and their implications
4. Note any gaps or missing information that would help the investigation
5. Provide recommendations for immediate response actions

Format as a professional incident summary for an analyst's report.",
        total = summary.total_events,
        start = summary
            .time_range_start
            .map_or_else(|| "N/A".to_string(), |t| t.to_rfc3339()),
        end = summary
            .time_range_end
            .map_or_else(|| "N/A".to_string(), |t| t.to_rfc3339()),
        tag_counts = summary.tag_counts,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::models::{EdgeType, GraphEdge, GraphNode};

    fn make_event(id: &str, minutes_ago: i64, tag: EventTag) -> TimelineEvent {
        TimelineEvent {
            id: id.into(),
            timestamp: Utc::now() - chrono::Duration::minutes(minutes_ago),
            title: format!("Event {id}"),
            description: String::new(),
            entity_type: "Principal".into(),
            entity_id: "p1".into(),
            operation: String::new(),
            status: "success".into(),
            tag,
            notes: String::new(),
            properties: HashMap::new(),
        }
    }

    #[test]
    fn event_tag_default_is_unreviewed() {
        assert_eq!(EventTag::default(), EventTag::Unreviewed);
    }

    #[test]
    fn event_tag_colors() {
        assert_eq!(EventTag::Suspicious.color(), "#FF6B6B");
        assert_eq!(EventTag::Unreviewed.color(), "#A0A0A0");
    }

    #[test]
    fn event_tag_is_suspicious() {
        assert!(EventTag::Suspicious.is_suspicious());
        assert!(EventTag::InitialAccess.is_suspicious());
        assert!(!EventTag::Benign.is_suspicious());
        assert!(!EventTag::Unreviewed.is_suspicious());
    }

    #[test]
    fn timeline_add_event_sorts_by_timestamp() {
        let mut tl = InvestigationTimeline::new("test");
        tl.add_event(make_event("b", 10, EventTag::Unreviewed)); // older
        tl.add_event(make_event("a", 30, EventTag::Unreviewed)); // oldest
        tl.add_event(make_event("c", 5, EventTag::Unreviewed)); // newest

        assert_eq!(tl.events[0].id, "a");
        assert_eq!(tl.events[1].id, "b");
        assert_eq!(tl.events[2].id, "c");
    }

    #[test]
    fn timeline_tag_event() {
        let mut tl = InvestigationTimeline::new("test");
        tl.add_event(make_event("evt-1", 5, EventTag::Unreviewed));

        assert!(tl.tag_event("evt-1", EventTag::Suspicious, "looks bad"));
        assert_eq!(tl.events[0].tag, EventTag::Suspicious);
        assert_eq!(tl.events[0].notes, "looks bad");

        // Non-existent event returns false
        assert!(!tl.tag_event("missing", EventTag::Benign, ""));
    }

    #[test]
    fn timeline_filter_by_tag() {
        let mut tl = InvestigationTimeline::new("test");
        tl.add_event(make_event("a", 5, EventTag::Suspicious));
        tl.add_event(make_event("b", 4, EventTag::Unreviewed));
        tl.add_event(make_event("c", 3, EventTag::Suspicious));
        tl.add_event(make_event("d", 2, EventTag::Benign));

        assert_eq!(tl.get_events_by_tag(&EventTag::Suspicious).len(), 2);
        assert_eq!(tl.get_unreviewed_events().len(), 1);
        assert_eq!(tl.get_suspicious_events().len(), 2);
    }

    #[test]
    fn timeline_time_range_empty() {
        let tl = InvestigationTimeline::new("test");
        let (start, end) = tl.time_range();
        assert!(start.is_none());
        assert!(end.is_none());
    }

    #[test]
    fn timeline_time_range() {
        let mut tl = InvestigationTimeline::new("test");
        tl.add_event(make_event("a", 30, EventTag::Unreviewed));
        tl.add_event(make_event("b", 5, EventTag::Unreviewed));

        let (start, end) = tl.time_range();
        assert!(start.is_some());
        assert!(end.is_some());
        assert!(start.unwrap() < end.unwrap());
    }

    #[test]
    fn timeline_summary() {
        let mut tl = InvestigationTimeline::new("test");
        tl.add_event(make_event("a", 5, EventTag::Suspicious));
        tl.add_event(make_event("b", 4, EventTag::Unreviewed));
        tl.ai_summary = "AI says something".into();

        let s = tl.summary();
        assert_eq!(s.total_events, 2);
        assert_eq!(*s.tag_counts.get("suspicious").unwrap_or(&0), 1);
        assert_eq!(*s.tag_counts.get("unreviewed").unwrap_or(&0), 1);
        assert!(s.has_ai_summary);
        assert!(!s.has_analyst_summary);
    }

    #[test]
    fn extract_timeline_from_graph_nodes() {
        let mut graph = SecurityGraph::new();
        let t1 = Utc::now() - chrono::Duration::hours(1);
        let t2 = Utc::now();

        let mut n1 = GraphNode {
            id: "p1".into(),
            node_type: NodeType::Principal,
            label: "alice".into(),
            properties: HashMap::new(),
            first_seen: Some(t1),
            last_seen: Some(t1),
            event_count: 1,
        };
        n1.properties
            .insert("user_type".into(), Value::String("IAMUser".into()));
        graph.add_node(n1);

        let n2 = GraphNode {
            id: "ip1".into(),
            node_type: NodeType::IPAddress,
            label: "10.0.0.1".into(),
            properties: HashMap::new(),
            first_seen: Some(t2),
            last_seen: Some(t2),
            event_count: 1,
        };
        graph.add_node(n2);

        let tl = extract_timeline_from_graph(&graph, true, false);
        assert_eq!(tl.events.len(), 2);
        // Sorted by timestamp, so t1 (p1) comes first
        assert!(tl.events[0].title.contains("alice"));
    }

    #[test]
    fn extract_timeline_from_graph_edges() {
        let mut graph = SecurityGraph::new();
        let t = Utc::now();

        graph.add_node(GraphNode {
            id: "a".into(),
            node_type: NodeType::Principal,
            label: "alice".into(),
            properties: HashMap::new(),
            first_seen: None,
            last_seen: None,
            event_count: 0,
        });
        graph.add_node(GraphNode {
            id: "b".into(),
            node_type: NodeType::IPAddress,
            label: "10.0.0.1".into(),
            properties: HashMap::new(),
            first_seen: None,
            last_seen: None,
            event_count: 0,
        });

        let edge_id = GraphEdge::create_id(&EdgeType::AuthenticatedFrom, "a", "b");
        graph.add_edge(GraphEdge {
            id: edge_id,
            edge_type: EdgeType::AuthenticatedFrom,
            source_id: "a".into(),
            target_id: "b".into(),
            properties: HashMap::new(),
            weight: 1.0,
            first_seen: Some(t),
            last_seen: Some(t),
            event_count: 3,
        });

        let tl = extract_timeline_from_graph(&graph, false, true);
        assert_eq!(tl.events.len(), 1);
        assert!(tl.events[0].title.contains("AUTHENTICATED_FROM"));
        assert!(tl.events[0].description.contains("3 times"));
    }

    #[test]
    fn extract_timeline_auto_tags_findings() {
        let mut graph = SecurityGraph::new();
        let t = Utc::now();

        let mut props = HashMap::new();
        props.insert("severity".into(), Value::String("critical".into()));

        graph.add_node(GraphNode {
            id: "f1".into(),
            node_type: NodeType::SecurityFinding,
            label: "Root Login".into(),
            properties: props,
            first_seen: Some(t),
            last_seen: Some(t),
            event_count: 1,
        });

        let tl = extract_timeline_from_graph(&graph, true, false);
        assert_eq!(tl.events[0].tag, EventTag::Suspicious);
    }

    #[test]
    fn generate_prompt_includes_events() {
        let mut tl = InvestigationTimeline::new("test");
        tl.add_event(make_event("a", 5, EventTag::Suspicious));

        let prompt = generate_timeline_summary_prompt(&tl);
        assert!(prompt.contains("Event a"));
        assert!(prompt.contains("suspicious"));
        assert!(prompt.contains("Total events: 1"));
    }

    #[test]
    fn event_tag_serde_roundtrip() {
        let tag = EventTag::PrivilegeEscalation;
        let json = serde_json::to_string(&tag).unwrap();
        assert_eq!(json, "\"privilege_escalation\"");
        let back: EventTag = serde_json::from_str(&json).unwrap();
        assert_eq!(back, EventTag::PrivilegeEscalation);
    }

    // ─── Narrative generation tests ─────────────────────────

    #[test]
    fn format_bytes_scales() {
        assert_eq!(super::format_bytes(42), "42 B");
        assert_eq!(super::format_bytes(1_500), "1.5 KB");
        assert_eq!(super::format_bytes(2_500_000), "2.5 MB");
        assert_eq!(super::format_bytes(1_500_000_000), "1.5 GB");
    }

    #[test]
    fn narrate_authentication_event() {
        let mut props = HashMap::new();
        props.insert("class_uid".into(), Value::Number(3002.into()));
        props.insert("actor_user_name".into(), Value::String("bryan".into()));
        props.insert("actor_user_type".into(), Value::String("IAMUser".into()));
        props.insert(
            "api_service_name".into(),
            Value::String("AWS Console".into()),
        );
        props.insert(
            "src_endpoint_ip".into(),
            Value::String("73.162.45.100".into()),
        );
        props.insert("status".into(), Value::String("Success".into()));

        let narrative = super::generate_narrative(&props);
        assert!(narrative.contains("bryan"));
        assert!(narrative.contains("IAMUser"));
        assert!(narrative.contains("73.162.45.100"));
        assert!(narrative.contains("Success"));
    }

    #[test]
    fn narrate_api_activity_with_context() {
        let mut props = HashMap::new();
        props.insert("class_uid".into(), Value::Number(6003.into()));
        props.insert(
            "actor_user_name".into(),
            Value::String("unknown-actor".into()),
        );
        props.insert(
            "api_operation".into(),
            Value::String("CreateAccessKey".into()),
        );
        props.insert("api_service_name".into(), Value::String("iam".into()));
        props.insert(
            "resource_arn".into(),
            Value::String("arn:aws:iam::651804262336:user/bryan".into()),
        );

        let narrative = super::generate_narrative(&props);
        assert!(narrative.contains("unknown-actor"));
        assert!(narrative.contains("iam:CreateAccessKey"));
        assert!(narrative.contains("arn:aws:iam"));
        // Should include IR context for CreateAccessKey
        assert!(narrative.contains("programmatic credentials"));
    }

    #[test]
    fn narrate_network_flow_event() {
        let mut props = HashMap::new();
        props.insert("class_uid".into(), Value::Number(4001.into()));
        props.insert("src_endpoint_ip".into(), Value::String("10.0.1.50".into()));
        props.insert(
            "dst_endpoint_ip".into(),
            Value::String("203.0.113.66".into()),
        );
        props.insert("protocol_name".into(), Value::String("TCP".into()));
        props.insert("dst_port".into(), Value::Number(443.into()));
        props.insert("bytes_in".into(), Value::Number(45_000.into()));
        props.insert("bytes_out".into(), Value::Number(150_000_000_u64.into()));

        let narrative = super::generate_narrative(&props);
        assert!(narrative.contains("10.0.1.50"));
        assert!(narrative.contains("203.0.113.66"));
        assert!(narrative.contains("TCP/443"));
        assert!(narrative.contains("150.0 MB"));
        assert!(narrative.contains("45.0 KB"));
    }

    #[test]
    fn narrate_dns_activity_event() {
        let mut props = HashMap::new();
        props.insert("class_uid".into(), Value::Number(4003.into()));
        props.insert("src_endpoint_ip".into(), Value::String("10.0.1.50".into()));
        props.insert(
            "query_hostname".into(),
            Value::String("c2-callback.evil.com".into()),
        );

        let narrative = super::generate_narrative(&props);
        assert!(narrative.contains("10.0.1.50"));
        assert!(narrative.contains("c2-callback.evil.com"));
    }

    #[test]
    fn narrate_generic_event() {
        let mut props = HashMap::new();
        props.insert("class_uid".into(), Value::Number(9999.into()));
        props.insert("actor_user_name".into(), Value::String("alice".into()));
        props.insert("status".into(), Value::String("Success".into()));

        let narrative = super::generate_narrative(&props);
        assert!(narrative.contains("alice"));
        assert!(narrative.contains("Success"));
    }

    #[test]
    fn operation_context_annotations() {
        let cases = vec![
            ("CreateAccessKey", "programmatic credentials"),
            ("DeactivateMFADevice", "multi-factor authentication"),
            ("StopLogging", "audit logging"),
            ("AssumeRole", "different identity"),
            ("PutBucketPolicy", "access controls"),
        ];

        for (op, expected_fragment) in cases {
            let mut props = HashMap::new();
            props.insert("api_operation".into(), Value::String(op.into()));
            let ctx = super::add_operation_context(&props);
            assert!(
                ctx.contains(expected_fragment),
                "operation '{op}' context should contain '{expected_fragment}', got: '{ctx}'"
            );
        }
    }

    #[test]
    fn no_context_for_benign_operations() {
        let mut props = HashMap::new();
        props.insert(
            "api_operation".into(),
            Value::String("DescribeInstances".into()),
        );
        let ctx = super::add_operation_context(&props);
        assert!(ctx.is_empty());
    }

    // ─── Temporal clustering tests ───────────────────────────

    fn make_timed_event(
        id: &str,
        timestamp: DateTime<Utc>,
        entity_id: &str,
        source_name: Option<&str>,
    ) -> TimelineEvent {
        let mut properties = HashMap::new();
        if let Some(src) = source_name {
            properties.insert("source_name".into(), Value::String(src.into()));
        }
        TimelineEvent {
            id: id.into(),
            timestamp,
            title: format!("Event {id}"),
            description: String::new(),
            entity_type: "Principal".into(),
            entity_id: entity_id.into(),
            operation: String::new(),
            status: "success".into(),
            tag: EventTag::Unreviewed,
            notes: String::new(),
            properties,
        }
    }

    #[test]
    fn temporal_clustering_basic() {
        // 3 events close together (1 min apart), gap, 2 events close together
        let base = Utc::now() - chrono::Duration::hours(1);
        let events = vec![
            make_timed_event("a", base, "user:alice", Some("cloudtrail")),
            make_timed_event(
                "b",
                base + chrono::Duration::minutes(1),
                "user:alice",
                Some("cloudtrail"),
            ),
            make_timed_event(
                "c",
                base + chrono::Duration::minutes(2),
                "user:bob",
                Some("vpc-flow"),
            ),
            // 10 min gap (> 5 min threshold)
            make_timed_event(
                "d",
                base + chrono::Duration::minutes(12),
                "user:alice",
                Some("route53"),
            ),
            make_timed_event(
                "e",
                base + chrono::Duration::minutes(13),
                "user:alice",
                Some("route53"),
            ),
        ];

        let clusters = super::cluster_timeline_events(&events, 300);
        assert_eq!(
            clusters.len(),
            2,
            "expected 2 clusters, got {}",
            clusters.len()
        );

        // First cluster: 3 events
        assert_eq!(clusters[0].event_count, 3);
        assert_eq!(clusters[0].event_ids, vec!["a", "b", "c"]);
        assert_eq!(clusters[0].dominant_entity, "user:alice"); // alice: 2, bob: 1
        assert!(clusters[0].gap_seconds.is_none()); // first cluster

        // Second cluster: 2 events
        assert_eq!(clusters[1].event_count, 2);
        assert_eq!(clusters[1].event_ids, vec!["d", "e"]);
        assert_eq!(clusters[1].dominant_entity, "user:alice");
        assert!(clusters[1].gap_seconds.unwrap() > 500); // ~10 min gap
    }

    #[test]
    fn temporal_clustering_single_cluster() {
        let base = Utc::now();
        let events = vec![
            make_timed_event("a", base, "user:alice", None),
            make_timed_event("b", base + chrono::Duration::minutes(1), "user:alice", None),
            make_timed_event("c", base + chrono::Duration::minutes(2), "user:alice", None),
        ];

        let clusters = super::cluster_timeline_events(&events, 300);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].event_count, 3);
        assert!(clusters[0].gap_seconds.is_none());
    }

    #[test]
    fn temporal_clustering_empty() {
        let clusters = super::cluster_timeline_events(&[], 300);
        assert!(clusters.is_empty());
    }

    #[test]
    fn cluster_dominant_entity() {
        let base = Utc::now();
        let events = vec![
            make_timed_event("a", base, "user:alice", None),
            make_timed_event("b", base + chrono::Duration::seconds(30), "user:bob", None),
            make_timed_event("c", base + chrono::Duration::seconds(60), "user:bob", None),
            make_timed_event("d", base + chrono::Duration::seconds(90), "user:bob", None),
        ];

        let clusters = super::cluster_timeline_events(&events, 300);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].dominant_entity, "user:bob"); // bob: 3, alice: 1
    }

    #[test]
    fn cluster_source_distribution() {
        let base = Utc::now();
        let events = vec![
            make_timed_event("a", base, "user:alice", Some("cloudtrail")),
            make_timed_event(
                "b",
                base + chrono::Duration::seconds(30),
                "user:alice",
                Some("cloudtrail"),
            ),
            make_timed_event(
                "c",
                base + chrono::Duration::seconds(60),
                "user:alice",
                Some("vpc-flow"),
            ),
        ];

        let clusters = super::cluster_timeline_events(&events, 300);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].source_distribution.get("cloudtrail"), Some(&2));
        assert_eq!(clusters[0].source_distribution.get("vpc-flow"), Some(&1));
    }
}
