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

/// Container for investigation timeline events with tagging support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationTimeline {
    #[serde(default)]
    pub investigation_id: String,
    #[serde(default)]
    pub events: Vec<TimelineEvent>,
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

/// Extract a timeline from a [`SecurityGraph`].
///
/// Converts graph nodes and edges with timestamps into timeline events.
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
        let description = build_node_description(node);

        let operation = node
            .properties
            .get("operation")
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
    for edge in &graph.edges {
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
        let description = if edge.event_count > 1 {
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
}
