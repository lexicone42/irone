use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::graph::{InvestigationTimeline, NodeType, SecurityGraph};

/// Types of reports that can be generated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportType {
    Investigation,
    Detection,
    ExecutiveSummary,
}

/// Summary of entities in an investigation graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySummary {
    pub entity_type: String,
    pub count: usize,
    pub examples: Vec<String>,
}

/// Summary of a detection rule execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResultSummary {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub triggered: bool,
    pub match_count: usize,
    #[serde(default)]
    pub sample_matches: Vec<serde_json::Map<String, Value>>,
    #[serde(default)]
    pub query: String,
}

/// Data model for investigation reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationReportData {
    #[serde(default = "default_investigation_title")]
    pub title: String,
    pub generated_at: DateTime<Utc>,
    #[serde(default)]
    pub investigation_id: String,

    // Executive summary
    #[serde(default)]
    pub executive_summary: String,

    // Graph data
    #[serde(default)]
    pub entity_summaries: Vec<EntitySummary>,
    #[serde(default)]
    pub total_nodes: usize,
    #[serde(default)]
    pub total_edges: usize,

    // Entity details
    #[serde(default)]
    pub principals: Vec<HashMap<String, Value>>,
    #[serde(default)]
    pub ip_addresses: Vec<HashMap<String, Value>>,
    #[serde(default)]
    pub resources: Vec<HashMap<String, Value>>,
    #[serde(default)]
    pub api_operations: Vec<HashMap<String, Value>>,
    #[serde(default)]
    pub findings: Vec<HashMap<String, Value>>,

    // AI analysis
    #[serde(default)]
    pub ai_analysis: String,

    // Timeline data
    #[serde(default)]
    pub timeline_events: Vec<serde_json::Map<String, Value>>,
    #[serde(default)]
    pub timeline_tag_counts: HashMap<String, usize>,
    #[serde(default)]
    pub timeline_ai_summary: String,
    #[serde(default)]
    pub timeline_analyst_summary: String,

    // Metadata
    pub time_range_start: Option<DateTime<Utc>>,
    pub time_range_end: Option<DateTime<Utc>>,
    #[serde(default)]
    pub data_sources: Vec<String>,
}

fn default_investigation_title() -> String {
    "Security Investigation Report".into()
}

/// Data model for detection engineering reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionReportData {
    #[serde(default = "default_detection_title")]
    pub title: String,
    pub generated_at: DateTime<Utc>,

    #[serde(default)]
    pub detection_results: Vec<DetectionResultSummary>,
    #[serde(default)]
    pub total_rules: usize,
    #[serde(default)]
    pub rules_triggered: usize,
    #[serde(default)]
    pub rules_by_severity: HashMap<String, usize>,
    #[serde(default)]
    pub mitre_coverage: Vec<String>,
    #[serde(default)]
    pub ai_suggested_rules: Vec<HashMap<String, Value>>,
    #[serde(default)]
    pub test_summary: String,
}

fn default_detection_title() -> String {
    "Detection Engineering Report".into()
}

/// Complete report container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub report_type: ReportType,
    pub title: String,
    #[serde(default)]
    pub subtitle: String,
    #[serde(default = "default_author")]
    pub author: String,
    pub generated_at: DateTime<Utc>,

    /// The structured data backing this report (Investigation or Detection).
    pub data: ReportData,
}

fn default_author() -> String {
    "iris".into()
}

/// Typed report data — either an investigation or detection report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ReportData {
    Investigation(Box<InvestigationReportData>),
    Detection(DetectionReportData),
}

/// Convert a [`SecurityGraph`] to [`InvestigationReportData`].
pub fn graph_to_report_data(
    graph: &SecurityGraph,
    investigation_id: &str,
    executive_summary: &str,
    ai_analysis: &str,
    time_range_start: Option<DateTime<Utc>>,
    time_range_end: Option<DateTime<Utc>>,
    timeline: Option<&InvestigationTimeline>,
) -> InvestigationReportData {
    let summary = graph.summary();

    // Build entity summaries
    let entity_summaries: Vec<EntitySummary> = summary
        .nodes_by_type
        .iter()
        .map(|(node_type, &count)| {
            let examples: Vec<String> = graph
                .nodes
                .values()
                .filter(|n| n.node_type.to_string() == *node_type)
                .take(5)
                .map(|n| n.label.clone())
                .collect();
            EntitySummary {
                entity_type: node_type.clone(),
                count,
                examples,
            }
        })
        .collect();

    // Extract entities by type
    let mut principals = Vec::new();
    let mut ip_addresses = Vec::new();
    let mut resources = Vec::new();
    let mut api_operations = Vec::new();
    let mut findings = Vec::new();

    for node in graph.nodes.values() {
        let mut props: HashMap<String, Value> = node.properties.clone();
        props.insert("label".into(), Value::String(node.label.clone()));

        match node.node_type {
            NodeType::Principal => principals.push(props),
            NodeType::IPAddress => ip_addresses.push(props),
            NodeType::Resource => resources.push(props),
            NodeType::APIOperation => api_operations.push(props),
            NodeType::SecurityFinding => findings.push(props),
            NodeType::Event => {} // skip raw events
        }
    }

    // Data sources from node properties
    let data_sources: Vec<String> = graph
        .nodes
        .values()
        .filter_map(|n| {
            n.properties
                .get("data_source")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    // Timeline data
    let (timeline_events, timeline_tag_counts, timeline_ai_summary, timeline_analyst_summary) =
        if let Some(tl) = timeline {
            let events: Vec<serde_json::Map<String, Value>> = tl
                .events
                .iter()
                .filter_map(|e| serde_json::to_value(e).ok()?.as_object().cloned())
                .collect();
            let tl_summary = tl.summary();
            (
                events,
                tl_summary.tag_counts,
                tl.ai_summary.clone(),
                tl.analyst_summary.clone(),
            )
        } else {
            (Vec::new(), HashMap::new(), String::new(), String::new())
        };

    InvestigationReportData {
        title: "Security Investigation Report".into(),
        generated_at: Utc::now(),
        investigation_id: investigation_id.into(),
        executive_summary: executive_summary.into(),
        entity_summaries,
        total_nodes: summary.total_nodes,
        total_edges: summary.total_edges,
        principals,
        ip_addresses,
        resources,
        api_operations,
        findings,
        ai_analysis: ai_analysis.into(),
        timeline_events,
        timeline_tag_counts,
        timeline_ai_summary,
        timeline_analyst_summary,
        time_range_start,
        time_range_end,
        data_sources,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{EdgeType, GraphEdge, GraphNode};

    #[test]
    fn report_type_serde() {
        let json = serde_json::to_string(&ReportType::Investigation).unwrap();
        assert_eq!(json, "\"investigation\"");
    }

    #[test]
    fn entity_summary_serde() {
        let es = EntitySummary {
            entity_type: "Principal".into(),
            count: 3,
            examples: vec!["alice".into(), "bob".into()],
        };
        let json = serde_json::to_value(&es).unwrap();
        assert_eq!(json["count"], 3);
    }

    #[test]
    fn graph_to_report_data_basic() {
        let mut graph = SecurityGraph::new();
        graph.add_node(GraphNode {
            id: "p1".into(),
            node_type: NodeType::Principal,
            label: "alice".into(),
            properties: HashMap::new(),
            first_seen: Some(Utc::now()),
            last_seen: Some(Utc::now()),
            event_count: 1,
        });
        graph.add_node(GraphNode {
            id: "ip1".into(),
            node_type: NodeType::IPAddress,
            label: "10.0.0.1".into(),
            properties: HashMap::new(),
            first_seen: Some(Utc::now()),
            last_seen: Some(Utc::now()),
            event_count: 1,
        });
        let edge_id = GraphEdge::create_id(&EdgeType::AuthenticatedFrom, "p1", "ip1");
        graph.add_edge(GraphEdge {
            id: edge_id,
            edge_type: EdgeType::AuthenticatedFrom,
            source_id: "p1".into(),
            target_id: "ip1".into(),
            properties: HashMap::new(),
            weight: 1.0,
            first_seen: Some(Utc::now()),
            last_seen: Some(Utc::now()),
            event_count: 1,
        });

        let report = graph_to_report_data(&graph, "inv-001", "Test summary", "", None, None, None);

        assert_eq!(report.investigation_id, "inv-001");
        assert_eq!(report.total_nodes, 2);
        assert_eq!(report.total_edges, 1);
        assert_eq!(report.principals.len(), 1);
        assert_eq!(report.ip_addresses.len(), 1);
        assert!(report.executive_summary.contains("Test summary"));
    }

    #[test]
    fn graph_to_report_data_with_timeline() {
        let graph = SecurityGraph::new();
        let mut tl = InvestigationTimeline::new("test");
        tl.ai_summary = "AI analysis".into();

        let report = graph_to_report_data(&graph, "inv", "", "", None, None, Some(&tl));
        assert_eq!(report.timeline_ai_summary, "AI analysis");
    }

    #[test]
    fn investigation_report_data_serializes() {
        let report = InvestigationReportData {
            title: "Test".into(),
            generated_at: Utc::now(),
            investigation_id: "inv-1".into(),
            executive_summary: String::new(),
            entity_summaries: Vec::new(),
            total_nodes: 0,
            total_edges: 0,
            principals: Vec::new(),
            ip_addresses: Vec::new(),
            resources: Vec::new(),
            api_operations: Vec::new(),
            findings: Vec::new(),
            ai_analysis: String::new(),
            timeline_events: Vec::new(),
            timeline_tag_counts: HashMap::new(),
            timeline_ai_summary: String::new(),
            timeline_analyst_summary: String::new(),
            time_range_start: None,
            time_range_end: None,
            data_sources: Vec::new(),
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["title"], "Test");
        assert_eq!(json["total_nodes"], 0);
    }
}
