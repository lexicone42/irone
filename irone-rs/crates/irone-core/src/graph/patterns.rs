//! Graph-based pattern detection for security investigation graphs.
//!
//! Detects structural anomalies in a [`SecurityGraph`] that per-event detection
//! rules cannot catch. These patterns emerge from *relationships between entities*
//! rather than individual event properties.
//!
//! # Design philosophy
//!
//! Event-based detection (the 45 YAML rules) answers: "did this event look bad?"
//! Graph-pattern detection answers: "does this *topology* look bad?" The two
//! approaches are complementary — event rules catch known-bad operations, while
//! graph patterns catch unexpected structural relationships.
//!
//! # Pattern types
//!
//! - **Privilege fanout**: A principal accessing an unusual breadth of API services
//!   (reconnaissance or post-compromise enumeration)
//! - **Resource convergence**: Multiple unrelated principals accessing the same
//!   resource (indicates a high-value target or shared-credential abuse)
//! - **Impossible travel**: A principal authenticating from geographically
//!   incompatible IPs within a short time window
//! - **Service bridge**: A principal connecting two otherwise-disconnected service
//!   clusters (lateral movement between service boundaries)

use std::collections::{HashMap, HashSet};

use chrono::TimeDelta;
use serde::{Deserialize, Serialize};

use super::models::{Direction, EdgeType, NodeType, SecurityGraph};

/// A structural pattern detected in the investigation graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphPattern {
    /// What kind of pattern was detected.
    pub pattern_type: PatternType,
    /// Severity estimate (0.0–1.0). Higher = more concerning.
    pub severity: f64,
    /// Human-readable description for IR analysts.
    pub description: String,
    /// Machine-readable description for AI investigators.
    pub analysis_hint: String,
    /// Graph node IDs involved in this pattern.
    pub involved_nodes: Vec<String>,
    /// Graph edge IDs involved in this pattern.
    pub involved_edges: Vec<String>,
}

/// Categories of graph-structural patterns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternType {
    /// Principal accessing an unusual breadth of distinct API services.
    PrivilegeFanout,
    /// Multiple unrelated principals accessing the same resource.
    ResourceConvergence,
    /// Principal authenticating from multiple distinct external IPs.
    MultiSourceAuth,
    /// Principal bridging otherwise-disconnected service clusters.
    ServiceBridge,
}

impl std::fmt::Display for PatternType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrivilegeFanout => write!(f, "Privilege Fanout"),
            Self::ResourceConvergence => write!(f, "Resource Convergence"),
            Self::MultiSourceAuth => write!(f, "Multi-Source Authentication"),
            Self::ServiceBridge => write!(f, "Service Bridge"),
        }
    }
}

/// Run all graph-pattern detectors against an investigation graph.
///
/// Returns patterns sorted by severity (highest first). Each detector is
/// independent — they examine different structural properties of the graph.
#[must_use]
pub fn detect_patterns(graph: &SecurityGraph) -> Vec<GraphPattern> {
    let mut patterns = Vec::new();

    detect_privilege_fanout(graph, &mut patterns);
    detect_resource_convergence(graph, &mut patterns);
    detect_multi_source_auth(graph, &mut patterns);
    detect_service_bridges(graph, &mut patterns);

    patterns.sort_by(|a, b| {
        b.severity
            .partial_cmp(&a.severity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    patterns
}

// ─── Privilege Fanout ──────────────────────────────────────────────────

/// Detect principals accessing an unusually broad set of AWS services.
///
/// Traces: `Principal` → `CalledApi` → `APIOperation`, then counts distinct services
/// (the part before ":" in the API label, e.g., "s3" from "s3:GetObject").
///
/// A principal touching 5+ distinct services in one investigation window is
/// unusual for most human users (service accounts are expected to be narrow).
const FANOUT_SERVICE_THRESHOLD: usize = 5;

fn detect_privilege_fanout(graph: &SecurityGraph, out: &mut Vec<GraphPattern>) {
    let principals = graph.get_nodes_by_type(&NodeType::Principal);

    for principal in &principals {
        let api_edges = graph.get_edges_for_node(&principal.id, Direction::Outgoing);
        let api_edges: Vec<_> = api_edges
            .iter()
            .filter(|e| e.edge_type == EdgeType::CalledApi)
            .collect();

        // Extract distinct services from API operation labels
        let mut services: HashSet<String> = HashSet::new();
        let mut api_node_ids: Vec<String> = Vec::new();
        let mut edge_ids: Vec<String> = Vec::new();

        for edge in &api_edges {
            if let Some(api_node) = graph.get_node(&edge.target_id) {
                // API labels are "service:operation" (e.g., "s3:GetObject")
                if let Some(service) = api_node.label.split(':').next() {
                    services.insert(service.to_string());
                }
                api_node_ids.push(api_node.id.clone());
                edge_ids.push(edge.id.clone());
            }
        }

        if services.len() >= FANOUT_SERVICE_THRESHOLD {
            let service_list: Vec<_> = {
                let mut s: Vec<_> = services.iter().cloned().collect();
                s.sort();
                s
            };

            // Severity scales from 0.4 (at threshold) to 0.9 (at 2× threshold)
            #[allow(clippy::cast_precision_loss)]
            let severity = (0.4
                + 0.5
                    * ((services.len() - FANOUT_SERVICE_THRESHOLD) as f64
                        / FANOUT_SERVICE_THRESHOLD as f64))
                .min(0.9);

            let mut involved_nodes = vec![principal.id.clone()];
            involved_nodes.extend(api_node_ids);

            out.push(GraphPattern {
                pattern_type: PatternType::PrivilegeFanout,
                severity,
                description: format!(
                    "{} accessed {} distinct AWS services: {}",
                    principal.label,
                    services.len(),
                    service_list.join(", ")
                ),
                analysis_hint: format!(
                    "Principal '{}' touched {} services in the investigation window. \
                     Investigate whether this breadth is expected for this identity type. \
                     Service accounts should typically access 1-2 services. \
                     Human users accessing 5+ services may indicate post-compromise enumeration \
                     or overly permissive IAM policies.",
                    principal.label,
                    services.len()
                ),
                involved_nodes,
                involved_edges: edge_ids,
            });
        }
    }
}

// ─── Resource Convergence ──────────────────────────────────────────────

/// Detect resources accessed by multiple distinct principals.
///
/// Traces: `APIOperation` → `AccessedResource` → `Resource`, then for each resource
/// looks backwards to find distinct principals. Multiple unrelated users
/// accessing the same resource is a signal of shared-credential abuse or a
/// high-value target.
const CONVERGENCE_PRINCIPAL_THRESHOLD: usize = 3;

fn detect_resource_convergence(graph: &SecurityGraph, out: &mut Vec<GraphPattern>) {
    let resources = graph.get_nodes_by_type(&NodeType::Resource);

    for resource in &resources {
        // Find all API operations that accessed this resource
        let incoming = graph.get_edges_for_node(&resource.id, Direction::Incoming);
        let accessing_apis: Vec<_> = incoming
            .iter()
            .filter(|e| e.edge_type == EdgeType::AccessedResource)
            .collect();

        // Trace back from API operations to principals
        let mut principals: HashSet<String> = HashSet::new();
        let mut all_nodes: Vec<String> = vec![resource.id.clone()];
        let mut all_edges: Vec<String> = Vec::new();

        for api_edge in &accessing_apis {
            all_edges.push(api_edge.id.clone());
            all_nodes.push(api_edge.source_id.clone());

            // Find who called this API
            let callers = graph.get_edges_for_node(&api_edge.source_id, Direction::Incoming);
            for caller_edge in callers {
                if caller_edge.edge_type == EdgeType::CalledApi
                    && let Some(node) = graph.get_node(&caller_edge.source_id)
                    && node.node_type == NodeType::Principal
                {
                    principals.insert(node.label.clone());
                    all_nodes.push(node.id.clone());
                    all_edges.push(caller_edge.id.clone());
                }
            }
        }

        if principals.len() >= CONVERGENCE_PRINCIPAL_THRESHOLD {
            let principal_list: Vec<_> = {
                let mut p: Vec<_> = principals.iter().cloned().collect();
                p.sort();
                p
            };

            #[allow(clippy::cast_precision_loss)]
            let severity = (0.5
                + 0.3
                    * ((principals.len() - CONVERGENCE_PRINCIPAL_THRESHOLD) as f64
                        / CONVERGENCE_PRINCIPAL_THRESHOLD as f64))
                .min(0.9);

            out.push(GraphPattern {
                pattern_type: PatternType::ResourceConvergence,
                severity,
                description: format!(
                    "Resource '{}' accessed by {} distinct principals: {}",
                    resource.label,
                    principals.len(),
                    principal_list.join(", ")
                ),
                analysis_hint: format!(
                    "Resource '{}' was accessed by {} principals ({}). \
                     If these principals are unrelated (different teams/roles), \
                     this resource may be a high-value target or the access may indicate \
                     shared credential abuse. Check if the resource contains sensitive data \
                     and whether all principals have legitimate business need.",
                    resource.label,
                    principals.len(),
                    principal_list.join(", ")
                ),
                involved_nodes: all_nodes,
                involved_edges: all_edges,
            });
        }
    }
}

// ─── Multi-Source Authentication ────────────────────────────────────────

/// Detect principals authenticating from multiple distinct external IPs.
///
/// Legitimate users typically authenticate from 1-2 IPs. A principal with
/// 3+ distinct source IPs (especially external) in a short window suggests
/// credential sharing, stolen tokens, or proxy-hopping.
fn detect_multi_source_auth(graph: &SecurityGraph, out: &mut Vec<GraphPattern>) {
    let principals = graph.get_nodes_by_type(&NodeType::Principal);

    for principal in &principals {
        let auth_edges: Vec<_> = graph
            .get_edges_for_node(&principal.id, Direction::Outgoing)
            .into_iter()
            .filter(|e| e.edge_type == EdgeType::AuthenticatedFrom)
            .collect();

        // Collect distinct IPs (excluding RFC1918)
        let mut external_ips: HashSet<String> = HashSet::new();
        let mut all_ip_ids: Vec<String> = Vec::new();
        let mut edge_ids: Vec<String> = Vec::new();

        for edge in &auth_edges {
            if let Some(ip_node) = graph.get_node(&edge.target_id)
                && ip_node.node_type == NodeType::IPAddress
                && !super::models::IPAddressNode::is_rfc1918(&ip_node.label)
            {
                external_ips.insert(ip_node.label.clone());
                all_ip_ids.push(ip_node.id.clone());
                edge_ids.push(edge.id.clone());
            }
        }

        if external_ips.len() >= 3 {
            let ip_list: Vec<_> = {
                let mut ips: Vec<_> = external_ips.iter().cloned().collect();
                ips.sort();
                ips
            };

            // Check time span — tighter window = higher severity
            let time_span = auth_edges
                .iter()
                .filter_map(|e| {
                    let first = e.first_seen?;
                    let last = e.last_seen?;
                    Some((first, last))
                })
                .fold(None, |acc, (f, l)| match acc {
                    None => Some((f, l)),
                    Some((af, al)) => Some((af.min(f), al.max(l))),
                });

            let short_window = time_span.is_some_and(|(f, l)| l - f < TimeDelta::hours(1));

            #[allow(clippy::cast_precision_loss)]
            let base_severity = 0.5 + 0.1 * (external_ips.len() as f64 - 3.0).min(4.0);
            let severity = if short_window {
                (base_severity + 0.2).min(0.95)
            } else {
                base_severity.min(0.85)
            };

            let window_note = if short_window {
                " within a short time window (< 1 hour)"
            } else {
                ""
            };

            let mut involved_nodes = vec![principal.id.clone()];
            involved_nodes.extend(all_ip_ids);

            out.push(GraphPattern {
                pattern_type: PatternType::MultiSourceAuth,
                severity,
                description: format!(
                    "{} authenticated from {} distinct external IPs{}: {}",
                    principal.label,
                    external_ips.len(),
                    window_note,
                    ip_list.join(", ")
                ),
                analysis_hint: format!(
                    "Principal '{}' used {} external source IPs{}. \
                     This could indicate: (1) credential theft with use from multiple locations, \
                     (2) proxy/VPN rotation to evade IP-based detection, or \
                     (3) legitimate mobile user. Check if the IPs share an ASN or \
                     geolocation — different ASNs strengthen the anomaly signal.",
                    principal.label,
                    external_ips.len(),
                    window_note
                ),
                involved_nodes,
                involved_edges: edge_ids,
            });
        }
    }
}

// ─── Service Bridge ────────────────────────────────────────────────────

/// Detect principals that bridge otherwise-disconnected service clusters.
///
/// In a well-segmented environment, most principals interact with a narrow
/// set of related services. A principal that is the *only* link between two
/// service clusters may be performing lateral movement.
///
/// Algorithm: for each principal, find the sets of services reached. Then
/// check if removing this principal would disconnect any two services
/// (i.e., the principal is an articulation point in the principal-service
/// bipartite graph).
fn detect_service_bridges(graph: &SecurityGraph, out: &mut Vec<GraphPattern>) {
    // Build bipartite graph: service → set of principals that access it
    let mut service_to_principals: HashMap<String, HashSet<String>> = HashMap::new();
    let mut principal_to_services: HashMap<String, HashSet<String>> = HashMap::new();

    for edge in &graph.edges {
        if edge.edge_type == EdgeType::CalledApi
            && let (Some(principal), Some(api)) = (
                graph.get_node(&edge.source_id),
                graph.get_node(&edge.target_id),
            )
            && principal.node_type == NodeType::Principal
            && api.node_type == NodeType::APIOperation
            && let Some(service) = api.label.split(':').next()
        {
            service_to_principals
                .entry(service.to_string())
                .or_default()
                .insert(principal.id.clone());
            principal_to_services
                .entry(principal.id.clone())
                .or_default()
                .insert(service.to_string());
        }
    }

    // For each principal, check if they're the sole link between any two services
    for (principal_id, services) in &principal_to_services {
        if services.len() < 2 {
            continue;
        }

        // For each pair of services this principal touches, check if any other
        // principal also touches both
        let service_list: Vec<_> = services.iter().cloned().collect();
        let mut bridged_pairs: Vec<(String, String)> = Vec::new();

        for i in 0..service_list.len() {
            for j in (i + 1)..service_list.len() {
                let svc_a = &service_list[i];
                let svc_b = &service_list[j];

                let principals_a = service_to_principals.get(svc_a);
                let principals_b = service_to_principals.get(svc_b);

                if let (Some(pa), Some(pb)) = (principals_a, principals_b) {
                    // Check if any *other* principal touches both services
                    let shared: Vec<_> = pa
                        .intersection(pb)
                        .filter(|p| p.as_str() != principal_id)
                        .collect();

                    if shared.is_empty() {
                        bridged_pairs.push((svc_a.clone(), svc_b.clone()));
                    }
                }
            }
        }

        if !bridged_pairs.is_empty() {
            let principal_label = graph
                .get_node(principal_id)
                .map_or_else(|| principal_id.clone(), |n| n.label.clone());

            let bridged_services: HashSet<String> = bridged_pairs
                .iter()
                .flat_map(|(a, b)| [a.clone(), b.clone()])
                .collect();
            let mut bridged_list: Vec<_> = bridged_services.into_iter().collect();
            bridged_list.sort();

            #[allow(clippy::cast_precision_loss)]
            let severity = (0.5 + 0.1 * bridged_pairs.len() as f64).min(0.85);

            out.push(GraphPattern {
                pattern_type: PatternType::ServiceBridge,
                severity,
                description: format!(
                    "{} is the sole link between service clusters: {}",
                    principal_label,
                    bridged_list.join(", ")
                ),
                analysis_hint: format!(
                    "Principal '{}' is the only identity connecting services {}. \
                     If this principal is compromised, the attacker has bridged service \
                     boundaries that are otherwise isolated. Verify: (1) does this principal's \
                     IAM policy *need* access to all these services? (2) Is there a legitimate \
                     workflow that spans these service boundaries? (3) Would scoping the \
                     principal's permissions tighter reduce blast radius?",
                    principal_label,
                    bridged_list.join(" ↔ ")
                ),
                involved_nodes: vec![principal_id.clone()],
                involved_edges: Vec::new(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::{TimeZone, Utc};

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
            event_count: 1,
        }
    }

    fn make_edge(
        edge_type: EdgeType,
        source: &str,
        target: &str,
        first: Option<chrono::DateTime<Utc>>,
    ) -> GraphEdge {
        let id = GraphEdge::create_id(&edge_type, source, target);
        GraphEdge {
            id,
            edge_type,
            source_id: source.to_string(),
            target_id: target.to_string(),
            properties: HashMap::new(),
            weight: 1.0,
            first_seen: first,
            last_seen: first,
            event_count: 1,
        }
    }

    #[test]
    fn privilege_fanout_detected() {
        let mut graph = SecurityGraph::new();
        let t = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();

        graph.add_node(make_node("P:alice", NodeType::Principal, "alice"));

        // alice calls 6 distinct services
        for svc in &["s3", "iam", "ec2", "lambda", "dynamodb", "kms"] {
            let api_id = format!("API:{svc}:ListSomething");
            let api_label = format!("{svc}:ListSomething");
            graph.add_node(make_node(&api_id, NodeType::APIOperation, &api_label));
            graph.add_edge(make_edge(EdgeType::CalledApi, "P:alice", &api_id, Some(t)));
        }

        let patterns = detect_patterns(&graph);
        let fanout = patterns
            .iter()
            .find(|p| p.pattern_type == PatternType::PrivilegeFanout);

        assert!(fanout.is_some(), "should detect privilege fanout");
        let f = fanout.unwrap();
        assert!(f.severity >= 0.4);
        assert!(f.description.contains("alice"));
        assert!(f.description.contains("6 distinct AWS services"));
        // analysis_hint should provide machine-readable guidance
        assert!(f.analysis_hint.contains("post-compromise enumeration"));
    }

    #[test]
    fn privilege_fanout_not_triggered_below_threshold() {
        let mut graph = SecurityGraph::new();
        let t = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();

        graph.add_node(make_node("P:alice", NodeType::Principal, "alice"));

        // alice calls only 3 services (below threshold of 5)
        for svc in &["s3", "iam", "ec2"] {
            let api_id = format!("API:{svc}:List");
            let api_label = format!("{svc}:List");
            graph.add_node(make_node(&api_id, NodeType::APIOperation, &api_label));
            graph.add_edge(make_edge(EdgeType::CalledApi, "P:alice", &api_id, Some(t)));
        }

        let patterns = detect_patterns(&graph);
        assert!(
            !patterns
                .iter()
                .any(|p| p.pattern_type == PatternType::PrivilegeFanout),
            "3 services should not trigger fanout"
        );
    }

    #[test]
    fn resource_convergence_detected() {
        let mut graph = SecurityGraph::new();
        let t = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();

        // 3 principals accessing the same S3 bucket through different API ops
        graph.add_node(make_node("R:bucket", NodeType::Resource, "sensitive-data"));

        for user in &["alice", "bob", "carol"] {
            let p_id = format!("P:{user}");
            let api_id = format!("API:s3:GetObject:{user}");
            graph.add_node(make_node(&p_id, NodeType::Principal, user));
            graph.add_node(make_node(&api_id, NodeType::APIOperation, "s3:GetObject"));
            graph.add_edge(make_edge(EdgeType::CalledApi, &p_id, &api_id, Some(t)));
            graph.add_edge(make_edge(
                EdgeType::AccessedResource,
                &api_id,
                "R:bucket",
                Some(t),
            ));
        }

        let patterns = detect_patterns(&graph);
        let conv = patterns
            .iter()
            .find(|p| p.pattern_type == PatternType::ResourceConvergence);

        assert!(conv.is_some(), "should detect resource convergence");
        let c = conv.unwrap();
        assert!(c.description.contains("sensitive-data"));
        assert!(c.description.contains("3 distinct principals"));
    }

    #[test]
    fn multi_source_auth_detected() {
        let mut graph = SecurityGraph::new();
        let t = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();

        graph.add_node(make_node("P:alice", NodeType::Principal, "alice"));

        // alice authenticates from 4 external IPs
        for ip in &["203.0.113.1", "198.51.100.2", "192.0.2.3", "203.0.113.50"] {
            let ip_id = format!("IP:{ip}");
            graph.add_node(make_node(&ip_id, NodeType::IPAddress, ip));
            graph.add_edge(make_edge(
                EdgeType::AuthenticatedFrom,
                "P:alice",
                &ip_id,
                Some(t),
            ));
        }

        let patterns = detect_patterns(&graph);
        let multi = patterns
            .iter()
            .find(|p| p.pattern_type == PatternType::MultiSourceAuth);

        assert!(multi.is_some(), "should detect multi-source auth");
        assert!(
            multi
                .unwrap()
                .description
                .contains("4 distinct external IPs")
        );
    }

    #[test]
    fn multi_source_auth_ignores_rfc1918() {
        let mut graph = SecurityGraph::new();
        let t = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();

        graph.add_node(make_node("P:alice", NodeType::Principal, "alice"));

        // alice authenticates from 1 external + 5 internal IPs
        graph.add_node(make_node(
            "IP:203.0.113.1",
            NodeType::IPAddress,
            "203.0.113.1",
        ));
        graph.add_edge(make_edge(
            EdgeType::AuthenticatedFrom,
            "P:alice",
            "IP:203.0.113.1",
            Some(t),
        ));
        for i in 1..=5 {
            let ip = format!("10.0.0.{i}");
            let ip_id = format!("IP:{ip}");
            graph.add_node(make_node(&ip_id, NodeType::IPAddress, &ip));
            graph.add_edge(make_edge(
                EdgeType::AuthenticatedFrom,
                "P:alice",
                &ip_id,
                Some(t),
            ));
        }

        let patterns = detect_patterns(&graph);
        assert!(
            !patterns
                .iter()
                .any(|p| p.pattern_type == PatternType::MultiSourceAuth),
            "internal IPs should not count toward multi-source threshold"
        );
    }

    #[test]
    fn service_bridge_detected() {
        let mut graph = SecurityGraph::new();
        let t = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();

        // alice is the only principal who touches both S3 and IAM
        // bob only touches S3, carol only touches IAM
        graph.add_node(make_node("P:alice", NodeType::Principal, "alice"));
        graph.add_node(make_node("P:bob", NodeType::Principal, "bob"));
        graph.add_node(make_node("P:carol", NodeType::Principal, "carol"));

        graph.add_node(make_node(
            "API:s3:Get",
            NodeType::APIOperation,
            "s3:GetObject",
        ));
        graph.add_node(make_node(
            "API:iam:List",
            NodeType::APIOperation,
            "iam:ListUsers",
        ));

        // alice → s3 and iam
        graph.add_edge(make_edge(
            EdgeType::CalledApi,
            "P:alice",
            "API:s3:Get",
            Some(t),
        ));
        graph.add_edge(make_edge(
            EdgeType::CalledApi,
            "P:alice",
            "API:iam:List",
            Some(t),
        ));

        // bob → s3 only
        graph.add_edge(make_edge(
            EdgeType::CalledApi,
            "P:bob",
            "API:s3:Get",
            Some(t),
        ));

        // carol → iam only
        graph.add_edge(make_edge(
            EdgeType::CalledApi,
            "P:carol",
            "API:iam:List",
            Some(t),
        ));

        let patterns = detect_patterns(&graph);
        let bridge = patterns
            .iter()
            .find(|p| p.pattern_type == PatternType::ServiceBridge);

        assert!(
            bridge.is_some(),
            "alice should be detected as a service bridge"
        );
        let b = bridge.unwrap();
        assert!(b.description.contains("alice"));
        assert!(b.analysis_hint.contains("bridged service boundaries"));
    }

    #[test]
    fn service_bridge_not_triggered_when_shared() {
        let mut graph = SecurityGraph::new();
        let t = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();

        // Both alice and bob touch s3 and iam — no bridge
        for user in &["alice", "bob"] {
            let pid = format!("P:{user}");
            graph.add_node(make_node(&pid, NodeType::Principal, user));
            graph.add_edge(make_edge(EdgeType::CalledApi, &pid, "API:s3:Get", Some(t)));
            graph.add_edge(make_edge(
                EdgeType::CalledApi,
                &pid,
                "API:iam:List",
                Some(t),
            ));
        }
        graph.add_node(make_node(
            "API:s3:Get",
            NodeType::APIOperation,
            "s3:GetObject",
        ));
        graph.add_node(make_node(
            "API:iam:List",
            NodeType::APIOperation,
            "iam:ListUsers",
        ));

        let patterns = detect_patterns(&graph);
        assert!(
            !patterns
                .iter()
                .any(|p| p.pattern_type == PatternType::ServiceBridge),
            "no bridge when both principals touch both services"
        );
    }

    #[test]
    fn empty_graph_no_patterns() {
        let graph = SecurityGraph::new();
        assert!(detect_patterns(&graph).is_empty());
    }

    #[test]
    fn patterns_sorted_by_severity() {
        let patterns = {
            let mut graph = SecurityGraph::new();
            let t = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();

            // Build graph with both fanout and multi-source auth
            graph.add_node(make_node("P:alice", NodeType::Principal, "alice"));

            // 7 services for fanout
            for svc in &["s3", "iam", "ec2", "lambda", "dynamodb", "kms", "sqs"] {
                let api_id = format!("API:{svc}:Op");
                graph.add_node(make_node(
                    &api_id,
                    NodeType::APIOperation,
                    &format!("{svc}:Op"),
                ));
                graph.add_edge(make_edge(EdgeType::CalledApi, "P:alice", &api_id, Some(t)));
            }

            // 3 external IPs for multi-source auth
            for ip in &["203.0.113.1", "198.51.100.2", "192.0.2.3"] {
                let ip_id = format!("IP:{ip}");
                graph.add_node(make_node(&ip_id, NodeType::IPAddress, ip));
                graph.add_edge(make_edge(
                    EdgeType::AuthenticatedFrom,
                    "P:alice",
                    &ip_id,
                    Some(t),
                ));
            }

            detect_patterns(&graph)
        };

        for window in patterns.windows(2) {
            assert!(
                window[0].severity >= window[1].severity,
                "patterns should be sorted by severity descending"
            );
        }
    }
}
