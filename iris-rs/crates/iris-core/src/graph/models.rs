use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Types of nodes in the security graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeType {
    Principal,
    #[serde(rename = "IPAddress")]
    IPAddress,
    Resource,
    #[serde(rename = "APIOperation")]
    APIOperation,
    SecurityFinding,
    Event,
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Principal => write!(f, "Principal"),
            Self::IPAddress => write!(f, "IPAddress"),
            Self::Resource => write!(f, "Resource"),
            Self::APIOperation => write!(f, "APIOperation"),
            Self::SecurityFinding => write!(f, "SecurityFinding"),
            Self::Event => write!(f, "Event"),
        }
    }
}

/// Types of relationships between nodes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EdgeType {
    AuthenticatedFrom,
    CalledApi,
    AccessedResource,
    OriginatedFrom,
    RelatedTo,
    TriggeredBy,
    PerformedBy,
    Targeted,
}

impl std::fmt::Display for EdgeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthenticatedFrom => write!(f, "AUTHENTICATED_FROM"),
            Self::CalledApi => write!(f, "CALLED_API"),
            Self::AccessedResource => write!(f, "ACCESSED_RESOURCE"),
            Self::OriginatedFrom => write!(f, "ORIGINATED_FROM"),
            Self::RelatedTo => write!(f, "RELATED_TO"),
            Self::TriggeredBy => write!(f, "TRIGGERED_BY"),
            Self::PerformedBy => write!(f, "PERFORMED_BY"),
            Self::Targeted => write!(f, "TARGETED"),
        }
    }
}

/// Base graph node. All node variants share these fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub node_type: NodeType,
    pub label: String,
    #[serde(default)]
    pub properties: HashMap<String, Value>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    #[serde(default)]
    pub event_count: u64,
}

impl GraphNode {
    /// Update `first_seen`/`last_seen` based on an event timestamp.
    pub fn update_timestamps(&mut self, event_time: DateTime<Utc>) {
        match self.first_seen {
            None => self.first_seen = Some(event_time),
            Some(t) if event_time < t => self.first_seen = Some(event_time),
            _ => {}
        }
        match self.last_seen {
            None => self.last_seen = Some(event_time),
            Some(t) if event_time > t => self.last_seen = Some(event_time),
            _ => {}
        }
        self.event_count += 1;
    }
}

/// User, role, or service account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalNode {
    pub user_name: String,
    pub user_type: Option<String>,
    pub arn: Option<String>,
    pub account_id: Option<String>,
}

impl PrincipalNode {
    #[must_use]
    pub fn create_id(user_name: &str) -> String {
        format!("Principal:{user_name}")
    }

    /// Create a `GraphNode` + `PrincipalNode` from OCSF event data.
    #[must_use]
    pub fn from_ocsf(event: &HashMap<String, Value>) -> Option<(GraphNode, Self)> {
        let user_name = get_nested_str(event, &["actor.user.name", "user_name"])
            .or_else(|| get_deep_str(event, &["actor", "user", "name"]))?;

        let user_type = get_nested_str(event, &["actor.user.type", "user_type"])
            .or_else(|| get_deep_str(event, &["actor", "user", "type"]));

        let arn = get_nested_str(event, &["actor.user.uid"])
            .or_else(|| get_deep_str(event, &["actor", "user", "uid"]));

        let account_id = get_nested_str(event, &["actor.user.account_uid", "cloud.account.uid"])
            .or_else(|| get_deep_str(event, &["cloud", "account", "uid"]));

        let id = Self::create_id(&user_name);
        let node = GraphNode {
            id: id.clone(),
            node_type: NodeType::Principal,
            label: user_name.clone(),
            properties: HashMap::new(),
            first_seen: None,
            last_seen: None,
            event_count: 0,
        };
        let principal = Self {
            user_name,
            user_type,
            arn,
            account_id,
        };
        Some((node, principal))
    }
}

/// IP address entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPAddressNode {
    pub ip_address: String,
    pub is_internal: bool,
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
    pub asn: Option<String>,
}

impl IPAddressNode {
    #[must_use]
    pub fn create_id(ip: &str) -> String {
        format!("IPAddress:{ip}")
    }

    /// Check if an IP is RFC1918 private.
    #[must_use]
    pub fn is_rfc1918(ip: &str) -> bool {
        ip.starts_with("10.") || ip.starts_with("192.168.") || is_172_private(ip)
    }
}

fn is_172_private(ip: &str) -> bool {
    if let Some(rest) = ip.strip_prefix("172.")
        && let Some(dot_pos) = rest.find('.')
        && let Ok(second_octet) = rest[..dot_pos].parse::<u8>()
    {
        return (16..=31).contains(&second_octet);
    }
    false
}

/// AWS resource entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceNode {
    pub resource_type: String,
    pub resource_id: String,
    pub arn: Option<String>,
    pub region: Option<String>,
    pub account_id: Option<String>,
}

impl ResourceNode {
    #[must_use]
    pub fn create_id(resource_type: &str, resource_id: &str) -> String {
        format!("Resource:{resource_type}:{resource_id}")
    }

    /// Create from an ARN string.
    #[must_use]
    pub fn from_arn(arn: &str) -> Option<(GraphNode, Self)> {
        if !arn.starts_with("arn:") {
            return None;
        }
        let parts: Vec<&str> = arn.splitn(6, ':').collect();
        if parts.len() < 6 {
            return None;
        }

        let service = parts[2];
        let region = if parts[3].is_empty() {
            None
        } else {
            Some(parts[3].to_string())
        };
        let account_id = if parts[4].is_empty() {
            None
        } else {
            Some(parts[4].to_string())
        };
        let resource_part = parts[5];

        let (resource_type, resource_id) = if let Some(slash_pos) = resource_part.find('/') {
            (
                resource_part[..slash_pos].to_string(),
                resource_part[slash_pos + 1..].to_string(),
            )
        } else {
            (service.to_string(), resource_part.to_string())
        };

        let label = if resource_id.len() > 30 {
            format!("{}...", &resource_id[..30])
        } else {
            resource_id.clone()
        };

        let id = Self::create_id(&resource_type, &resource_id);
        let node = GraphNode {
            id: id.clone(),
            node_type: NodeType::Resource,
            label,
            properties: HashMap::new(),
            first_seen: None,
            last_seen: None,
            event_count: 0,
        };
        let resource = Self {
            resource_type,
            resource_id,
            arn: Some(arn.to_string()),
            region,
            account_id,
        };
        Some((node, resource))
    }
}

/// API operation performed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APIOperationNode {
    pub operation: String,
    pub service: String,
    pub success_count: u64,
    pub failure_count: u64,
}

impl APIOperationNode {
    #[must_use]
    pub fn create_id(service: &str, operation: &str) -> String {
        format!("APIOperation:{service}:{operation}")
    }

    /// Record a success or failure for this operation.
    pub fn record_status(&mut self, status: &str) {
        match status.to_lowercase().as_str() {
            "success" | "succeeded" | "ok" => self.success_count += 1,
            _ => self.failure_count += 1,
        }
    }

    /// Create from OCSF event data.
    #[must_use]
    pub fn from_ocsf(event: &HashMap<String, Value>) -> Option<(GraphNode, Self)> {
        let operation = get_nested_str(event, &["api.operation", "operation"])
            .or_else(|| get_deep_str(event, &["api", "operation"]))?;

        let mut service = get_nested_str(event, &["api.service.name", "service"])
            .or_else(|| get_deep_str(event, &["api", "service", "name"]))?;

        // Normalize service name
        if let Some(stripped) = service.strip_suffix(".amazonaws.com") {
            service = stripped.to_string();
        }

        let id = Self::create_id(&service, &operation);
        let node = GraphNode {
            id: id.clone(),
            node_type: NodeType::APIOperation,
            label: format!("{service}:{operation}"),
            properties: HashMap::new(),
            first_seen: None,
            last_seen: None,
            event_count: 0,
        };
        let api_op = Self {
            operation,
            service,
            success_count: 0,
            failure_count: 0,
        };
        Some((node, api_op))
    }
}

/// Security detection or finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFindingNode {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub triggered_at: DateTime<Utc>,
    pub match_count: u64,
    pub investigation_status: String,
}

impl SecurityFindingNode {
    #[must_use]
    pub fn create_id(rule_id: &str, triggered_at: DateTime<Utc>) -> String {
        let ts = triggered_at.format("%Y%m%d%H%M%S");
        format!("Finding:{rule_id}:{ts}")
    }
}

/// Individual security event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventNode {
    pub event_uid: String,
    pub class_uid: u32,
    pub class_name: String,
    pub timestamp: DateTime<Utc>,
    pub status: Option<String>,
    pub region: Option<String>,
    pub raw_event: Option<HashMap<String, Value>>,
}

impl EventNode {
    #[must_use]
    pub fn create_id(event_uid: &str) -> String {
        format!("Event:{event_uid}")
    }
}

/// Relationship between two graph nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub id: String,
    pub edge_type: EdgeType,
    pub source_id: String,
    pub target_id: String,
    #[serde(default)]
    pub properties: HashMap<String, Value>,
    #[serde(default = "default_weight")]
    pub weight: f64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    #[serde(default = "default_event_count")]
    pub event_count: u64,
}

fn default_weight() -> f64 {
    1.0
}
fn default_event_count() -> u64 {
    1
}

impl GraphEdge {
    /// Create a consistent edge ID.
    #[must_use]
    pub fn create_id(edge_type: &EdgeType, source_id: &str, target_id: &str) -> String {
        format!("{edge_type}:{source_id}->{target_id}")
    }

    /// Update `first_seen`/`last_seen` based on an event timestamp.
    pub fn update_timestamps(&mut self, event_time: DateTime<Utc>) {
        match self.first_seen {
            None => self.first_seen = Some(event_time),
            Some(t) if event_time < t => self.first_seen = Some(event_time),
            _ => {}
        }
        match self.last_seen {
            None => self.last_seen = Some(event_time),
            Some(t) if event_time > t => self.last_seen = Some(event_time),
            _ => {}
        }
        self.event_count += 1;
    }
}

/// Container for the complete security investigation graph.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityGraph {
    pub nodes: HashMap<String, GraphNode>,
    pub edges: Vec<GraphEdge>,
    #[serde(default)]
    pub metadata: HashMap<String, Value>,

    #[serde(skip)]
    edge_index: HashMap<String, usize>,
}

impl SecurityGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a graph with metadata.
    #[must_use]
    pub fn with_metadata(metadata: HashMap<String, Value>) -> Self {
        Self {
            metadata,
            ..Default::default()
        }
    }

    /// Add a node, merging timestamps if it already exists.
    pub fn add_node(&mut self, node: GraphNode) {
        if let Some(existing) = self.nodes.get_mut(&node.id) {
            if let Some(t) = node.first_seen {
                existing.update_timestamps(t);
            }
            if let Some(t) = node.last_seen {
                existing.update_timestamps(t);
            }
        } else {
            self.nodes.insert(node.id.clone(), node);
        }
    }

    /// Add an edge, merging timestamps if it already exists.
    pub fn add_edge(&mut self, edge: GraphEdge) {
        if let Some(&idx) = self.edge_index.get(&edge.id) {
            let existing = &mut self.edges[idx];
            if let Some(t) = edge.first_seen {
                existing.update_timestamps(t);
            }
            if let Some(t) = edge.last_seen {
                existing.update_timestamps(t);
            }
        } else {
            let idx = self.edges.len();
            self.edge_index.insert(edge.id.clone(), idx);
            self.edges.push(edge);
        }
    }

    /// Get a node by ID.
    #[must_use]
    pub fn get_node(&self, node_id: &str) -> Option<&GraphNode> {
        self.nodes.get(node_id)
    }

    /// Get an edge by ID.
    #[must_use]
    pub fn get_edge(&self, edge_id: &str) -> Option<&GraphEdge> {
        self.edge_index.get(edge_id).map(|&idx| &self.edges[idx])
    }

    /// Get all nodes connected to the specified node.
    #[must_use]
    pub fn get_neighbors(&self, node_id: &str, direction: Direction) -> Vec<&GraphNode> {
        let mut neighbor_ids = std::collections::HashSet::new();
        for edge in &self.edges {
            if matches!(direction, Direction::Outgoing | Direction::Both)
                && edge.source_id == node_id
            {
                neighbor_ids.insert(&edge.target_id);
            }
            if matches!(direction, Direction::Incoming | Direction::Both)
                && edge.target_id == node_id
            {
                neighbor_ids.insert(&edge.source_id);
            }
        }
        neighbor_ids
            .into_iter()
            .filter_map(|id| self.nodes.get(id.as_str()))
            .collect()
    }

    /// Get all edges connected to a node.
    #[must_use]
    pub fn get_edges_for_node(&self, node_id: &str, direction: Direction) -> Vec<&GraphEdge> {
        self.edges
            .iter()
            .filter(|e| match direction {
                Direction::Outgoing => e.source_id == node_id,
                Direction::Incoming => e.target_id == node_id,
                Direction::Both => e.source_id == node_id || e.target_id == node_id,
            })
            .collect()
    }

    /// Get all nodes of a specific type.
    #[must_use]
    pub fn get_nodes_by_type(&self, node_type: &NodeType) -> Vec<&GraphNode> {
        self.nodes
            .values()
            .filter(|n| &n.node_type == node_type)
            .collect()
    }

    /// Total number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total number of edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Summary of the graph contents.
    #[must_use]
    pub fn summary(&self) -> GraphSummary {
        let mut nodes_by_type: HashMap<String, usize> = HashMap::new();
        for node in self.nodes.values() {
            *nodes_by_type.entry(node.node_type.to_string()).or_default() += 1;
        }
        let mut edges_by_type: HashMap<String, usize> = HashMap::new();
        for edge in &self.edges {
            *edges_by_type.entry(edge.edge_type.to_string()).or_default() += 1;
        }
        GraphSummary {
            total_nodes: self.node_count(),
            total_edges: self.edge_count(),
            nodes_by_type,
            edges_by_type,
        }
    }
}

/// Direction for graph traversal queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Outgoing,
    Incoming,
    Both,
}

/// Summary of graph contents returned by [`SecurityGraph::summary`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSummary {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub nodes_by_type: HashMap<String, usize>,
    pub edges_by_type: HashMap<String, usize>,
}

// --- Helpers for OCSF field extraction ---

/// Try to get a string value from any of the given flat keys.
fn get_nested_str(event: &HashMap<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(Value::String(s)) = event.get(*key)
            && !s.is_empty()
        {
            return Some(s.clone());
        }
    }
    None
}

/// Navigate nested dicts to extract a string value.
fn get_deep_str(event: &HashMap<String, Value>, path: &[&str]) -> Option<String> {
    let mut current: &Value =
        &Value::Object(event.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
    for part in path {
        match current {
            Value::Object(map) => {
                current = map.get(*part)?;
            }
            _ => return None,
        }
    }
    match current {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id: &str, node_type: NodeType) -> GraphNode {
        GraphNode {
            id: id.to_string(),
            node_type,
            label: id.to_string(),
            properties: HashMap::new(),
            first_seen: None,
            last_seen: None,
            event_count: 0,
        }
    }

    fn make_edge(edge_type: EdgeType, source: &str, target: &str) -> GraphEdge {
        let id = GraphEdge::create_id(&edge_type, source, target);
        GraphEdge {
            id,
            edge_type,
            source_id: source.to_string(),
            target_id: target.to_string(),
            properties: HashMap::new(),
            weight: 1.0,
            first_seen: None,
            last_seen: None,
            event_count: 1,
        }
    }

    #[test]
    fn empty_graph() {
        let g = SecurityGraph::new();
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn add_and_get_node() {
        let mut g = SecurityGraph::new();
        g.add_node(make_node("Principal:alice", NodeType::Principal));
        assert_eq!(g.node_count(), 1);
        assert!(g.get_node("Principal:alice").is_some());
        assert!(g.get_node("missing").is_none());
    }

    #[test]
    fn add_duplicate_node_merges() {
        let mut g = SecurityGraph::new();
        let t1 = Utc::now() - chrono::Duration::hours(2);
        let t2 = Utc::now();

        let mut n1 = make_node("n1", NodeType::Principal);
        n1.first_seen = Some(t1);
        n1.last_seen = Some(t1);
        g.add_node(n1);

        let mut n2 = make_node("n1", NodeType::Principal);
        n2.first_seen = Some(t2);
        n2.last_seen = Some(t2);
        g.add_node(n2);

        assert_eq!(g.node_count(), 1);
        let node = g.get_node("n1").unwrap();
        assert_eq!(node.first_seen, Some(t1));
        assert_eq!(node.last_seen, Some(t2));
        assert_eq!(node.event_count, 2);
    }

    #[test]
    fn add_and_get_edge() {
        let mut g = SecurityGraph::new();
        g.add_node(make_node("a", NodeType::Principal));
        g.add_node(make_node("b", NodeType::IPAddress));
        let edge = make_edge(EdgeType::AuthenticatedFrom, "a", "b");
        let edge_id = edge.id.clone();
        g.add_edge(edge);
        assert_eq!(g.edge_count(), 1);
        assert!(g.get_edge(&edge_id).is_some());
    }

    #[test]
    fn add_duplicate_edge_merges() {
        let mut g = SecurityGraph::new();
        let t1 = Utc::now() - chrono::Duration::hours(1);
        let t2 = Utc::now();

        let mut e1 = make_edge(EdgeType::CalledApi, "a", "b");
        e1.first_seen = Some(t1);
        e1.last_seen = Some(t1);
        g.add_edge(e1);

        let mut e2 = make_edge(EdgeType::CalledApi, "a", "b");
        e2.first_seen = Some(t2);
        e2.last_seen = Some(t2);
        g.add_edge(e2);

        assert_eq!(g.edge_count(), 1);
        let edge = g.get_edge("CALLED_API:a->b").unwrap();
        assert_eq!(edge.first_seen, Some(t1));
        assert_eq!(edge.last_seen, Some(t2));
    }

    #[test]
    fn get_neighbors() {
        let mut g = SecurityGraph::new();
        g.add_node(make_node("a", NodeType::Principal));
        g.add_node(make_node("b", NodeType::IPAddress));
        g.add_node(make_node("c", NodeType::Resource));
        g.add_edge(make_edge(EdgeType::AuthenticatedFrom, "a", "b"));
        g.add_edge(make_edge(EdgeType::AccessedResource, "a", "c"));

        let out = g.get_neighbors("a", Direction::Outgoing);
        assert_eq!(out.len(), 2);

        let inc = g.get_neighbors("b", Direction::Incoming);
        assert_eq!(inc.len(), 1);
        assert_eq!(inc[0].id, "a");
    }

    #[test]
    fn get_edges_for_node() {
        let mut g = SecurityGraph::new();
        g.add_node(make_node("a", NodeType::Principal));
        g.add_node(make_node("b", NodeType::IPAddress));
        g.add_edge(make_edge(EdgeType::AuthenticatedFrom, "a", "b"));

        let out_edges = g.get_edges_for_node("a", Direction::Outgoing);
        assert_eq!(out_edges.len(), 1);

        let in_edges = g.get_edges_for_node("a", Direction::Incoming);
        assert!(in_edges.is_empty());
    }

    #[test]
    fn get_nodes_by_type() {
        let mut g = SecurityGraph::new();
        g.add_node(make_node("p1", NodeType::Principal));
        g.add_node(make_node("p2", NodeType::Principal));
        g.add_node(make_node("ip1", NodeType::IPAddress));

        let principals = g.get_nodes_by_type(&NodeType::Principal);
        assert_eq!(principals.len(), 2);

        let ips = g.get_nodes_by_type(&NodeType::IPAddress);
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn summary() {
        let mut g = SecurityGraph::new();
        g.add_node(make_node("p1", NodeType::Principal));
        g.add_node(make_node("ip1", NodeType::IPAddress));
        g.add_edge(make_edge(EdgeType::AuthenticatedFrom, "p1", "ip1"));

        let s = g.summary();
        assert_eq!(s.total_nodes, 2);
        assert_eq!(s.total_edges, 1);
        assert_eq!(s.nodes_by_type["Principal"], 1);
        assert_eq!(s.nodes_by_type["IPAddress"], 1);
        assert_eq!(s.edges_by_type["AUTHENTICATED_FROM"], 1);
    }

    #[test]
    fn node_type_display() {
        assert_eq!(NodeType::Principal.to_string(), "Principal");
        assert_eq!(NodeType::IPAddress.to_string(), "IPAddress");
        assert_eq!(NodeType::APIOperation.to_string(), "APIOperation");
    }

    #[test]
    fn edge_type_display() {
        assert_eq!(
            EdgeType::AuthenticatedFrom.to_string(),
            "AUTHENTICATED_FROM"
        );
        assert_eq!(EdgeType::CalledApi.to_string(), "CALLED_API");
    }

    #[test]
    fn principal_create_id() {
        assert_eq!(PrincipalNode::create_id("alice"), "Principal:alice");
    }

    #[test]
    fn ip_address_rfc1918() {
        assert!(IPAddressNode::is_rfc1918("10.0.0.1"));
        assert!(IPAddressNode::is_rfc1918("192.168.1.1"));
        assert!(IPAddressNode::is_rfc1918("172.16.0.1"));
        assert!(IPAddressNode::is_rfc1918("172.31.255.255"));
        assert!(!IPAddressNode::is_rfc1918("172.15.0.1"));
        assert!(!IPAddressNode::is_rfc1918("172.32.0.1"));
        assert!(!IPAddressNode::is_rfc1918("8.8.8.8"));
    }

    #[test]
    fn resource_from_arn() {
        let (node, res) = ResourceNode::from_arn("arn:aws:s3:::my-bucket").unwrap();
        assert_eq!(res.resource_type, "s3");
        assert_eq!(res.resource_id, "my-bucket");
        assert_eq!(node.node_type, NodeType::Resource);
    }

    #[test]
    fn resource_from_arn_with_slash() {
        let (_, res) = ResourceNode::from_arn("arn:aws:iam::123456789012:role/my-role").unwrap();
        assert_eq!(res.resource_type, "role");
        assert_eq!(res.resource_id, "my-role");
        assert_eq!(res.account_id.as_deref(), Some("123456789012"));
    }

    #[test]
    fn resource_from_arn_invalid() {
        assert!(ResourceNode::from_arn("not-an-arn").is_none());
        assert!(ResourceNode::from_arn("arn:aws:s3").is_none());
    }

    #[test]
    fn resource_label_truncation() {
        let long_id = "a".repeat(50);
        let arn = format!("arn:aws:s3:::{long_id}");
        let (node, _) = ResourceNode::from_arn(&arn).unwrap();
        assert!(node.label.len() <= 33); // 30 + "..."
        assert!(node.label.ends_with("..."));
    }

    #[test]
    fn api_operation_record_status() {
        let mut op = APIOperationNode {
            operation: "GetObject".into(),
            service: "s3".into(),
            success_count: 0,
            failure_count: 0,
        };
        op.record_status("Success");
        op.record_status("success");
        op.record_status("Failure");
        assert_eq!(op.success_count, 2);
        assert_eq!(op.failure_count, 1);
    }

    #[test]
    fn security_finding_create_id() {
        let ts = chrono::DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let id = SecurityFindingNode::create_id("rule-001", ts);
        assert_eq!(id, "Finding:rule-001:20240115103000");
    }

    #[test]
    fn graph_node_update_timestamps() {
        let mut node = make_node("test", NodeType::Event);
        let t1 = Utc::now() - chrono::Duration::hours(2);
        let t2 = Utc::now() - chrono::Duration::hours(1);
        let t3 = Utc::now();

        node.update_timestamps(t2);
        assert_eq!(node.first_seen, Some(t2));
        assert_eq!(node.last_seen, Some(t2));
        assert_eq!(node.event_count, 1);

        node.update_timestamps(t1);
        assert_eq!(node.first_seen, Some(t1)); // updated to earlier
        assert_eq!(node.last_seen, Some(t2)); // unchanged
        assert_eq!(node.event_count, 2);

        node.update_timestamps(t3);
        assert_eq!(node.first_seen, Some(t1)); // unchanged
        assert_eq!(node.last_seen, Some(t3)); // updated to later
        assert_eq!(node.event_count, 3);
    }

    #[test]
    fn principal_from_ocsf_flat_fields() {
        let mut event = HashMap::new();
        event.insert("actor.user.name".to_string(), Value::String("alice".into()));
        event.insert(
            "actor.user.type".to_string(),
            Value::String("IAMUser".into()),
        );

        let (node, principal) = PrincipalNode::from_ocsf(&event).unwrap();
        assert_eq!(node.id, "Principal:alice");
        assert_eq!(principal.user_name, "alice");
        assert_eq!(principal.user_type, Some("IAMUser".into()));
    }

    #[test]
    fn principal_from_ocsf_missing_name_returns_none() {
        let event = HashMap::new();
        assert!(PrincipalNode::from_ocsf(&event).is_none());
    }

    #[test]
    fn api_operation_from_ocsf() {
        let mut event = HashMap::new();
        event.insert(
            "api.operation".to_string(),
            Value::String("GetObject".into()),
        );
        event.insert(
            "api.service.name".to_string(),
            Value::String("s3.amazonaws.com".into()),
        );

        let (node, op) = APIOperationNode::from_ocsf(&event).unwrap();
        assert_eq!(node.label, "s3:GetObject");
        assert_eq!(op.service, "s3"); // .amazonaws.com stripped
        assert_eq!(op.operation, "GetObject");
    }

    #[test]
    fn graph_serde_roundtrip() {
        let mut g = SecurityGraph::new();
        g.add_node(make_node("a", NodeType::Principal));
        g.add_node(make_node("b", NodeType::IPAddress));
        g.add_edge(make_edge(EdgeType::AuthenticatedFrom, "a", "b"));

        let json = serde_json::to_string(&g).unwrap();
        let g2: SecurityGraph = serde_json::from_str(&json).unwrap();
        assert_eq!(g2.node_count(), 2);
        assert_eq!(g2.edge_count(), 1);
    }
}
