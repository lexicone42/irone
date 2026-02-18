use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use tracing::{debug, info};

use super::enrichment::SecurityLakeEnricher;
use super::models::{
    APIOperationNode, EdgeType, GraphEdge, GraphNode, IPAddressNode, NodeType, PrincipalNode,
    SecurityFindingNode, SecurityGraph,
};
use crate::connectors::ocsf::{SecurityLakeQueries, get_nested_value};
use crate::connectors::result::QueryResult;
use crate::detections::DetectionResult;

/// Builds security investigation graphs from detection results.
///
/// Extracts entities (users, IPs, operations) from detection matches,
/// creates graph nodes and edges, and optionally enriches with
/// related events from Security Lake.
pub struct GraphBuilder {
    graph: SecurityGraph,
}

impl Default for GraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphBuilder {
    pub fn new() -> Self {
        Self {
            graph: SecurityGraph::new(),
        }
    }

    /// Build a graph from a triggered detection, with optional enrichment.
    ///
    /// When `security_lake` is `Some`, enrichment queries are executed for
    /// each extracted user and IP (up to 10 each).
    pub async fn build_from_detection<S: SecurityLakeQueries>(
        &mut self,
        result: &DetectionResult,
        security_lake: Option<&S>,
        enrichment_window_minutes: i64,
        max_related_events: usize,
        include_events: bool,
    ) -> &SecurityGraph {
        self.reset();

        info!(
            rule_id = %result.rule_id,
            match_count = result.match_count,
            enrichment_window = enrichment_window_minutes,
            "building graph from detection"
        );

        // Create the security finding node
        let finding_id = SecurityFindingNode::create_id(&result.rule_id, result.executed_at);
        let finding_node = GraphNode {
            id: finding_id.clone(),
            node_type: NodeType::SecurityFinding,
            label: result.rule_name.clone(),
            properties: HashMap::new(),
            first_seen: Some(result.executed_at),
            last_seen: Some(result.executed_at),
            event_count: result.match_count as u64,
        };
        self.graph.add_node(finding_node);

        // Store metadata
        self.graph
            .metadata
            .insert("rule_id".into(), Value::String(result.rule_id.clone()));
        self.graph
            .metadata
            .insert("rule_name".into(), Value::String(result.rule_name.clone()));
        self.graph.metadata.insert(
            "severity".into(),
            Value::String(format!("{:?}", result.severity)),
        );
        self.graph.metadata.insert(
            "triggered_at".into(),
            Value::String(result.executed_at.to_rfc3339()),
        );
        self.graph.metadata.insert(
            "match_count".into(),
            Value::Number(result.match_count.into()),
        );

        // Extract identifiers from matches
        let identifiers = Self::extract_identifiers(&result.matches);
        debug!(
            users = identifiers.users.len(),
            ips = identifiers.ips.len(),
            operations = identifiers.operations.len(),
            "extracted identifiers"
        );

        // Process the original matches
        self.process_matches(&result.matches, &finding_id, include_events);

        // Enrich if a connector is provided
        if let Some(sl) = security_lake {
            let enricher = SecurityLakeEnricher::new(sl);
            let end_time = result.executed_at;
            let start_time = end_time - Duration::minutes(enrichment_window_minutes);

            // Enrich by users (limit to 10)
            for user in identifiers.users.iter().take(10) {
                self.enrich_by_user(
                    &enricher,
                    user,
                    start_time,
                    end_time,
                    max_related_events,
                    include_events,
                )
                .await;
            }

            // Enrich by IPs (limit to 10)
            for ip in identifiers.ips.iter().take(10) {
                self.enrich_by_ip(
                    &enricher,
                    ip,
                    start_time,
                    end_time,
                    max_related_events,
                    include_events,
                )
                .await;
            }
        }

        info!(
            nodes = self.graph.node_count(),
            edges = self.graph.edge_count(),
            "graph build complete"
        );

        &self.graph
    }

    /// Build a graph from specific identifiers without a detection.
    #[allow(clippy::too_many_arguments)]
    pub async fn build_from_identifiers<S: SecurityLakeQueries>(
        &mut self,
        security_lake: &S,
        users: &[String],
        ips: &[String],
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        max_events: usize,
        include_events: bool,
    ) -> &SecurityGraph {
        self.reset();

        let end_time = end.unwrap_or_else(Utc::now);
        let start_time = start.unwrap_or_else(|| end_time - Duration::hours(1));

        self.graph.metadata.insert(
            "investigation_type".into(),
            Value::String("identifier_search".into()),
        );

        let enricher = SecurityLakeEnricher::new(security_lake);

        for user in users.iter().take(10) {
            self.enrich_by_user(
                &enricher,
                user,
                start_time,
                end_time,
                max_events,
                include_events,
            )
            .await;
        }

        for ip in ips.iter().take(10) {
            self.enrich_by_ip(
                &enricher,
                ip,
                start_time,
                end_time,
                max_events,
                include_events,
            )
            .await;
        }

        &self.graph
    }

    /// Return the built graph.
    pub fn get_graph(&self) -> &SecurityGraph {
        &self.graph
    }

    /// Reset the builder for a new graph.
    pub fn reset(&mut self) {
        self.graph = SecurityGraph::new();
    }

    // --- Internal methods ---

    /// Extract key identifiers from detection match rows.
    fn extract_identifiers(matches: &[serde_json::Map<String, Value>]) -> ExtractedIdentifiers {
        let mut ids = ExtractedIdentifiers::default();

        for m in matches {
            // Users
            if let Some(val) =
                get_nested_value(m, "actor.user.name").or_else(|| m.get("user_name").cloned())
                && let Some(s) = val.as_str()
            {
                ids.users.insert(s.to_string());
            }

            // Source IP
            if let Some(val) = get_nested_value(m, "src_endpoint.ip")
                .or_else(|| m.get("source_ip").cloned())
                .or_else(|| m.get("src_ip").cloned())
                && let Some(s) = val.as_str()
            {
                ids.ips.insert(s.to_string());
            }

            // Destination IP
            if let Some(val) = get_nested_value(m, "dst_endpoint.ip")
                && let Some(s) = val.as_str()
            {
                ids.ips.insert(s.to_string());
            }

            // Operation
            if let Some(val) =
                get_nested_value(m, "api.operation").or_else(|| m.get("operation").cloned())
                && let Some(s) = val.as_str()
            {
                ids.operations.insert(s.to_string());
            }

            // Service
            if let Some(val) =
                get_nested_value(m, "api.service.name").or_else(|| m.get("service").cloned())
                && let Some(s) = val.as_str()
            {
                ids.services.insert(s.to_string());
            }
        }

        ids
    }

    /// Process detection matches, creating nodes and edges.
    fn process_matches(
        &mut self,
        matches: &[serde_json::Map<String, Value>],
        finding_id: &str,
        include_events: bool,
    ) {
        for m in matches {
            let event_time = parse_timestamp(m.get("time_dt"));

            // Principal node
            let principal_id = self.add_principal_from_ocsf(m, event_time);

            // Link principal to finding
            if let Some(pid) = &principal_id {
                self.add_edge(EdgeType::RelatedTo, pid, finding_id, event_time);
            }

            // IP node
            let ip_id = self.add_ip_from_ocsf(m, "src_endpoint.ip", event_time);

            // Link principal -> IP
            if let (Some(pid), Some(iid)) = (&principal_id, &ip_id) {
                self.add_edge(EdgeType::AuthenticatedFrom, pid, iid, event_time);
            }

            // API operation node
            let api_id = self.add_api_from_ocsf(m, event_time);

            // Link principal -> API
            if let (Some(pid), Some(aid)) = (&principal_id, &api_id) {
                self.add_edge(EdgeType::CalledApi, pid, aid, event_time);
            }

            // Event node
            if include_events {
                let event_id = self.add_event_from_ocsf(m, event_time);
                self.add_edge(EdgeType::TriggeredBy, finding_id, &event_id, event_time);
            }
        }
    }

    /// Process enrichment query results, creating nodes and edges.
    fn process_query_result(&mut self, qr: &QueryResult, include_events: bool) {
        for record in qr.rows() {
            let event_time = parse_timestamp(record.get("time_dt"));

            let principal_id = self.add_principal_from_ocsf(record, event_time);

            // Source IP
            let src_ip_id = self.add_ip_from_ocsf(record, "src_endpoint.ip", event_time);

            if let (Some(pid), Some(iid)) = (&principal_id, &src_ip_id) {
                self.add_edge(EdgeType::AuthenticatedFrom, pid, iid, event_time);
            }

            // Destination IP
            let dst_ip_id = self.add_ip_from_ocsf(record, "dst_endpoint.ip", event_time);

            if let (Some(sid), Some(did)) = (&src_ip_id, &dst_ip_id)
                && sid != did
            {
                self.add_edge(EdgeType::RelatedTo, sid, did, event_time);
            }

            // API operation
            let api_id = self.add_api_from_ocsf(record, event_time);
            if let (Some(pid), Some(aid)) = (&principal_id, &api_id) {
                self.add_edge(EdgeType::CalledApi, pid, aid, event_time);
            }

            // Event node
            if include_events {
                let event_id = self.add_event_from_ocsf(record, event_time);
                if let Some(iid) = &src_ip_id {
                    self.add_edge(EdgeType::OriginatedFrom, &event_id, iid, event_time);
                }
            }
        }
    }

    /// Try to create a Principal node from OCSF data.
    fn add_principal_from_ocsf(
        &mut self,
        event: &serde_json::Map<String, Value>,
        event_time: DateTime<Utc>,
    ) -> Option<String> {
        // Use the same extraction logic as PrincipalNode
        let (mut node, _principal) = PrincipalNode::from_ocsf_map(event)?;
        node.update_timestamps(event_time);
        let id = node.id.clone();
        self.graph.add_node(node);
        Some(id)
    }

    /// Try to create an IP address node from OCSF data at the given field path.
    fn add_ip_from_ocsf(
        &mut self,
        event: &serde_json::Map<String, Value>,
        ip_field: &str,
        event_time: DateTime<Utc>,
    ) -> Option<String> {
        let ip = get_nested_value(event, ip_field)
            .and_then(|v| v.as_str().map(std::string::ToString::to_string))
            .filter(|s| !s.is_empty())?;

        let id = IPAddressNode::create_id(&ip);
        let mut node = GraphNode {
            id: id.clone(),
            node_type: NodeType::IPAddress,
            label: ip.clone(),
            properties: HashMap::new(),
            first_seen: None,
            last_seen: None,
            event_count: 0,
        };
        node.update_timestamps(event_time);
        self.graph.add_node(node);
        Some(id)
    }

    /// Try to create an API operation node from OCSF data.
    fn add_api_from_ocsf(
        &mut self,
        event: &serde_json::Map<String, Value>,
        event_time: DateTime<Utc>,
    ) -> Option<String> {
        // Extract using the same logic as models::APIOperationNode
        let operation = get_nested_value(event, "api.operation")
            .or_else(|| event.get("operation").cloned())
            .and_then(|v| v.as_str().map(std::string::ToString::to_string))?;

        let mut service = get_nested_value(event, "api.service.name")
            .or_else(|| event.get("service").cloned())
            .and_then(|v| v.as_str().map(std::string::ToString::to_string))?;

        if let Some(stripped) = service.strip_suffix(".amazonaws.com") {
            service = stripped.to_string();
        }

        let id = APIOperationNode::create_id(&service, &operation);
        let mut node = GraphNode {
            id: id.clone(),
            node_type: NodeType::APIOperation,
            label: format!("{service}:{operation}"),
            properties: HashMap::new(),
            first_seen: None,
            last_seen: None,
            event_count: 0,
        };
        node.update_timestamps(event_time);

        // Record status if available
        if let Some(status) = event.get("status").and_then(|v| v.as_str()) {
            node.properties
                .insert("last_status".into(), Value::String(status.to_string()));
        }

        self.graph.add_node(node);
        Some(id)
    }

    /// Create an Event node from OCSF data. Always succeeds (generates ID if missing).
    fn add_event_from_ocsf(
        &mut self,
        event: &serde_json::Map<String, Value>,
        event_time: DateTime<Utc>,
    ) -> String {
        let event_uid = get_nested_value(event, "metadata.uid")
            .or_else(|| event.get("event_uid").cloned())
            .and_then(|v| v.as_str().map(std::string::ToString::to_string))
            .unwrap_or_else(|| format!("evt-{}", event_time.timestamp_nanos_opt().unwrap_or(0)));

        let id = format!("Event:{event_uid}");
        let class_name = get_nested_value(event, "class_name")
            .and_then(|v| v.as_str().map(std::string::ToString::to_string))
            .unwrap_or_default();

        let mut node = GraphNode {
            id: id.clone(),
            node_type: NodeType::Event,
            label: class_name,
            properties: HashMap::new(),
            first_seen: Some(event_time),
            last_seen: Some(event_time),
            event_count: 1,
        };

        if let Some(class_uid) = event.get("class_uid") {
            node.properties
                .insert("class_uid".into(), class_uid.clone());
        }

        self.graph.add_node(node);
        id
    }

    /// Add an edge to the graph.
    fn add_edge(
        &mut self,
        edge_type: EdgeType,
        source_id: &str,
        target_id: &str,
        event_time: DateTime<Utc>,
    ) {
        let id = GraphEdge::create_id(&edge_type, source_id, target_id);
        let edge = GraphEdge {
            id,
            edge_type,
            source_id: source_id.to_string(),
            target_id: target_id.to_string(),
            properties: HashMap::new(),
            weight: 1.0,
            first_seen: Some(event_time),
            last_seen: Some(event_time),
            event_count: 1,
        };
        self.graph.add_edge(edge);
    }

    /// Enrich by user, adding results to the graph.
    async fn enrich_by_user<S: SecurityLakeQueries>(
        &mut self,
        enricher: &SecurityLakeEnricher<'_, S>,
        user: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
        include_events: bool,
    ) {
        let qr = enricher.enrich_by_user(user, start, end, None, limit).await;
        if !qr.is_empty() {
            debug!(user = user, events = qr.len(), "enriched by user");
            self.process_query_result(&qr, include_events);
        }
    }

    /// Enrich by IP, adding results to the graph.
    async fn enrich_by_ip<S: SecurityLakeQueries>(
        &mut self,
        enricher: &SecurityLakeEnricher<'_, S>,
        ip: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
        include_events: bool,
    ) {
        let qr = enricher.enrich_by_ip(ip, start, end, "both", limit).await;
        if !qr.is_empty() {
            debug!(ip = ip, events = qr.len(), "enriched by IP");
            self.process_query_result(&qr, include_events);
        }
    }
}

/// Identifiers extracted from detection match data.
#[derive(Debug, Default)]
struct ExtractedIdentifiers {
    users: HashSet<String>,
    ips: HashSet<String>,
    operations: HashSet<String>,
    services: HashSet<String>,
}

/// Parse a timestamp from a JSON value (ISO-8601 string or epoch).
fn parse_timestamp(value: Option<&Value>) -> DateTime<Utc> {
    match value {
        Some(Value::String(s)) if !s.is_empty() => {
            // Try ISO-8601 (with optional Z suffix)
            let normalized = s.replace('Z', "+00:00");
            DateTime::parse_from_rfc3339(&normalized).map_or_else(
                |_| {
                    // Try chrono's flexible parsing
                    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
                        .map_or_else(|_| Utc::now(), |ndt| ndt.and_utc())
                },
                |dt| dt.with_timezone(&Utc),
            )
        }
        Some(Value::Number(n)) => {
            // Epoch seconds
            if let Some(secs) = n.as_i64() {
                DateTime::from_timestamp(secs, 0).unwrap_or_else(Utc::now)
            } else {
                Utc::now()
            }
        }
        _ => Utc::now(),
    }
}

// Helper on PrincipalNode that works with serde_json::Map directly
impl PrincipalNode {
    /// Create from a `serde_json::Map` (OCSF data with possible flat or nested keys).
    #[must_use]
    pub fn from_ocsf_map(event: &serde_json::Map<String, Value>) -> Option<(GraphNode, Self)> {
        let user_name =
            crate::connectors::ocsf::get_nested_str(event, &["actor.user.name", "user_name"])?;

        let user_type =
            crate::connectors::ocsf::get_nested_str(event, &["actor.user.type", "user_type"]);

        let arn = crate::connectors::ocsf::get_nested_str(event, &["actor.user.uid"]);

        let account_id = crate::connectors::ocsf::get_nested_str(
            event,
            &["actor.user.account_uid", "cloud.account.uid"],
        );

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

#[cfg(test)]
mod tests {
    use chrono::Datelike;
    use serde_json::json;

    use super::*;
    use crate::connectors::ocsf::SecurityLakeError;
    use crate::detections::Severity;
    use crate::json_row;

    /// Mock `SecurityLakeQueries` for testing `GraphBuilder`.
    struct MockSL {
        user_results: QueryResult,
        ip_results: QueryResult,
    }

    impl MockSL {
        fn empty() -> Self {
            Self {
                user_results: QueryResult::empty(),
                ip_results: QueryResult::empty(),
            }
        }

        fn with_user_events(mut self, qr: QueryResult) -> Self {
            self.user_results = qr;
            self
        }
    }

    impl SecurityLakeQueries for MockSL {
        async fn query_by_event_class(
            &self,
            event_class: crate::connectors::ocsf::OCSFEventClass,
            _start: DateTime<Utc>,
            _end: DateTime<Utc>,
            _limit: usize,
            _additional_filters: Option<&str>,
        ) -> Result<QueryResult, SecurityLakeError> {
            // Return user_results for auth/api classes, ip_results for network
            match event_class {
                crate::connectors::ocsf::OCSFEventClass::NetworkActivity => {
                    Ok(self.ip_results.clone())
                }
                _ => Ok(self.user_results.clone()),
            }
        }

        async fn query_authentication_events(
            &self,
            _: DateTime<Utc>,
            _: DateTime<Utc>,
            _: Option<&str>,
            _: usize,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(QueryResult::empty())
        }

        async fn query_api_activity(
            &self,
            _: DateTime<Utc>,
            _: DateTime<Utc>,
            _: Option<&str>,
            _: Option<&str>,
            _: usize,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(QueryResult::empty())
        }

        async fn query_network_activity(
            &self,
            _: DateTime<Utc>,
            _: DateTime<Utc>,
            _: Option<&str>,
            _: Option<&str>,
            _: Option<u16>,
            _: usize,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(QueryResult::empty())
        }

        async fn query_security_findings(
            &self,
            _: DateTime<Utc>,
            _: DateTime<Utc>,
            _: Option<&str>,
            _: usize,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(QueryResult::empty())
        }

        async fn get_event_summary(
            &self,
            _: DateTime<Utc>,
            _: DateTime<Utc>,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(QueryResult::empty())
        }
    }

    fn sample_detection() -> DetectionResult {
        DetectionResult {
            rule_id: "RULE-001".into(),
            rule_name: "Test Detection".into(),
            triggered: true,
            severity: Severity::High,
            match_count: 2,
            matches: vec![
                json_row!(
                    "actor.user.name" => "alice",
                    "src_endpoint.ip" => "10.0.0.1",
                    "api.operation" => "GetObject",
                    "api.service.name" => "s3.amazonaws.com",
                    "time_dt" => "2024-01-15T10:30:00Z"
                ),
                json_row!(
                    "actor.user.name" => "alice",
                    "src_endpoint.ip" => "10.0.0.2",
                    "api.operation" => "PutObject",
                    "api.service.name" => "s3.amazonaws.com",
                    "time_dt" => "2024-01-15T10:31:00Z"
                ),
            ],
            message: "Suspicious S3 activity detected".into(),
            executed_at: chrono::DateTime::parse_from_rfc3339("2024-01-15T10:32:00Z")
                .unwrap()
                .with_timezone(&Utc),
            execution_time_ms: 150.0,
            error: None,
        }
    }

    #[test]
    fn extract_identifiers_from_matches() {
        let det = sample_detection();
        let ids = GraphBuilder::extract_identifiers(&det.matches);
        assert!(ids.users.contains("alice"));
        assert!(ids.ips.contains("10.0.0.1"));
        assert!(ids.ips.contains("10.0.0.2"));
        assert!(ids.operations.contains("GetObject"));
        assert!(ids.operations.contains("PutObject"));
        assert!(ids.services.contains("s3.amazonaws.com"));
    }

    #[tokio::test]
    async fn build_from_detection_no_enrichment() {
        let mut builder = GraphBuilder::new();
        let det = sample_detection();

        let graph = builder
            .build_from_detection::<MockSL>(&det, None, 60, 500, false)
            .await;

        // Should have: 1 finding + 1 principal (alice) + 2 IPs + 2 API ops = 6
        assert!(graph.node_count() >= 5, "got {} nodes", graph.node_count());

        // Finding node exists
        let finding_nodes = graph.get_nodes_by_type(&NodeType::SecurityFinding);
        assert_eq!(finding_nodes.len(), 1);

        // Principal node exists
        let principals = graph.get_nodes_by_type(&NodeType::Principal);
        assert_eq!(principals.len(), 1);

        // IP nodes exist
        let ips = graph.get_nodes_by_type(&NodeType::IPAddress);
        assert_eq!(ips.len(), 2);

        // API operation nodes
        let apis = graph.get_nodes_by_type(&NodeType::APIOperation);
        assert_eq!(apis.len(), 2);

        // Edges should exist
        assert!(graph.edge_count() > 0);
    }

    #[tokio::test]
    async fn build_from_detection_with_enrichment() {
        let enrichment_data = vec![json_row!(
            "actor.user.name" => "alice",
            "src_endpoint.ip" => "10.0.0.3",
            "api.operation" => "ListBuckets",
            "api.service.name" => "s3",
            "time_dt" => "2024-01-15T10:25:00Z"
        )];

        let mock_sl = MockSL::empty().with_user_events(QueryResult::from_maps(enrichment_data));

        let mut builder = GraphBuilder::new();
        let det = sample_detection();

        let graph = builder
            .build_from_detection(&det, Some(&mock_sl), 60, 500, false)
            .await;

        // Should have more nodes due to enrichment
        let ips = graph.get_nodes_by_type(&NodeType::IPAddress);
        assert!(
            ips.len() >= 3,
            "expected enrichment IP, got {} IPs",
            ips.len()
        );
    }

    #[tokio::test]
    async fn build_with_event_nodes() {
        let mut builder = GraphBuilder::new();
        let det = sample_detection();

        let graph = builder
            .build_from_detection::<MockSL>(&det, None, 60, 500, true)
            .await;

        let events = graph.get_nodes_by_type(&NodeType::Event);
        assert_eq!(events.len(), 2, "expected 2 event nodes");
    }

    #[test]
    fn parse_timestamp_iso() {
        let val = json!("2024-01-15T10:30:00Z");
        let ts = parse_timestamp(Some(&val));
        assert_eq!(ts.year(), 2024);
        assert_eq!(ts.month(), 1);
    }

    #[test]
    fn parse_timestamp_none_returns_now() {
        let ts = parse_timestamp(None);
        // Should be recent (within last second)
        let diff = Utc::now() - ts;
        assert!(diff.num_seconds() < 2);
    }

    #[test]
    fn reset_clears_graph() {
        let mut builder = GraphBuilder::new();
        builder.graph.add_node(GraphNode {
            id: "test".into(),
            node_type: NodeType::Principal,
            label: "test".into(),
            properties: HashMap::new(),
            first_seen: None,
            last_seen: None,
            event_count: 0,
        });
        assert_eq!(builder.get_graph().node_count(), 1);

        builder.reset();
        assert_eq!(builder.get_graph().node_count(), 0);
    }
}
