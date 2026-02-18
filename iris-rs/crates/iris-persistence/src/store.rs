use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use iris_core::graph::{EventTag, InvestigationTimeline, TimelineEvent};
use iris_core::graph::{GraphEdge, GraphNode, SecurityGraph};

use crate::error::Result;

// ---------------------------------------------------------------------------
// Table definitions — 5 tables mirroring the Python DuckDB schema
// ---------------------------------------------------------------------------

/// `inv_id` -> serialized `InvestigationMetadata`
const INVESTIGATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("investigations");

/// (`inv_id`, `node_id`) -> serialized `GraphNode`
const GRAPH_NODES: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("graph_nodes");

/// (`inv_id`, `edge_id`) -> serialized `GraphEdge`
const GRAPH_EDGES: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("graph_edges");

/// (`inv_id`, `event_id`) -> serialized `TimelineEvent`
const TIMELINE_EVENTS: TableDefinition<(&str, &str), &[u8]> =
    TableDefinition::new("timeline_events");

/// (`inv_id`, `artifact_type`) -> content bytes
const ARTIFACTS: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("artifacts");

// ---------------------------------------------------------------------------
// Internal metadata record stored in the INVESTIGATIONS table
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InvestigationMetadata {
    name: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    status: String,
    #[serde(default)]
    metadata: HashMap<String, Value>,
    #[serde(default)]
    node_count: usize,
    #[serde(default)]
    edge_count: usize,
}

// ---------------------------------------------------------------------------
// Public return types
// ---------------------------------------------------------------------------

/// Full investigation data returned by [`InvestigationStore::load_investigation`].
#[derive(Debug, Clone)]
pub struct LoadedInvestigation {
    pub name: String,
    pub graph: SecurityGraph,
    pub created_at: DateTime<Utc>,
    pub timeline_tags: HashMap<String, String>,
    pub status: String,
}

/// Lightweight summary returned by [`InvestigationStore::list_investigations`].
#[derive(Debug, Clone, Serialize)]
pub struct InvestigationSummary {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub status: String,
    pub node_count: usize,
    pub edge_count: usize,
}

// ---------------------------------------------------------------------------
// InvestigationStore
// ---------------------------------------------------------------------------

/// Redb-backed persistence for investigations, graphs, and timelines.
///
/// All operations are synchronous — the web layer should use
/// `tokio::task::spawn_blocking` when calling store methods.
pub struct InvestigationStore {
    db: Database,
}

impl InvestigationStore {
    /// Open (or create) a store at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path)?;
        Self::ensure_tables(&db)?;
        Ok(Self { db })
    }

    /// Create a temporary store backed by a tempfile. Useful for tests.
    #[cfg(test)]
    pub fn open_temp() -> Result<Self> {
        let tmp = tempfile::NamedTempFile::new()
            .expect("failed to create tempfile for InvestigationStore");
        let db = Database::create(tmp.path())?;
        Self::ensure_tables(&db)?;
        Ok(Self { db })
    }

    /// Create all 5 tables if they don't already exist (idempotent).
    fn ensure_tables(db: &Database) -> Result<()> {
        let write_txn = db.begin_write()?;
        // Opening a table in a write transaction creates it if absent
        let _ = write_txn.open_table(INVESTIGATIONS)?;
        let _ = write_txn.open_table(GRAPH_NODES)?;
        let _ = write_txn.open_table(GRAPH_EDGES)?;
        let _ = write_txn.open_table(TIMELINE_EVENTS)?;
        let _ = write_txn.open_table(ARTIFACTS)?;
        write_txn.commit()?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Investigation CRUD
    // -----------------------------------------------------------------------

    /// Upsert investigation metadata and persist the full graph.
    pub fn save_investigation(
        &self,
        inv_id: &str,
        name: &str,
        graph: &SecurityGraph,
        created_at: Option<DateTime<Utc>>,
        metadata: Option<HashMap<String, Value>>,
        status: &str,
    ) -> Result<()> {
        let now = Utc::now();
        let created_at = created_at.unwrap_or(now);

        let meta = InvestigationMetadata {
            name: name.to_string(),
            created_at,
            updated_at: now,
            status: status.to_string(),
            metadata: metadata.unwrap_or_default(),
            node_count: graph.node_count(),
            edge_count: graph.edge_count(),
        };

        let meta_bytes = serde_json::to_vec(&meta)?;

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(INVESTIGATIONS)?;
            table.insert(inv_id, meta_bytes.as_slice())?;
        }
        // Write graph data in the same transaction
        Self::write_graph_in_txn(&write_txn, inv_id, graph)?;
        write_txn.commit()?;
        Ok(())
    }

    /// Load a full investigation (metadata + graph + timeline tags).
    ///
    /// Returns `None` if the investigation does not exist.
    pub fn load_investigation(&self, inv_id: &str) -> Result<Option<LoadedInvestigation>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(INVESTIGATIONS)?;

        let Some(meta_guard) = table.get(inv_id)? else {
            return Ok(None);
        };
        let meta: InvestigationMetadata = serde_json::from_slice(meta_guard.value())?;
        drop(meta_guard);

        let graph = Self::read_graph_in_txn(&read_txn, inv_id)?;
        let timeline = Self::read_timeline_in_txn(&read_txn, inv_id)?;

        // Build timeline_tags dict from persisted events (non-unreviewed only)
        let mut timeline_tags = HashMap::new();
        if let Some(ref tl) = timeline {
            for ev in &tl.events {
                if ev.tag != EventTag::Unreviewed {
                    timeline_tags.insert(ev.id.clone(), ev.tag.to_string());
                }
            }
        }

        Ok(Some(LoadedInvestigation {
            name: meta.name,
            graph,
            created_at: meta.created_at,
            timeline_tags,
            status: meta.status,
        }))
    }

    /// Return a lightweight list of all investigations, ordered by creation time (newest first).
    pub fn list_investigations(&self) -> Result<Vec<InvestigationSummary>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(INVESTIGATIONS)?;

        let mut summaries = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let id = key.value().to_string();
            let meta: InvestigationMetadata = serde_json::from_slice(value.value())?;
            summaries.push(InvestigationSummary {
                id,
                name: meta.name,
                created_at: meta.created_at,
                status: meta.status,
                node_count: meta.node_count,
                edge_count: meta.edge_count,
            });
        }

        // Sort newest first (matching Python's ORDER BY created_at DESC)
        summaries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(summaries)
    }

    /// Cascade-delete an investigation and all related data.
    pub fn delete_investigation(&self, inv_id: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;

        // Delete from all 5 tables in cascade order
        Self::delete_range_in_table(&write_txn, ARTIFACTS, inv_id)?;
        Self::delete_range_in_table(&write_txn, TIMELINE_EVENTS, inv_id)?;
        Self::delete_range_in_table(&write_txn, GRAPH_EDGES, inv_id)?;
        Self::delete_range_in_table(&write_txn, GRAPH_NODES, inv_id)?;

        {
            let mut table = write_txn.open_table(INVESTIGATIONS)?;
            table.remove(inv_id)?;
        }

        write_txn.commit()?;
        Ok(())
    }

    /// Update investigation status (e.g. "active" -> "closed").
    pub fn update_status(&self, inv_id: &str, status: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(INVESTIGATIONS)?;
            let Some(guard) = table.get(inv_id)? else {
                return Ok(());
            };
            let mut meta: InvestigationMetadata = serde_json::from_slice(guard.value())?;
            drop(guard);

            meta.status = status.to_string();
            meta.updated_at = Utc::now();
            let bytes = serde_json::to_vec(&meta)?;
            table.insert(inv_id, bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Graph persistence
    // -----------------------------------------------------------------------

    /// Replace all nodes/edges for an investigation.
    pub fn save_graph(&self, inv_id: &str, graph: &SecurityGraph) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        Self::write_graph_in_txn(&write_txn, inv_id, graph)?;

        // Update node_count/edge_count in investigation metadata if it exists
        {
            let mut table = write_txn.open_table(INVESTIGATIONS)?;
            // Read existing metadata (drop guard before writing)
            let existing: Option<InvestigationMetadata> = table
                .get(inv_id)?
                .map(|g| serde_json::from_slice(g.value()))
                .transpose()?;

            if let Some(mut meta) = existing {
                meta.node_count = graph.node_count();
                meta.edge_count = graph.edge_count();
                meta.updated_at = Utc::now();
                let bytes = serde_json::to_vec(&meta)?;
                table.insert(inv_id, bytes.as_slice())?;
            }
        }

        write_txn.commit()?;
        Ok(())
    }

    /// Load all nodes/edges for an investigation into a `SecurityGraph`.
    pub fn load_graph(&self, inv_id: &str) -> Result<SecurityGraph> {
        let read_txn = self.db.begin_read()?;
        Self::read_graph_in_txn(&read_txn, inv_id)
    }

    // -----------------------------------------------------------------------
    // Timeline persistence
    // -----------------------------------------------------------------------

    /// Replace all timeline events for an investigation.
    pub fn save_timeline(&self, inv_id: &str, timeline: &InvestigationTimeline) -> Result<()> {
        let write_txn = self.db.begin_write()?;

        // Delete existing events
        Self::delete_range_in_table(&write_txn, TIMELINE_EVENTS, inv_id)?;

        // Insert new events
        {
            let mut table = write_txn.open_table(TIMELINE_EVENTS)?;
            for event in &timeline.events {
                let bytes = serde_json::to_vec(event)?;
                table.insert((inv_id, event.id.as_str()), bytes.as_slice())?;
            }
        }

        write_txn.commit()?;
        Ok(())
    }

    /// Load timeline events. Returns `None` if no events exist.
    pub fn load_timeline(&self, inv_id: &str) -> Result<Option<InvestigationTimeline>> {
        let read_txn = self.db.begin_read()?;
        Self::read_timeline_in_txn(&read_txn, inv_id)
    }

    /// Update the tag and notes on a single timeline event.
    ///
    /// Returns `true` if the event existed, `false` otherwise.
    pub fn tag_event(&self, inv_id: &str, event_id: &str, tag: &str, notes: &str) -> Result<bool> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TIMELINE_EVENTS)?;
            let Some(guard) = table.get((inv_id, event_id))? else {
                return Ok(false);
            };
            let mut event: TimelineEvent = serde_json::from_slice(guard.value())?;
            drop(guard);

            // Parse the tag string into an EventTag
            let tag_json = format!("\"{tag}\"");
            event.tag = serde_json::from_str(&tag_json).unwrap_or_default();
            event.notes = notes.to_string();

            let bytes = serde_json::to_vec(&event)?;
            table.insert((inv_id, event_id), bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Artifact caching
    // -----------------------------------------------------------------------

    /// Store (or replace) a cached visualization artifact.
    pub fn save_artifact(&self, inv_id: &str, artifact_type: &str, content: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(ARTIFACTS)?;
            table.insert((inv_id, artifact_type), content.as_bytes())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Load a cached artifact. Returns `None` if not found.
    pub fn load_artifact(&self, inv_id: &str, artifact_type: &str) -> Result<Option<String>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(ARTIFACTS)?;

        match table.get((inv_id, artifact_type))? {
            Some(guard) => {
                let s = String::from_utf8_lossy(guard.value()).into_owned();
                Ok(Some(s))
            }
            None => Ok(None),
        }
    }

    /// Remove all cached artifacts for an investigation.
    pub fn delete_artifacts(&self, inv_id: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        Self::delete_range_in_table(&write_txn, ARTIFACTS, inv_id)?;
        write_txn.commit()?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Write all graph nodes and edges inside an existing write transaction.
    /// Deletes existing data for the investigation first.
    fn write_graph_in_txn(
        write_txn: &redb::WriteTransaction,
        inv_id: &str,
        graph: &SecurityGraph,
    ) -> Result<()> {
        // Delete existing nodes/edges
        Self::delete_range_in_table(write_txn, GRAPH_NODES, inv_id)?;
        Self::delete_range_in_table(write_txn, GRAPH_EDGES, inv_id)?;

        // Insert nodes
        {
            let mut table = write_txn.open_table(GRAPH_NODES)?;
            for node in graph.nodes.values() {
                let bytes = serde_json::to_vec(node)?;
                table.insert((inv_id, node.id.as_str()), bytes.as_slice())?;
            }
        }

        // Insert edges
        {
            let mut table = write_txn.open_table(GRAPH_EDGES)?;
            for edge in &graph.edges {
                let bytes = serde_json::to_vec(edge)?;
                table.insert((inv_id, edge.id.as_str()), bytes.as_slice())?;
            }
        }

        Ok(())
    }

    /// Read all nodes/edges for an investigation from a read transaction.
    fn read_graph_in_txn(read_txn: &redb::ReadTransaction, inv_id: &str) -> Result<SecurityGraph> {
        let mut graph = SecurityGraph::new();

        // Read nodes
        {
            let table = read_txn.open_table(GRAPH_NODES)?;
            for entry in table.range((inv_id, "")..)? {
                let (key, value) = entry?;
                let (kid, _) = key.value();
                if kid != inv_id {
                    break;
                }
                let node: GraphNode = serde_json::from_slice(value.value())?;
                // Insert directly into the nodes map to avoid merge behavior
                graph.nodes.insert(node.id.clone(), node);
            }
        }

        // Read edges
        {
            let table = read_txn.open_table(GRAPH_EDGES)?;
            for entry in table.range((inv_id, "")..)? {
                let (key, value) = entry?;
                let (kid, _) = key.value();
                if kid != inv_id {
                    break;
                }
                let edge: GraphEdge = serde_json::from_slice(value.value())?;
                graph.edges.push(edge);
            }
        }

        Ok(graph)
    }

    /// Read timeline events from a read transaction.
    fn read_timeline_in_txn(
        read_txn: &redb::ReadTransaction,
        inv_id: &str,
    ) -> Result<Option<InvestigationTimeline>> {
        let table = read_txn.open_table(TIMELINE_EVENTS)?;
        let mut events = Vec::new();

        for entry in table.range((inv_id, "")..)? {
            let (key, value) = entry?;
            let (kid, _) = key.value();
            if kid != inv_id {
                break;
            }
            let event: TimelineEvent = serde_json::from_slice(value.value())?;
            events.push(event);
        }

        if events.is_empty() {
            return Ok(None);
        }

        // Sort by timestamp (matching Python's ORDER BY timestamp)
        events.sort_by_key(|e| e.timestamp);

        let mut timeline = InvestigationTimeline::new(inv_id);
        timeline.events = events;
        Ok(Some(timeline))
    }

    /// Delete all entries in a composite-key table where the first key component
    /// matches `inv_id`.
    fn delete_range_in_table(
        write_txn: &redb::WriteTransaction,
        table_def: TableDefinition<(&str, &str), &[u8]>,
        inv_id: &str,
    ) -> Result<()> {
        let mut table = write_txn.open_table(table_def)?;

        // Collect keys to delete (can't modify while iterating)
        let keys: Vec<(String, String)> = {
            let mut keys = Vec::new();
            for entry in table.range((inv_id, "")..)? {
                let (key, _) = entry?;
                let (kid, second) = key.value();
                if kid != inv_id {
                    break;
                }
                keys.push((kid.to_string(), second.to_string()));
            }
            keys
        };

        for (k1, k2) in &keys {
            table.remove((k1.as_str(), k2.as_str()))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use iris_core::graph::{EdgeType, NodeType};
    use std::collections::HashMap;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

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

    fn sample_graph() -> SecurityGraph {
        let mut graph = SecurityGraph::new();
        let t1 = Utc.with_ymd_and_hms(2024, 6, 1, 12, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2024, 6, 1, 13, 0, 0).unwrap();

        let mut admin = make_node("principal:admin", NodeType::Principal);
        admin.label = "admin@example.com".to_string();
        admin.first_seen = Some(t1);
        admin.last_seen = Some(t2);
        admin.event_count = 5;
        admin.properties.insert(
            "user_type".to_string(),
            Value::String("IAMUser".to_string()),
        );
        admin.properties.insert(
            "account_id".to_string(),
            Value::String("123456789".to_string()),
        );
        graph.nodes.insert(admin.id.clone(), admin);

        let mut ip = make_node("ip:10.0.0.1", NodeType::IPAddress);
        ip.label = "10.0.0.1".to_string();
        ip.first_seen = Some(t1);
        ip.event_count = 3;
        ip.properties
            .insert("is_internal".to_string(), Value::Bool(true));
        graph.nodes.insert(ip.id.clone(), ip);

        let mut edge = make_edge(
            EdgeType::AuthenticatedFrom,
            "principal:admin",
            "ip:10.0.0.1",
        );
        edge.weight = 5.0;
        edge.first_seen = Some(t1);
        edge.last_seen = Some(t2);
        edge.event_count = 5;
        edge.properties
            .insert("sessions".to_string(), Value::Number(3.into()));
        graph.edges.push(edge);

        graph
    }

    fn sample_timeline() -> InvestigationTimeline {
        let t1 = Utc.with_ymd_and_hms(2024, 6, 1, 12, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2024, 6, 1, 12, 30, 0).unwrap();

        let mut timeline = InvestigationTimeline::new("inv-test");
        timeline.events = vec![
            TimelineEvent {
                id: "evt-1".to_string(),
                timestamp: t1,
                title: "Login from admin".to_string(),
                description: "IAMUser login".to_string(),
                entity_type: "Principal".to_string(),
                entity_id: "principal:admin".to_string(),
                operation: "ConsoleLogin".to_string(),
                status: "success".to_string(),
                tag: EventTag::Important,
                notes: String::new(),
                properties: HashMap::new(),
            },
            TimelineEvent {
                id: "evt-2".to_string(),
                timestamp: t2,
                title: "S3 access".to_string(),
                description: "GetObject on sensitive-bucket".to_string(),
                entity_type: "Resource".to_string(),
                entity_id: "resource:s3:sensitive-bucket".to_string(),
                operation: "GetObject".to_string(),
                status: "success".to_string(),
                tag: EventTag::Suspicious,
                notes: "Analyst: unusual access pattern".to_string(),
                properties: {
                    let mut m = HashMap::new();
                    m.insert(
                        "bucket".to_string(),
                        Value::String("sensitive-bucket".to_string()),
                    );
                    m
                },
            },
        ];
        timeline
    }

    // -----------------------------------------------------------------------
    // TestSchemaManagement
    // -----------------------------------------------------------------------

    #[test]
    fn test_open_twice_idempotent() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        // Open, use, drop — then reopen on same file (redb is exclusive-lock)
        {
            let store = InvestigationStore::open(tmp.path()).unwrap();
            store
                .save_investigation("x", "Test", &SecurityGraph::new(), None, None, "active")
                .unwrap();
        }
        // Reopen should not panic and data should persist
        let store = InvestigationStore::open(tmp.path()).unwrap();
        let loaded = store.load_investigation("x").unwrap();
        assert!(loaded.is_some());
    }

    #[test]
    fn test_fresh_store_empty() {
        let store = InvestigationStore::open_temp().unwrap();
        let list = store.list_investigations().unwrap();
        assert!(list.is_empty());
    }

    // -----------------------------------------------------------------------
    // TestInvestigationCRUD
    // -----------------------------------------------------------------------

    #[test]
    fn test_save_load_empty_graph() {
        let store = InvestigationStore::open_temp().unwrap();
        let graph = SecurityGraph::new();
        store
            .save_investigation("inv-1", "Empty Investigation", &graph, None, None, "active")
            .unwrap();

        let loaded = store.load_investigation("inv-1").unwrap().unwrap();
        assert_eq!(loaded.name, "Empty Investigation");
        assert_eq!(loaded.graph.node_count(), 0);
        assert_eq!(loaded.graph.edge_count(), 0);
        assert_eq!(loaded.status, "active");
    }

    #[test]
    fn test_save_load_with_nodes_edges() {
        let store = InvestigationStore::open_temp().unwrap();
        let graph = sample_graph();
        let created = Utc.with_ymd_and_hms(2024, 6, 1, 0, 0, 0).unwrap();

        store
            .save_investigation(
                "inv-2",
                "Admin Investigation",
                &graph,
                Some(created),
                None,
                "active",
            )
            .unwrap();

        let loaded = store.load_investigation("inv-2").unwrap().unwrap();
        assert_eq!(loaded.name, "Admin Investigation");
        assert_eq!(loaded.created_at, created);
        assert_eq!(loaded.graph.node_count(), 2);
        assert_eq!(loaded.graph.edge_count(), 1);

        let admin_node = loaded.graph.get_node("principal:admin").unwrap();
        assert_eq!(admin_node.label, "admin@example.com");
        assert_eq!(admin_node.node_type, NodeType::Principal);
        assert_eq!(admin_node.event_count, 5);
        assert_eq!(
            admin_node.properties["user_type"],
            Value::String("IAMUser".to_string())
        );

        let ip_node = loaded.graph.get_node("ip:10.0.0.1").unwrap();
        assert_eq!(ip_node.properties["is_internal"], Value::Bool(true));

        let edge = &loaded.graph.edges[0];
        assert_eq!(edge.edge_type, EdgeType::AuthenticatedFrom);
        assert!((edge.weight - 5.0).abs() < f64::EPSILON);
        assert_eq!(edge.event_count, 5);
        assert_eq!(edge.properties["sessions"], Value::Number(3.into()));
    }

    #[test]
    fn test_load_nonexistent() {
        let store = InvestigationStore::open_temp().unwrap();
        let loaded = store.load_investigation("doesnt-exist").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_list_investigations() {
        let store = InvestigationStore::open_temp().unwrap();
        let graph = sample_graph();
        store
            .save_investigation(
                "inv-a",
                "First",
                &SecurityGraph::new(),
                None,
                None,
                "active",
            )
            .unwrap();
        store
            .save_investigation("inv-b", "Second", &graph, None, None, "active")
            .unwrap();

        let list = store.list_investigations().unwrap();
        assert_eq!(list.len(), 2);

        let second = list.iter().find(|i| i.id == "inv-b").unwrap();
        assert_eq!(second.name, "Second");
        assert_eq!(second.node_count, 2);
        assert_eq!(second.edge_count, 1);
    }

    #[test]
    fn test_delete_investigation() {
        let store = InvestigationStore::open_temp().unwrap();
        let graph = sample_graph();
        store
            .save_investigation("inv-del", "To Delete", &graph, None, None, "active")
            .unwrap();
        assert!(store.load_investigation("inv-del").unwrap().is_some());

        store.delete_investigation("inv-del").unwrap();
        assert!(store.load_investigation("inv-del").unwrap().is_none());
        assert!(store.list_investigations().unwrap().is_empty());
    }

    #[test]
    fn test_update_status() {
        let store = InvestigationStore::open_temp().unwrap();
        store
            .save_investigation(
                "inv-s",
                "Status Test",
                &SecurityGraph::new(),
                None,
                None,
                "active",
            )
            .unwrap();

        store.update_status("inv-s", "closed").unwrap();
        let loaded = store.load_investigation("inv-s").unwrap().unwrap();
        assert_eq!(loaded.status, "closed");
    }

    #[test]
    fn test_save_overwrites_existing() {
        let store = InvestigationStore::open_temp().unwrap();
        store
            .save_investigation(
                "inv-ow",
                "Original",
                &SecurityGraph::new(),
                None,
                None,
                "active",
            )
            .unwrap();
        store
            .save_investigation(
                "inv-ow",
                "Updated",
                &SecurityGraph::new(),
                None,
                None,
                "active",
            )
            .unwrap();

        let loaded = store.load_investigation("inv-ow").unwrap().unwrap();
        assert_eq!(loaded.name, "Updated");
    }

    // -----------------------------------------------------------------------
    // TestGraphPersistence
    // -----------------------------------------------------------------------

    #[test]
    fn test_properties_json_roundtrip() {
        let store = InvestigationStore::open_temp().unwrap();
        let mut graph = SecurityGraph::new();

        let mut props = HashMap::new();
        props.insert("nested".to_string(), serde_json::json!({"key": "value"}));
        props.insert("list_val".to_string(), serde_json::json!([1, 2, 3]));
        props.insert("bool_val".to_string(), Value::Bool(true));
        props.insert("null_val".to_string(), Value::Null);

        let mut node = make_node("node-1", NodeType::Resource);
        node.label = "test-resource".to_string();
        node.properties = props;
        graph.nodes.insert(node.id.clone(), node);

        store.save_graph("inv-json", &graph).unwrap();
        let loaded = store.load_graph("inv-json").unwrap();

        let loaded_props = &loaded.get_node("node-1").unwrap().properties;
        assert_eq!(loaded_props["nested"], serde_json::json!({"key": "value"}));
        assert_eq!(loaded_props["list_val"], serde_json::json!([1, 2, 3]));
        assert_eq!(loaded_props["bool_val"], Value::Bool(true));
        assert_eq!(loaded_props["null_val"], Value::Null);
    }

    #[test]
    fn test_timestamp_preservation() {
        let store = InvestigationStore::open_temp().unwrap();
        let ts = Utc.with_ymd_and_hms(2024, 6, 15, 10, 30, 0).unwrap();

        let mut graph = SecurityGraph::new();
        let mut node = make_node("n-ts", NodeType::Event);
        node.label = "ts-test".to_string();
        node.first_seen = Some(ts);
        node.last_seen = Some(ts);
        graph.nodes.insert(node.id.clone(), node);

        store.save_graph("inv-ts", &graph).unwrap();
        let loaded = store.load_graph("inv-ts").unwrap();

        let loaded_node = loaded.get_node("n-ts").unwrap();
        assert_eq!(loaded_node.first_seen, Some(ts));
        assert_eq!(loaded_node.last_seen, Some(ts));
    }

    #[test]
    fn test_save_graph_replaces_all() {
        let store = InvestigationStore::open_temp().unwrap();
        let graph = sample_graph();
        store.save_graph("inv-rep", &graph).unwrap();
        assert_eq!(store.load_graph("inv-rep").unwrap().node_count(), 2);

        let mut new_graph = SecurityGraph::new();
        let node = make_node("only-one", NodeType::Principal);
        new_graph.nodes.insert(node.id.clone(), node);
        store.save_graph("inv-rep", &new_graph).unwrap();

        let loaded = store.load_graph("inv-rep").unwrap();
        assert_eq!(loaded.node_count(), 1);
        assert!(loaded.get_node("only-one").is_some());
    }

    // -----------------------------------------------------------------------
    // TestTimelinePersistence
    // -----------------------------------------------------------------------

    #[test]
    fn test_save_load_timeline() {
        let store = InvestigationStore::open_temp().unwrap();
        let timeline = sample_timeline();
        store.save_timeline("inv-tl", &timeline).unwrap();

        let loaded = store.load_timeline("inv-tl").unwrap().unwrap();
        assert_eq!(loaded.events.len(), 2);
        assert_eq!(loaded.events[0].id, "evt-1");
        assert_eq!(loaded.events[0].tag, EventTag::Important);
        assert_eq!(loaded.events[1].notes, "Analyst: unusual access pattern");
        assert_eq!(
            loaded.events[1].properties["bucket"],
            Value::String("sensitive-bucket".to_string())
        );
    }

    #[test]
    fn test_load_empty_timeline() {
        let store = InvestigationStore::open_temp().unwrap();
        let loaded = store.load_timeline("inv-empty").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_tag_event() {
        let store = InvestigationStore::open_temp().unwrap();
        let timeline = sample_timeline();
        store.save_timeline("inv-tag", &timeline).unwrap();

        let result = store
            .tag_event("inv-tag", "evt-1", "suspicious", "Flagged by analyst")
            .unwrap();
        assert!(result);

        let loaded = store.load_timeline("inv-tag").unwrap().unwrap();
        let evt = loaded.events.iter().find(|e| e.id == "evt-1").unwrap();
        assert_eq!(evt.tag, EventTag::Suspicious);
        assert_eq!(evt.notes, "Flagged by analyst");
    }

    #[test]
    fn test_tag_nonexistent() {
        let store = InvestigationStore::open_temp().unwrap();
        let result = store
            .tag_event("inv-no", "evt-no", "suspicious", "")
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_timeline_tags_in_loaded_investigation() {
        let store = InvestigationStore::open_temp().unwrap();
        let timeline = sample_timeline();

        store
            .save_investigation(
                "inv-tt",
                "Tagged",
                &SecurityGraph::new(),
                None,
                None,
                "active",
            )
            .unwrap();
        store.save_timeline("inv-tt", &timeline).unwrap();

        let loaded = store.load_investigation("inv-tt").unwrap().unwrap();
        assert_eq!(loaded.timeline_tags["evt-1"], "important");
        assert_eq!(loaded.timeline_tags["evt-2"], "suspicious");
    }

    // -----------------------------------------------------------------------
    // TestArtifactCaching
    // -----------------------------------------------------------------------

    #[test]
    fn test_save_load_artifact() {
        let store = InvestigationStore::open_temp().unwrap();
        let html = "<html><body>Graph Viz</body></html>";
        store.save_artifact("inv-a", "graph_html", html).unwrap();
        let loaded = store.load_artifact("inv-a", "graph_html").unwrap();
        assert_eq!(loaded.as_deref(), Some(html));
    }

    #[test]
    fn test_load_missing_artifact() {
        let store = InvestigationStore::open_temp().unwrap();
        let loaded = store.load_artifact("inv-no", "graph_html").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_artifact_overwrite() {
        let store = InvestigationStore::open_temp().unwrap();
        store.save_artifact("inv-a", "graph_html", "v1").unwrap();
        store.save_artifact("inv-a", "graph_html", "v2").unwrap();
        assert_eq!(
            store
                .load_artifact("inv-a", "graph_html")
                .unwrap()
                .as_deref(),
            Some("v2")
        );
    }

    #[test]
    fn test_delete_artifacts() {
        let store = InvestigationStore::open_temp().unwrap();
        store.save_artifact("inv-d", "graph_html", "graph").unwrap();
        store
            .save_artifact("inv-d", "timeline_html", "timeline")
            .unwrap();
        store.delete_artifacts("inv-d").unwrap();
        assert!(
            store
                .load_artifact("inv-d", "graph_html")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .load_artifact("inv-d", "timeline_html")
                .unwrap()
                .is_none()
        );
    }

    // -----------------------------------------------------------------------
    // TestConcurrentInvestigations
    // -----------------------------------------------------------------------

    #[test]
    fn test_isolation() {
        let store = InvestigationStore::open_temp().unwrap();
        let graph = sample_graph();

        store
            .save_investigation("inv-x", "X", &graph, None, None, "active")
            .unwrap();
        store
            .save_investigation("inv-y", "Y", &SecurityGraph::new(), None, None, "active")
            .unwrap();

        let x = store.load_investigation("inv-x").unwrap().unwrap();
        let y = store.load_investigation("inv-y").unwrap().unwrap();
        assert_eq!(x.graph.node_count(), 2);
        assert_eq!(y.graph.node_count(), 0);
    }

    #[test]
    fn test_delete_one_preserves_other() {
        let store = InvestigationStore::open_temp().unwrap();
        let graph = sample_graph();

        store
            .save_investigation("inv-keep", "Keep", &graph, None, None, "active")
            .unwrap();
        store
            .save_investigation("inv-drop", "Drop", &graph, None, None, "active")
            .unwrap();

        store.delete_investigation("inv-drop").unwrap();
        assert!(store.load_investigation("inv-drop").unwrap().is_none());

        let kept = store.load_investigation("inv-keep").unwrap().unwrap();
        assert_eq!(kept.graph.node_count(), 2);
    }

    // -----------------------------------------------------------------------
    // TestFullRoundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_roundtrip() {
        let store = InvestigationStore::open_temp().unwrap();
        let graph = sample_graph();
        let timeline = sample_timeline();
        let created = Utc.with_ymd_and_hms(2024, 6, 1, 0, 0, 0).unwrap();

        let mut meta = HashMap::new();
        meta.insert("source".to_string(), Value::String("test".to_string()));

        store
            .save_investigation(
                "inv-full",
                "Full Roundtrip",
                &graph,
                Some(created),
                Some(meta),
                "active",
            )
            .unwrap();
        store.save_timeline("inv-full", &timeline).unwrap();
        store
            .save_artifact("inv-full", "graph_html", "<html>graph</html>")
            .unwrap();

        let loaded = store.load_investigation("inv-full").unwrap().unwrap();
        assert_eq!(loaded.name, "Full Roundtrip");
        assert_eq!(loaded.graph.node_count(), 2);
        assert_eq!(loaded.graph.edge_count(), 1);
        assert_eq!(loaded.timeline_tags["evt-1"], "important");
        assert_eq!(loaded.timeline_tags["evt-2"], "suspicious");

        let tl = store.load_timeline("inv-full").unwrap().unwrap();
        assert_eq!(tl.events.len(), 2);

        let artifact = store
            .load_artifact("inv-full", "graph_html")
            .unwrap()
            .unwrap();
        assert_eq!(artifact, "<html>graph</html>");

        let list = store.list_investigations().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].node_count, 2);
    }

    // -----------------------------------------------------------------------
    // New: concurrent readers (redb MVCC validation)
    // -----------------------------------------------------------------------

    #[test]
    fn test_concurrent_readers() {
        let store = InvestigationStore::open_temp().unwrap();
        let graph = sample_graph();

        store
            .save_investigation("inv-mvcc", "MVCC Test", &graph, None, None, "active")
            .unwrap();

        // Start two concurrent read transactions
        let read1 = store.db.begin_read().unwrap();
        let read2 = store.db.begin_read().unwrap();

        let table1 = read1.open_table(INVESTIGATIONS).unwrap();
        let table2 = read2.open_table(INVESTIGATIONS).unwrap();

        // Both should see the same data
        assert!(table1.get("inv-mvcc").unwrap().is_some());
        assert!(table2.get("inv-mvcc").unwrap().is_some());
    }
}
