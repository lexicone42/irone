use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use irone_core::graph::{
    EdgeType, EventTag, GraphBuilder, GraphEdge, GraphNode, InvestigationTimeline, NodeType,
    SecurityGraph, extract_timeline_from_graph,
};
use irone_core::reports::graph_to_report_data;

use crate::error::WebError;
use crate::state::{AppState, Investigation};

/// Build the investigations sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/investigations",
            get(list_investigations).post(create_investigation),
        )
        .route(
            "/investigations/from-detection",
            post(create_from_detection),
        )
        .route(
            "/investigations/{inv_id}",
            get(get_investigation).delete(delete_investigation),
        )
        .route("/investigations/{inv_id}/graph", get(get_graph))
        .route("/investigations/{inv_id}/report", get(get_report))
        .route("/investigations/{inv_id}/timeline", get(get_timeline))
        .route(
            "/investigations/{inv_id}/enrich",
            post(enrich_investigation),
        )
        .route(
            "/investigations/{inv_id}/timeline/tag",
            post(tag_timeline_event),
        )
        .route("/investigations/seed", post(seed_investigation))
}

// -- Request / Response types --

#[derive(Debug, Deserialize)]
pub struct CreateInvestigationRequest {
    pub name: Option<String>,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub ips: Vec<String>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    /// Source to use for enrichment queries.
    pub source_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateFromDetectionRequest {
    pub rule_id: String,
    pub name: Option<String>,
    /// If omitted, uses the first Security Lake source from the catalog.
    pub source_name: Option<String>,
    #[serde(default = "default_lookback")]
    pub lookback_minutes: i64,
    #[serde(default = "default_enrichment_window")]
    pub enrichment_window_minutes: i64,
}

const fn default_lookback() -> i64 {
    60
}

const fn default_enrichment_window() -> i64 {
    120
}

#[derive(Debug, Deserialize)]
pub struct TagEventRequest {
    pub event_id: String,
    pub tag: EventTag,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Serialize)]
pub struct InvestigationSummary {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub status: String,
    pub node_count: usize,
    pub edge_count: usize,
}

#[derive(Debug, Serialize)]
pub struct CreateFromDetectionResponse {
    pub investigation_id: String,
    pub name: String,
    pub triggered: bool,
    pub match_count: usize,
    pub node_count: usize,
    pub edge_count: usize,
}

/// Cytoscape.js-compatible graph elements.
#[derive(Debug, Serialize)]
pub struct CytoscapeElements {
    pub elements: Vec<CytoscapeElement>,
    pub summary: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct CytoscapeElement {
    pub group: &'static str,
    pub data: serde_json::Map<String, serde_json::Value>,
}

// -- Handlers --

/// `GET /api/investigations` — list all investigations.
async fn list_investigations(State(state): State<AppState>) -> Json<Vec<InvestigationSummary>> {
    let invs = state.investigations.read().await;
    let mut summaries: Vec<InvestigationSummary> = invs
        .values()
        .map(|inv| InvestigationSummary {
            id: inv.id.clone(),
            name: inv.name.clone(),
            created_at: inv.created_at.to_rfc3339(),
            status: inv.status.clone(),
            node_count: inv.graph.node_count(),
            edge_count: inv.graph.edge_count(),
        })
        .collect();
    summaries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Json(summaries)
}

/// `POST /api/investigations` — create from identifiers.
async fn create_investigation(
    State(state): State<AppState>,
    Json(body): Json<CreateInvestigationRequest>,
) -> Result<Json<InvestigationSummary>, WebError> {
    let inv_id = uuid::Uuid::new_v4().to_string();
    let name = body
        .name
        .unwrap_or_else(|| format!("Investigation {}", &inv_id[..8]));

    // Build connector for enrichment if source specified
    let graph = if let Some(ref source_name) = body.source_name {
        let catalog = state.catalog.read().await;
        let source = catalog
            .get_source(source_name)
            .cloned()
            .ok_or_else(|| WebError::NotFound(format!("source '{source_name}' not found")))?;
        drop(catalog);

        let connector =
            irone_aws::create_connector(source, &state.sdk_config, state.config.use_direct_query)
                .await;
        let mut builder = GraphBuilder::new();
        Box::pin(builder.build_from_identifiers(
            &connector,
            &body.users,
            &body.ips,
            body.start,
            body.end,
            1000,
            true,
        ))
        .await;
        builder.into_graph()
    } else {
        SecurityGraph::new()
    };

    let timeline = extract_timeline_from_graph(&graph, true, true);
    let now = Utc::now();

    let node_count = graph.node_count();
    let edge_count = graph.edge_count();

    let inv = Investigation {
        id: inv_id.clone(),
        name: name.clone(),
        graph,
        timeline,
        created_at: now,
        status: "active".into(),
    };

    // Persist
    persist_investigation(&state, &inv).await;
    state
        .investigations
        .write()
        .await
        .insert(inv_id.clone(), inv);

    Ok(Json(InvestigationSummary {
        id: inv_id,
        name,
        created_at: now.to_rfc3339(),
        status: "active".into(),
        node_count,
        edge_count,
    }))
}

/// `POST /api/investigations/from-detection` — full detection→graph→timeline pipeline.
async fn create_from_detection(
    State(state): State<AppState>,
    Json(body): Json<CreateFromDetectionRequest>,
) -> Result<Json<CreateFromDetectionResponse>, WebError> {
    // 1. Check rule exists and get its preferred data source
    let rule = state
        .runner
        .get_rule(&body.rule_id)
        .ok_or_else(|| WebError::NotFound(format!("rule '{}' not found", body.rule_id)))?;
    let rule_data_sources = rule.metadata().data_sources.clone();

    // 2. Resolve source: explicit name, rule's preferred data_source, or first SL source
    let catalog = state.catalog.read().await;
    let source = if let Some(ref name) = body.source_name {
        catalog
            .get_source(name)
            .cloned()
            .ok_or_else(|| WebError::NotFound(format!("source '{name}' not found")))?
    } else if let Some(preferred) = rule_data_sources.first() {
        catalog.get_source(preferred).cloned().ok_or_else(|| {
            WebError::BadRequest(format!(
                "rule requires source '{preferred}' but it is not registered"
            ))
        })?
    } else {
        catalog
            .filter_by_tag("security-lake")
            .into_iter()
            .next()
            .cloned()
            .ok_or_else(|| WebError::BadRequest("no Security Lake source configured".into()))?
    };
    drop(catalog);

    // 3. Run detection
    let connector =
        irone_aws::create_connector(source, &state.sdk_config, state.config.use_direct_query).await;
    let result = state
        .runner
        .run_rule(
            &body.rule_id,
            &connector,
            None,
            Some(Utc::now()),
            body.lookback_minutes,
        )
        .await;

    // Gate: detection error
    if let Some(ref err) = result.error {
        return Err(WebError::Internal(format!("detection error: {err}")));
    }

    // Gate: not triggered
    if !result.triggered {
        return Ok(Json(CreateFromDetectionResponse {
            investigation_id: String::new(),
            name: String::new(),
            triggered: false,
            match_count: 0,
            node_count: 0,
            edge_count: 0,
        }));
    }

    // 3. Build graph with enrichment — Arrow-level string filters ensure
    //    only matching rows survive, keeping within the API Gateway 29s limit.
    let mut builder = GraphBuilder::new();
    Box::pin(builder.build_from_detection::<irone_aws::ConnectorKind>(
        &result,
        Some(&connector),
        body.enrichment_window_minutes,
        500,
        true,
    ))
    .await;
    let graph = builder.into_graph();

    // 4. Extract timeline
    let timeline = extract_timeline_from_graph(&graph, true, true);

    // 5. Create investigation
    let inv_id = uuid::Uuid::new_v4().to_string();
    let rule_name = result.rule_name.clone();
    let name = body
        .name
        .unwrap_or_else(|| format!("{} - {}", rule_name, Utc::now().format("%Y-%m-%d")));

    let node_count = graph.node_count();
    let edge_count = graph.edge_count();
    let match_count = result.match_count;

    let inv = Investigation {
        id: inv_id.clone(),
        name: name.clone(),
        graph,
        timeline,
        created_at: Utc::now(),
        status: "active".into(),
    };

    persist_investigation(&state, &inv).await;
    state
        .investigations
        .write()
        .await
        .insert(inv_id.clone(), inv);

    Ok(Json(CreateFromDetectionResponse {
        investigation_id: inv_id,
        name,
        triggered: true,
        match_count,
        node_count,
        edge_count,
    }))
}

/// `GET /api/investigations/{inv_id}` — get investigation details.
async fn get_investigation(
    State(state): State<AppState>,
    Path(inv_id): Path<String>,
) -> Result<Json<serde_json::Value>, WebError> {
    let invs = state.investigations.read().await;
    let inv = invs
        .get(&inv_id)
        .ok_or_else(|| WebError::NotFound(format!("investigation '{inv_id}' not found")))?;

    let summary = inv.graph.summary();
    let timeline_summary = inv.timeline.summary();

    Ok(Json(serde_json::json!({
        "id": inv.id,
        "name": inv.name,
        "created_at": inv.created_at.to_rfc3339(),
        "status": inv.status,
        "graph_summary": summary,
        "timeline_summary": timeline_summary,
    })))
}

/// `GET /api/investigations/{inv_id}/graph` — Cytoscape.js elements format.
async fn get_graph(
    State(state): State<AppState>,
    Path(inv_id): Path<String>,
) -> Result<Json<CytoscapeElements>, WebError> {
    let invs = state.investigations.read().await;
    let inv = invs
        .get(&inv_id)
        .ok_or_else(|| WebError::NotFound(format!("investigation '{inv_id}' not found")))?;

    let graph = &inv.graph;
    let mut elements = Vec::new();

    // Nodes → Cytoscape elements
    for node in graph.nodes.values() {
        let mut data = serde_json::Map::new();
        data.insert("id".into(), serde_json::Value::String(node.id.clone()));
        data.insert(
            "label".into(),
            serde_json::Value::String(node.label.clone()),
        );
        data.insert(
            "node_type".into(),
            serde_json::Value::String(node.node_type.to_string()),
        );
        if let Some(t) = node.first_seen {
            data.insert(
                "first_seen".into(),
                serde_json::Value::String(t.to_rfc3339()),
            );
        }
        if let Some(t) = node.last_seen {
            data.insert(
                "last_seen".into(),
                serde_json::Value::String(t.to_rfc3339()),
            );
        }
        data.insert(
            "event_count".into(),
            serde_json::Value::Number(node.event_count.into()),
        );
        elements.push(CytoscapeElement {
            group: "nodes",
            data,
        });
    }

    // Edges → Cytoscape elements
    for edge in &graph.edges {
        let mut data = serde_json::Map::new();
        data.insert("id".into(), serde_json::Value::String(edge.id.clone()));
        data.insert(
            "source".into(),
            serde_json::Value::String(edge.source_id.clone()),
        );
        data.insert(
            "target".into(),
            serde_json::Value::String(edge.target_id.clone()),
        );
        data.insert(
            "edge_type".into(),
            serde_json::Value::String(edge.edge_type.to_string()),
        );
        data.insert("weight".into(), serde_json::json!(edge.weight));
        data.insert(
            "event_count".into(),
            serde_json::Value::Number(edge.event_count.into()),
        );
        if !edge.properties.is_empty() {
            data.insert("properties".into(), serde_json::json!(edge.properties));
        }
        if let Some(t) = edge.first_seen {
            data.insert(
                "first_seen".into(),
                serde_json::Value::String(t.to_rfc3339()),
            );
        }
        if let Some(t) = edge.last_seen {
            data.insert(
                "last_seen".into(),
                serde_json::Value::String(t.to_rfc3339()),
            );
        }
        elements.push(CytoscapeElement {
            group: "edges",
            data,
        });
    }

    let summary = serde_json::to_value(graph.summary()).unwrap_or_default();

    Ok(Json(CytoscapeElements { elements, summary }))
}

/// `GET /api/investigations/{inv_id}/report` — generate report data.
async fn get_report(
    State(state): State<AppState>,
    Path(inv_id): Path<String>,
) -> Result<Json<serde_json::Value>, WebError> {
    let invs = state.investigations.read().await;
    let inv = invs
        .get(&inv_id)
        .ok_or_else(|| WebError::NotFound(format!("investigation '{inv_id}' not found")))?;

    let (start, end) = inv.timeline.time_range();
    let report = graph_to_report_data(
        &inv.graph,
        &inv.id,
        "", // executive_summary
        "", // ai_analysis
        start,
        end,
        Some(&inv.timeline),
    );

    Ok(Json(serde_json::to_value(report).unwrap_or_default()))
}

/// `GET /api/investigations/{inv_id}/timeline` — get timeline data directly.
async fn get_timeline(
    State(state): State<AppState>,
    Path(inv_id): Path<String>,
) -> Result<Json<InvestigationTimeline>, WebError> {
    let invs = state.investigations.read().await;
    let inv = invs
        .get(&inv_id)
        .ok_or_else(|| WebError::NotFound(format!("investigation '{inv_id}' not found")))?;

    Ok(Json(inv.timeline.clone()))
}

/// `POST /api/investigations/{inv_id}/enrich` — re-enrich an investigation.
async fn enrich_investigation(
    State(state): State<AppState>,
    Path(inv_id): Path<String>,
) -> Result<Json<serde_json::Value>, WebError> {
    // Get existing investigation
    let inv = {
        let invs = state.investigations.read().await;
        invs.get(&inv_id)
            .cloned()
            .ok_or_else(|| WebError::NotFound(format!("investigation '{inv_id}' not found")))?
    };

    // Find a Security Lake source for enrichment
    let catalog = state.catalog.read().await;
    let sl_sources = catalog.filter_by_tag("security-lake");
    let source = sl_sources
        .first()
        .copied()
        .cloned()
        .ok_or_else(|| WebError::BadRequest("no Security Lake source configured".into()))?;
    drop(catalog);

    // Build connector and re-enrich
    let connector =
        irone_aws::create_connector(source, &state.sdk_config, state.config.use_direct_query).await;

    // Extract identifiers from existing graph
    let principals: Vec<String> = inv
        .graph
        .get_nodes_by_type(&NodeType::Principal)
        .into_iter()
        .map(|n| n.label.clone())
        .collect();
    let ips: Vec<String> = inv
        .graph
        .get_nodes_by_type(&NodeType::IPAddress)
        .into_iter()
        .map(|n| n.label.clone())
        .collect();

    let (start, end) = inv.timeline.time_range();

    let mut builder = GraphBuilder::new();
    Box::pin(builder.build_from_identifiers(&connector, &principals, &ips, start, end, 1000, true))
        .await;
    let graph = builder.into_graph();
    let timeline = extract_timeline_from_graph(&graph, true, true);

    let node_count = graph.node_count();
    let edge_count = graph.edge_count();

    // Update in-memory
    let mut invs = state.investigations.write().await;
    if let Some(existing) = invs.get_mut(&inv_id) {
        existing.graph = graph;
        existing.timeline = timeline;
    }
    drop(invs);

    // Persist only the updated graph and timeline (avoid cloning entire Investigation)
    if let Some(ref store) = state.investigation_store {
        let invs = state.investigations.read().await;
        if let Some(inv) = invs.get(&inv_id) {
            let store = Arc::clone(store);
            let id = inv.id.clone();
            let graph = inv.graph.clone();
            let timeline = inv.timeline.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let _ = store.save_graph(&id, &graph);
                let _ = store.save_timeline(&id, &timeline);
                let _ = store.delete_artifacts(&id);
            })
            .await;
        }
    }

    Ok(Json(serde_json::json!({
        "enriched": true,
        "node_count": node_count,
        "edge_count": edge_count,
    })))
}

/// `POST /api/investigations/{inv_id}/timeline/tag` — tag a timeline event.
async fn tag_timeline_event(
    State(state): State<AppState>,
    Path(inv_id): Path<String>,
    Json(body): Json<TagEventRequest>,
) -> Result<Json<serde_json::Value>, WebError> {
    let mut invs = state.investigations.write().await;
    let inv = invs
        .get_mut(&inv_id)
        .ok_or_else(|| WebError::NotFound(format!("investigation '{inv_id}' not found")))?;

    let found = inv
        .timeline
        .tag_event(&body.event_id, body.tag.clone(), &body.notes);
    if !found {
        return Err(WebError::NotFound(format!(
            "event '{}' not found in investigation '{inv_id}'",
            body.event_id
        )));
    }

    // Persist tag
    if let Some(ref store) = state.investigation_store {
        let store = Arc::clone(store);
        let inv_id = inv_id.clone();
        let event_id = body.event_id.clone();
        let tag = body.tag.to_string();
        let notes = body.notes.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = store.tag_event(&inv_id, &event_id, &tag, &notes);
            let _ = store.delete_artifacts(&inv_id);
        })
        .await;
    }

    Ok(Json(serde_json::json!({
        "tagged": true,
        "event_id": body.event_id,
        "tag": body.tag,
    })))
}

/// `DELETE /api/investigations/{inv_id}` — delete an investigation.
async fn delete_investigation(
    State(state): State<AppState>,
    Path(inv_id): Path<String>,
) -> Result<Json<serde_json::Value>, WebError> {
    let removed = state.investigations.write().await.remove(&inv_id);
    if removed.is_none() {
        return Err(WebError::NotFound(format!(
            "investigation '{inv_id}' not found"
        )));
    }

    // Cascade delete from persistence
    if let Some(ref store) = state.investigation_store {
        let store = Arc::clone(store);
        let id = inv_id.clone();
        let _ = tokio::task::spawn_blocking(move || store.delete_investigation(&id)).await;
    }

    Ok(Json(serde_json::json!({ "deleted": inv_id })))
}

// -- Helpers --

/// `POST /api/investigations/seed` — create a demo investigation with synthetic data.
///
/// Builds a realistic graph with all node/edge types for testing and demos.
/// No Security Lake connection required.
async fn seed_investigation(
    State(state): State<AppState>,
    Json(body): Json<SeedInvestigationRequest>,
) -> Result<Json<InvestigationSummary>, WebError> {
    let inv_id = uuid::Uuid::new_v4().to_string();
    let name = body
        .name
        .unwrap_or_else(|| "Demo: Console Login Investigation".into());
    let now = Utc::now();

    let graph = build_seed_graph(now);
    let timeline = extract_timeline_from_graph(&graph, true, true);

    let inv = Investigation {
        id: inv_id.clone(),
        name: name.clone(),
        graph,
        timeline,
        created_at: now,
        status: "active".into(),
    };

    persist_investigation(&state, &inv).await;
    let summary = InvestigationSummary {
        id: inv_id.clone(),
        name,
        created_at: now.to_rfc3339(),
        status: "active".into(),
        node_count: inv.graph.node_count(),
        edge_count: inv.graph.edge_count(),
    };
    state.investigations.write().await.insert(inv_id, inv);

    Ok(Json(summary))
}

#[derive(Debug, Deserialize)]
pub struct SeedInvestigationRequest {
    pub name: Option<String>,
}

/// Build a realistic demo graph simulating a console login investigation.
#[allow(clippy::too_many_lines)]
fn build_seed_graph(now: DateTime<Utc>) -> SecurityGraph {
    use chrono::Duration;

    let mut graph = SecurityGraph::new();

    let t0 = now - Duration::hours(6);
    let _t1 = now - Duration::hours(5);
    let t2 = now - Duration::hours(4);
    let t3 = now - Duration::hours(3);
    let t4 = now - Duration::hours(2);
    let t5 = now - Duration::hours(1);

    // --- Principals ---
    let bryan = GraphNode {
        id: "Principal:bryan".into(),
        node_type: NodeType::Principal,
        label: "bryan".into(),
        properties: HashMap::new(),
        first_seen: Some(t0),
        last_seen: Some(t5),
        event_count: 12,
    };
    let attacker = GraphNode {
        id: "Principal:unknown-actor".into(),
        node_type: NodeType::Principal,
        label: "unknown-actor".into(),
        properties: HashMap::new(),
        first_seen: Some(t2),
        last_seen: Some(t4),
        event_count: 5,
    };

    // --- IPs ---
    let home_ip = GraphNode {
        id: "IP:73.162.45.100".into(),
        node_type: NodeType::IPAddress,
        label: "73.162.45.100".into(),
        properties: HashMap::new(),
        first_seen: Some(t0),
        last_seen: Some(t5),
        event_count: 10,
    };
    let suspicious_ip = GraphNode {
        id: "IP:185.220.101.42".into(),
        node_type: NodeType::IPAddress,
        label: "185.220.101.42".into(),
        properties: HashMap::new(),
        first_seen: Some(t2),
        last_seen: Some(t4),
        event_count: 8,
    };
    let internal_ip = GraphNode {
        id: "IP:10.0.1.50".into(),
        node_type: NodeType::IPAddress,
        label: "10.0.1.50".into(),
        properties: HashMap::new(),
        first_seen: Some(t3),
        last_seen: Some(t5),
        event_count: 20,
    };
    let c2_ip = GraphNode {
        id: "IP:203.0.113.66".into(),
        node_type: NodeType::IPAddress,
        label: "203.0.113.66".into(),
        properties: HashMap::new(),
        first_seen: Some(t3),
        last_seen: Some(t4),
        event_count: 150,
    };

    // --- API Operations ---
    let console_login = GraphNode {
        id: "API:ConsoleLogin".into(),
        node_type: NodeType::APIOperation,
        label: "ConsoleLogin".into(),
        properties: HashMap::new(),
        first_seen: Some(t0),
        last_seen: Some(t2),
        event_count: 3,
    };
    let create_key = GraphNode {
        id: "API:CreateAccessKey".into(),
        node_type: NodeType::APIOperation,
        label: "CreateAccessKey".into(),
        properties: HashMap::new(),
        first_seen: Some(t3),
        last_seen: Some(t3),
        event_count: 1,
    };
    let get_object = GraphNode {
        id: "API:GetObject".into(),
        node_type: NodeType::APIOperation,
        label: "s3:GetObject".into(),
        properties: HashMap::new(),
        first_seen: Some(t3),
        last_seen: Some(t4),
        event_count: 45,
    };
    let deactivate_mfa = GraphNode {
        id: "API:DeactivateMFADevice".into(),
        node_type: NodeType::APIOperation,
        label: "DeactivateMFADevice".into(),
        properties: HashMap::new(),
        first_seen: Some(t2),
        last_seen: Some(t2),
        event_count: 1,
    };

    // --- Resources ---
    let s3_bucket = GraphNode {
        id: "Resource:arn:aws:s3:::customer-data-prod".into(),
        node_type: NodeType::Resource,
        label: "s3://customer-data-prod".into(),
        properties: HashMap::new(),
        first_seen: Some(t3),
        last_seen: Some(t4),
        event_count: 45,
    };
    let iam_user = GraphNode {
        id: "Resource:arn:aws:iam::651804262336:user/bryan".into(),
        node_type: NodeType::Resource,
        label: "iam:user/bryan".into(),
        properties: HashMap::new(),
        first_seen: Some(t0),
        last_seen: Some(t3),
        event_count: 3,
    };
    let domain_node = GraphNode {
        id: "Resource:domain:c2-callback.evil.com".into(),
        node_type: NodeType::Resource,
        label: "c2-callback.evil.com".into(),
        properties: {
            let mut p = HashMap::new();
            p.insert("resource_type".into(), serde_json::json!("domain"));
            p
        },
        first_seen: Some(t3),
        last_seen: Some(t4),
        event_count: 150,
    };

    // --- Security Finding ---
    let finding = GraphNode {
        id: "Finding:detect-access-key-created-001".into(),
        node_type: NodeType::SecurityFinding,
        label: "IAM Access Key Created".into(),
        properties: {
            let mut p = HashMap::new();
            p.insert("severity".into(), serde_json::json!("medium"));
            p.insert(
                "rule_id".into(),
                serde_json::json!("detect-access-key-created"),
            );
            p
        },
        first_seen: Some(t3),
        last_seen: Some(t3),
        event_count: 1,
    };
    let finding2 = GraphNode {
        id: "Finding:detect-mfa-device-change-001".into(),
        node_type: NodeType::SecurityFinding,
        label: "MFA Device Modification".into(),
        properties: {
            let mut p = HashMap::new();
            p.insert("severity".into(), serde_json::json!("high"));
            p.insert(
                "rule_id".into(),
                serde_json::json!("detect-mfa-device-change"),
            );
            p
        },
        first_seen: Some(t2),
        last_seen: Some(t2),
        event_count: 1,
    };

    // Add all nodes
    for node in [
        bryan,
        attacker,
        home_ip,
        suspicious_ip,
        internal_ip,
        c2_ip,
        console_login,
        create_key,
        get_object,
        deactivate_mfa,
        s3_bucket,
        iam_user,
        domain_node,
        finding,
        finding2,
    ] {
        graph.add_node(node);
    }

    // --- Event nodes with OCSF properties for narrative generation ---
    let evt_login = GraphNode {
        id: "Event:seed-login-bryan".into(),
        node_type: NodeType::Event,
        label: "Authentication".into(),
        properties: {
            let mut p = HashMap::new();
            p.insert("class_uid".into(), serde_json::json!(3002));
            p.insert("actor_user_name".into(), serde_json::json!("bryan"));
            p.insert("actor_user_type".into(), serde_json::json!("IAMUser"));
            p.insert("api_service_name".into(), serde_json::json!("AWS Console"));
            p.insert("src_endpoint_ip".into(), serde_json::json!("73.162.45.100"));
            p.insert("status".into(), serde_json::json!("Success"));
            p
        },
        first_seen: Some(t0),
        last_seen: Some(t0),
        event_count: 1,
    };
    let evt_mfa = GraphNode {
        id: "Event:seed-mfa-deactivate".into(),
        node_type: NodeType::Event,
        label: "API Activity".into(),
        properties: {
            let mut p = HashMap::new();
            p.insert("class_uid".into(), serde_json::json!(6003));
            p.insert("actor_user_name".into(), serde_json::json!("unknown-actor"));
            p.insert(
                "api_operation".into(),
                serde_json::json!("DeactivateMFADevice"),
            );
            p.insert("api_service_name".into(), serde_json::json!("iam"));
            p.insert(
                "resource_arn".into(),
                serde_json::json!("arn:aws:iam::651804262336:user/bryan"),
            );
            p.insert(
                "src_endpoint_ip".into(),
                serde_json::json!("185.220.101.42"),
            );
            p
        },
        first_seen: Some(t2),
        last_seen: Some(t2),
        event_count: 1,
    };
    let evt_create_key = GraphNode {
        id: "Event:seed-create-access-key".into(),
        node_type: NodeType::Event,
        label: "API Activity".into(),
        properties: {
            let mut p = HashMap::new();
            p.insert("class_uid".into(), serde_json::json!(6003));
            p.insert("actor_user_name".into(), serde_json::json!("unknown-actor"));
            p.insert("api_operation".into(), serde_json::json!("CreateAccessKey"));
            p.insert("api_service_name".into(), serde_json::json!("iam"));
            p.insert(
                "resource_arn".into(),
                serde_json::json!("arn:aws:iam::651804262336:user/bryan"),
            );
            p.insert(
                "src_endpoint_ip".into(),
                serde_json::json!("185.220.101.42"),
            );
            p
        },
        first_seen: Some(t3),
        last_seen: Some(t3),
        event_count: 1,
    };
    let evt_exfil = GraphNode {
        id: "Event:seed-s3-getobject".into(),
        node_type: NodeType::Event,
        label: "API Activity".into(),
        properties: {
            let mut p = HashMap::new();
            p.insert("class_uid".into(), serde_json::json!(6003));
            p.insert("actor_user_name".into(), serde_json::json!("unknown-actor"));
            p.insert("api_operation".into(), serde_json::json!("GetObject"));
            p.insert("api_service_name".into(), serde_json::json!("s3"));
            p.insert(
                "resource_arn".into(),
                serde_json::json!("arn:aws:s3:::customer-data-prod"),
            );
            p.insert(
                "src_endpoint_ip".into(),
                serde_json::json!("185.220.101.42"),
            );
            p
        },
        first_seen: Some(t3),
        last_seen: Some(t4),
        event_count: 45,
    };
    let evt_dns = GraphNode {
        id: "Event:seed-dns-c2".into(),
        node_type: NodeType::Event,
        label: "DNS Activity".into(),
        properties: {
            let mut p = HashMap::new();
            p.insert("class_uid".into(), serde_json::json!(4003));
            p.insert("src_endpoint_ip".into(), serde_json::json!("10.0.1.50"));
            p.insert(
                "query_hostname".into(),
                serde_json::json!("c2-callback.evil.com"),
            );
            p
        },
        first_seen: Some(t3),
        last_seen: Some(t4),
        event_count: 150,
    };
    let evt_flow = GraphNode {
        id: "Event:seed-flow-c2".into(),
        node_type: NodeType::Event,
        label: "Network Activity".into(),
        properties: {
            let mut p = HashMap::new();
            p.insert("class_uid".into(), serde_json::json!(4001));
            p.insert("src_endpoint_ip".into(), serde_json::json!("10.0.1.50"));
            p.insert("dst_endpoint_ip".into(), serde_json::json!("203.0.113.66"));
            p.insert("protocol_name".into(), serde_json::json!("TCP"));
            p.insert("dst_port".into(), serde_json::json!(443));
            p.insert("bytes_in".into(), serde_json::json!(45_000_u64));
            p.insert("bytes_out".into(), serde_json::json!(150_000_000_u64));
            p
        },
        first_seen: Some(t3),
        last_seen: Some(t4),
        event_count: 85,
    };

    for node in [
        evt_login,
        evt_mfa,
        evt_create_key,
        evt_exfil,
        evt_dns,
        evt_flow,
    ] {
        graph.add_node(node);
    }

    // --- Edges ---
    // Bryan's normal activity
    graph.add_edge(make_seed_edge(
        EdgeType::AuthenticatedFrom,
        "Principal:bryan",
        "IP:73.162.45.100",
        t0,
    ));
    graph.add_edge(make_seed_edge(
        EdgeType::CalledApi,
        "Principal:bryan",
        "API:ConsoleLogin",
        t0,
    ));

    // Attacker's activity from suspicious IP
    graph.add_edge(make_seed_edge(
        EdgeType::AuthenticatedFrom,
        "Principal:unknown-actor",
        "IP:185.220.101.42",
        t2,
    ));
    graph.add_edge(make_seed_edge(
        EdgeType::CalledApi,
        "Principal:unknown-actor",
        "API:DeactivateMFADevice",
        t2,
    ));
    graph.add_edge(make_seed_edge(
        EdgeType::CalledApi,
        "Principal:unknown-actor",
        "API:CreateAccessKey",
        t3,
    ));
    graph.add_edge(make_seed_edge(
        EdgeType::CalledApi,
        "Principal:unknown-actor",
        "API:GetObject",
        t3,
    ));

    // API → Resource edges
    graph.add_edge(make_seed_edge(
        EdgeType::AccessedResource,
        "API:GetObject",
        "Resource:arn:aws:s3:::customer-data-prod",
        t3,
    ));
    graph.add_edge(make_seed_edge(
        EdgeType::AccessedResource,
        "API:CreateAccessKey",
        "Resource:arn:aws:iam::651804262336:user/bryan",
        t3,
    ));
    graph.add_edge(make_seed_edge(
        EdgeType::AccessedResource,
        "API:DeactivateMFADevice",
        "Resource:arn:aws:iam::651804262336:user/bryan",
        t2,
    ));

    // Finding edges
    graph.add_edge(make_seed_edge(
        EdgeType::TriggeredBy,
        "Finding:detect-access-key-created-001",
        "API:CreateAccessKey",
        t3,
    ));
    graph.add_edge(make_seed_edge(
        EdgeType::PerformedBy,
        "Finding:detect-access-key-created-001",
        "Principal:unknown-actor",
        t3,
    ));
    graph.add_edge(make_seed_edge(
        EdgeType::TriggeredBy,
        "Finding:detect-mfa-device-change-001",
        "API:DeactivateMFADevice",
        t2,
    ));
    graph.add_edge(make_seed_edge(
        EdgeType::PerformedBy,
        "Finding:detect-mfa-device-change-001",
        "Principal:unknown-actor",
        t2,
    ));

    // Network flows (CommunicatedWith with aggregated properties)
    let mut flow1_props = HashMap::new();
    flow1_props.insert("bytes_in".into(), serde_json::json!(45_000_u64));
    flow1_props.insert("bytes_out".into(), serde_json::json!(150_000_000_u64));
    flow1_props.insert("dst_port".into(), serde_json::json!([443, 8443]));
    flow1_props.insert("protocol".into(), serde_json::json!("TCP"));
    let flow1 = GraphEdge {
        id: GraphEdge::create_id(
            &EdgeType::CommunicatedWith,
            "IP:10.0.1.50",
            "IP:203.0.113.66",
        ),
        edge_type: EdgeType::CommunicatedWith,
        source_id: "IP:10.0.1.50".into(),
        target_id: "IP:203.0.113.66".into(),
        properties: flow1_props,
        weight: (150_045_000_f64).log2(), // ~27.2
        first_seen: Some(t3),
        last_seen: Some(t4),
        event_count: 85,
    };
    graph.add_edge(flow1);

    let mut flow2_props = HashMap::new();
    flow2_props.insert("bytes_in".into(), serde_json::json!(2000_u64));
    flow2_props.insert("bytes_out".into(), serde_json::json!(500_u64));
    flow2_props.insert("dst_port".into(), serde_json::json!([22]));
    flow2_props.insert("protocol".into(), serde_json::json!("TCP"));
    let flow2 = GraphEdge {
        id: GraphEdge::create_id(
            &EdgeType::CommunicatedWith,
            "IP:185.220.101.42",
            "IP:10.0.1.50",
        ),
        edge_type: EdgeType::CommunicatedWith,
        source_id: "IP:185.220.101.42".into(),
        target_id: "IP:10.0.1.50".into(),
        properties: flow2_props,
        weight: (2500_f64).log2(),
        first_seen: Some(t2),
        last_seen: Some(t3),
        event_count: 3,
    };
    graph.add_edge(flow2);

    // DNS resolution (ResolvedTo)
    graph.add_edge(make_seed_edge(
        EdgeType::ResolvedTo,
        "IP:10.0.1.50",
        "Resource:domain:c2-callback.evil.com",
        t3,
    ));

    // RelatedTo: suspicious IP and attacker linked to compromised host
    graph.add_edge(make_seed_edge(
        EdgeType::RelatedTo,
        "IP:185.220.101.42",
        "IP:10.0.1.50",
        t2,
    ));

    graph
}

fn make_seed_edge(
    edge_type: EdgeType,
    source_id: &str,
    target_id: &str,
    time: DateTime<Utc>,
) -> GraphEdge {
    GraphEdge {
        id: GraphEdge::create_id(&edge_type, source_id, target_id),
        edge_type,
        source_id: source_id.to_string(),
        target_id: target_id.to_string(),
        properties: HashMap::new(),
        weight: 1.0,
        first_seen: Some(time),
        last_seen: Some(time),
        event_count: 1,
    }
}

async fn persist_investigation(state: &AppState, inv: &Investigation) {
    if let Some(ref store) = state.investigation_store {
        let store = Arc::clone(store);
        let id = inv.id.clone();
        let name = inv.name.clone();
        let graph = inv.graph.clone();
        let timeline = inv.timeline.clone();
        let created_at = inv.created_at;
        let status = inv.status.clone();

        let _ = tokio::task::spawn_blocking(move || {
            let _ = store.save_investigation(&id, &name, &graph, Some(created_at), None, &status);
            let _ = store.save_timeline(&id, &timeline);
        })
        .await;
    }
}
