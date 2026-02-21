use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use iris_core::graph::{
    EventTag, GraphBuilder, NodeType, SecurityGraph, extract_timeline_from_graph,
};
use iris_core::reports::graph_to_report_data;

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
        .route(
            "/investigations/{inv_id}/enrich",
            post(enrich_investigation),
        )
        .route(
            "/investigations/{inv_id}/timeline/tag",
            post(tag_timeline_event),
        )
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
            iris_aws::create_connector(source, &state.sdk_config, state.config.use_direct_query)
                .await;
        let mut builder = GraphBuilder::new();
        builder
            .build_from_identifiers(
                &connector,
                &body.users,
                &body.ips,
                body.start,
                body.end,
                1000,
                true,
            )
            .await;
        builder.into_graph()
    } else {
        SecurityGraph::new()
    };

    let timeline = extract_timeline_from_graph(&graph, true, true);
    let now = Utc::now();

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
        node_count: 0,
        edge_count: 0,
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
        iris_aws::create_connector(source, &state.sdk_config, state.config.use_direct_query).await;
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

    // 3. Build graph from detection matches only (no enrichment).
    //    Enrichment scans too many Parquet files for the API Gateway 29s limit.
    //    Use POST /investigations/{id}/enrich for enrichment after creation.
    let mut builder = GraphBuilder::new();
    builder
        .build_from_detection::<iris_aws::ConnectorKind>(
            &result,
            None,
            body.enrichment_window_minutes,
            1000,
            true,
        )
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
        iris_aws::create_connector(source, &state.sdk_config, state.config.use_direct_query).await;

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
    builder
        .build_from_identifiers(&connector, &principals, &ips, start, end, 1000, true)
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
