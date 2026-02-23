use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use irone_core::audit;
use irone_core::graph::{
    AttackNarrative, EdgeType, EventTag, GraphBuilder, GraphEdge, GraphNode, InvestigationTimeline,
    NodeType, SecurityGraph, extract_attack_paths, extract_timeline_from_graph,
};
use irone_core::reports::graph_to_report_data;

use crate::error::WebError;
use crate::investigation_store::InvestigationMetadata;
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
            "/investigations/{inv_id}/attack-paths",
            get(get_attack_paths),
        )
        .route("/investigations/{inv_id}/anomalies", get(get_anomalies))
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

/// Maximum number of identifiers (users/IPs) per request.
const MAX_IDENTIFIERS: usize = 100;

/// Maximum name length.
const MAX_NAME_LENGTH: usize = 256;

/// Maximum lookback window in minutes (7 days).
const MAX_LOOKBACK_MINUTES: i64 = 10080;

impl CreateInvestigationRequest {
    fn validate(&self) -> Result<(), WebError> {
        if self.users.len() > MAX_IDENTIFIERS {
            return Err(WebError::BadRequest(format!(
                "too many users (max {MAX_IDENTIFIERS}, got {})",
                self.users.len()
            )));
        }
        if self.ips.len() > MAX_IDENTIFIERS {
            return Err(WebError::BadRequest(format!(
                "too many IPs (max {MAX_IDENTIFIERS}, got {})",
                self.ips.len()
            )));
        }
        if let Some(ref name) = self.name
            && name.len() > MAX_NAME_LENGTH
        {
            return Err(WebError::BadRequest(format!(
                "name too long (max {MAX_NAME_LENGTH} chars)"
            )));
        }
        if let (Some(start), Some(end)) = (self.start, self.end) {
            if start >= end {
                return Err(WebError::BadRequest(
                    "start time must be before end time".into(),
                ));
            }
            let range = end - start;
            if range.num_minutes() > MAX_LOOKBACK_MINUTES {
                return Err(WebError::BadRequest(format!(
                    "time range too large (max {} days)",
                    MAX_LOOKBACK_MINUTES / 1440
                )));
            }
        }
        Ok(())
    }
}

impl CreateFromDetectionRequest {
    fn validate(&self) -> Result<(), WebError> {
        if self.rule_id.is_empty() {
            return Err(WebError::BadRequest("rule_id is required".into()));
        }
        if self.lookback_minutes <= 0 || self.lookback_minutes > MAX_LOOKBACK_MINUTES {
            return Err(WebError::BadRequest(format!(
                "lookback_minutes must be 1..{MAX_LOOKBACK_MINUTES}"
            )));
        }
        if self.enrichment_window_minutes <= 0
            || self.enrichment_window_minutes > MAX_LOOKBACK_MINUTES
        {
            return Err(WebError::BadRequest(format!(
                "enrichment_window_minutes must be 1..{MAX_LOOKBACK_MINUTES}"
            )));
        }
        if let Some(ref name) = self.name
            && name.len() > MAX_NAME_LENGTH
        {
            return Err(WebError::BadRequest(format!(
                "name too long (max {MAX_NAME_LENGTH} chars)"
            )));
        }
        Ok(())
    }
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
async fn list_investigations(
    State(state): State<AppState>,
) -> Result<Json<Vec<InvestigationSummary>>, WebError> {
    // DynamoDB path
    if let Some(ref ddb_store) = state.dynamo_investigation_store {
        let metas = ddb_store.list_investigations().await.map_err(|e| {
            WebError::Internal(format!("failed to list investigations from DynamoDB: {e}"))
        })?;
        let summaries = metas
            .into_iter()
            .map(|m| InvestigationSummary {
                id: m.id,
                name: m.name,
                created_at: m.created_at,
                status: m.status,
                node_count: m.node_count,
                edge_count: m.edge_count,
            })
            .collect();
        return Ok(Json(summaries));
    }

    // In-memory fallback
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
    Ok(Json(summaries))
}

/// `POST /api/investigations` — create from identifiers.
async fn create_investigation(
    State(state): State<AppState>,
    Json(body): Json<CreateInvestigationRequest>,
) -> Result<Json<InvestigationSummary>, WebError> {
    body.validate()?;
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

    audit::investigation_created("api", &inv_id, &name);

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
#[allow(clippy::too_many_lines)]
async fn create_from_detection(
    State(state): State<AppState>,
    Json(body): Json<CreateFromDetectionRequest>,
) -> Result<Json<CreateFromDetectionResponse>, WebError> {
    body.validate()?;
    // 1. Check rule exists and get its preferred data source
    let rule = state
        .runner
        .get_rule(&body.rule_id)
        .ok_or_else(|| WebError::NotFound(format!("rule '{}' not found", body.rule_id)))?;
    let rule_data_sources = rule.metadata().data_sources.clone();
    let rule_name = rule.metadata().name.clone();

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

    // 3. Run detection synchronously (fast with filter pushdown, ~2-5s)
    let use_direct = state.config.use_direct_query;
    let connector =
        irone_aws::create_connector(source.clone(), &state.sdk_config, use_direct).await;
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

    if result.error.is_some() {
        return Err(WebError::Internal(format!(
            "detection failed: {}",
            result.error.as_deref().unwrap_or("unknown")
        )));
    }

    // 4. Build minimal graph from detection matches (no enrichment yet)
    let mut builder = GraphBuilder::new();
    Box::pin(builder.build_from_detection::<irone_aws::ConnectorKind>(&result, None, 0, 0, true))
        .await;
    let graph = builder.into_graph();
    let node_count = graph.nodes.len();
    let edge_count = graph.edges.len();

    // 5. Create investigation with detection results
    let inv_id = uuid::Uuid::new_v4().to_string();
    let name = body
        .name
        .unwrap_or_else(|| format!("{} - {}", rule_name, Utc::now().format("%Y-%m-%d")));

    let triggered = result.triggered;
    let match_count = result.match_count;

    let status = if triggered { "enriching" } else { "active" };

    let pipeline_enabled = !state.config.investigation_state_machine_arn.is_empty();

    if pipeline_enabled {
        // --- Step Functions pipeline path ---
        let s3_client = state.s3_client.as_ref().ok_or_else(|| {
            WebError::Internal("pipeline enabled but S3 client not initialized".into())
        })?;
        let bucket = &state.config.report_bucket;
        let now = Utc::now();

        // Write DetectionResult to S3
        let detection_json = serde_json::to_vec(&result).map_err(|e| {
            WebError::Internal(format!("failed to serialize detection result: {e}"))
        })?;
        s3_client
            .put_object()
            .bucket(bucket)
            .key(format!("investigations/{inv_id}/detection_result.json"))
            .body(detection_json.into())
            .content_type("application/json")
            .send()
            .await
            .map_err(|e| {
                WebError::Internal(format!("failed to write detection result to S3: {e}"))
            })?;

        // Write minimal graph to S3 for immediate display
        let graph_json = serde_json::to_vec(&graph)
            .map_err(|e| WebError::Internal(format!("failed to serialize graph: {e}")))?;
        s3_client
            .put_object()
            .bucket(bucket)
            .key(format!("investigations/{inv_id}/graph.json"))
            .body(graph_json.into())
            .content_type("application/json")
            .send()
            .await
            .map_err(|e| WebError::Internal(format!("failed to write graph to S3: {e}")))?;

        // Create DynamoDB record
        if let Some(ref ddb_store) = state.dynamo_investigation_store {
            let source_name = body
                .source_name
                .as_deref()
                .unwrap_or(&source.name)
                .to_string();
            let meta = InvestigationMetadata {
                id: inv_id.clone(),
                name: name.clone(),
                status: status.into(),
                rule_id: body.rule_id.clone(),
                source_name: source_name.clone(),
                triggered,
                match_count,
                node_count,
                edge_count,
                created_at: now.to_rfc3339(),
                updated_at: now.to_rfc3339(),
                sfn_execution_arn: None,
                error: None,
            };
            ddb_store.create_investigation(&meta).await.map_err(|e| {
                WebError::Internal(format!("failed to create DynamoDB record: {e}"))
            })?;

            // Start Step Function execution if detection triggered
            if triggered && let Some(ref sfn_client) = state.sfn_client {
                let sfn_input = serde_json::json!({
                    "action": "enrich",
                    "investigation_id": inv_id,
                    "rule_id": body.rule_id,
                    "source_name": source_name,
                    "enrichment_window_minutes": body.enrichment_window_minutes,
                    "bucket": bucket,
                });

                let exec = sfn_client
                    .start_execution()
                    .state_machine_arn(&state.config.investigation_state_machine_arn)
                    .name(format!("inv-{inv_id}"))
                    .input(sfn_input.to_string())
                    .send()
                    .await
                    .map_err(|e| {
                        WebError::Internal(format!("failed to start Step Function: {e}"))
                    })?;

                tracing::info!(
                    inv_id = %inv_id,
                    execution_arn = %exec.execution_arn(),
                    "started Step Function enrichment"
                );
            }
        }

        // Also store in-memory for immediate reads (cache)
        let inv = Investigation {
            id: inv_id.clone(),
            name: name.clone(),
            graph,
            timeline: InvestigationTimeline::default(),
            created_at: now,
            status: status.into(),
        };
        state
            .investigations
            .write()
            .await
            .insert(inv_id.clone(), inv);
    } else {
        // --- Legacy in-memory path (local dev) ---
        let inv = Investigation {
            id: inv_id.clone(),
            name: name.clone(),
            graph,
            timeline: InvestigationTimeline::default(),
            created_at: Utc::now(),
            status: status.into(),
        };
        state
            .investigations
            .write()
            .await
            .insert(inv_id.clone(), inv);

        if triggered {
            let bg_state = state.clone();
            let bg_inv_id = inv_id.clone();
            let enrichment_window = body.enrichment_window_minutes;

            tokio::spawn(async move {
                let bg_connector =
                    irone_aws::create_connector(source, &bg_state.sdk_config, use_direct).await;

                let mut builder = GraphBuilder::new();
                Box::pin(builder.build_from_detection::<irone_aws::ConnectorKind>(
                    &result,
                    Some(&bg_connector),
                    enrichment_window,
                    1000,
                    true,
                ))
                .await;
                let graph = builder.into_graph();
                let timeline = extract_timeline_from_graph(&graph, true, true);

                let inv_snapshot = {
                    let mut invs = bg_state.investigations.write().await;
                    if let Some(inv) = invs.get_mut(&bg_inv_id) {
                        inv.graph = graph;
                        inv.timeline = timeline;
                        inv.status = "active".into();
                        Some(inv.clone())
                    } else {
                        None
                    }
                };

                if let Some(ref inv) = inv_snapshot {
                    persist_investigation(&bg_state, inv).await;
                }

                tracing::info!(
                    inv_id = %bg_inv_id,
                    "background enrichment complete"
                );
            });
        } else {
            let invs = state.investigations.read().await;
            if let Some(inv) = invs.get(&inv_id) {
                persist_investigation(&state, inv).await;
            }
        }
    }

    audit::investigation_created("api", &inv_id, &name);

    Ok(Json(CreateFromDetectionResponse {
        investigation_id: inv_id,
        name,
        triggered,
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
    // DynamoDB path: return metadata + graph summary from S3 if available
    if let Some(ref ddb_store) = state.dynamo_investigation_store {
        let meta = ddb_store
            .get_investigation(&inv_id)
            .await
            .map_err(|e| WebError::Internal(format!("DynamoDB read failed: {e}")))?
            .ok_or_else(|| WebError::NotFound(format!("investigation '{inv_id}' not found")))?;

        // Try to load graph summary from S3 for enriched investigations
        let graph_summary = if meta.status == "active" {
            load_graph_from_s3(&state, &inv_id)
                .await
                .map(|g| g.summary())
                .ok()
        } else {
            None
        };

        return Ok(Json(serde_json::json!({
            "id": meta.id,
            "name": meta.name,
            "created_at": meta.created_at,
            "status": meta.status,
            "graph_summary": graph_summary,
            "node_count": meta.node_count,
            "edge_count": meta.edge_count,
            "rule_id": meta.rule_id,
            "triggered": meta.triggered,
            "match_count": meta.match_count,
            "error": meta.error,
        })));
    }

    // In-memory fallback
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
        "metadata": inv.graph.metadata,
    })))
}

/// `GET /api/investigations/{inv_id}/graph` — Cytoscape.js elements format.
async fn get_graph(
    State(state): State<AppState>,
    Path(inv_id): Path<String>,
) -> Result<Json<CytoscapeElements>, WebError> {
    // S3 path: load graph from S3
    if state.s3_client.is_some() {
        let graph = load_graph_from_s3(&state, &inv_id).await.map_err(|e| {
            WebError::NotFound(format!("graph not found for investigation '{inv_id}': {e}"))
        })?;
        return Ok(Json(graph_to_cytoscape(&graph)));
    }

    // In-memory fallback
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
    // S3 path: load graph + timeline from S3
    if state.s3_client.is_some() {
        let graph = load_graph_from_s3(&state, &inv_id).await.map_err(|e| {
            WebError::NotFound(format!("graph not found for investigation '{inv_id}': {e}"))
        })?;
        let timeline = load_timeline_from_s3(&state, &inv_id)
            .await
            .unwrap_or_else(|_| InvestigationTimeline::new(&inv_id));
        let (start, end) = timeline.time_range();
        let report = graph_to_report_data(&graph, &inv_id, "", "", start, end, Some(&timeline));
        return Ok(Json(serde_json::to_value(report).unwrap_or_default()));
    }

    // In-memory fallback
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
    // S3 path
    if state.s3_client.is_some() {
        let timeline = load_timeline_from_s3(&state, &inv_id).await.map_err(|e| {
            WebError::NotFound(format!(
                "timeline not found for investigation '{inv_id}': {e}"
            ))
        })?;
        return Ok(Json(timeline));
    }

    // In-memory fallback
    let invs = state.investigations.read().await;
    let inv = invs
        .get(&inv_id)
        .ok_or_else(|| WebError::NotFound(format!("investigation '{inv_id}' not found")))?;

    Ok(Json(inv.timeline.clone()))
}

/// `GET /api/investigations/{inv_id}/attack-paths` — extracted kill chain narratives.
async fn get_attack_paths(
    State(state): State<AppState>,
    Path(inv_id): Path<String>,
) -> Result<Json<Vec<AttackNarrative>>, WebError> {
    // S3 path: try pre-computed attack_paths.json first, fall back to on-demand
    if state.s3_client.is_some() {
        if let Ok(paths) = load_attack_paths_from_s3(&state, &inv_id).await {
            return Ok(Json(paths));
        }
        // Fall back to computing from graph
        let graph = load_graph_from_s3(&state, &inv_id).await.map_err(|e| {
            WebError::NotFound(format!("graph not found for investigation '{inv_id}': {e}"))
        })?;
        return Ok(Json(extract_attack_paths(&graph)));
    }

    // In-memory fallback
    let invs = state.investigations.read().await;
    let inv = invs
        .get(&inv_id)
        .ok_or_else(|| WebError::NotFound(format!("investigation '{inv_id}' not found")))?;

    Ok(Json(extract_attack_paths(&inv.graph)))
}

/// `GET /api/investigations/{inv_id}/anomalies` — entity anomaly scores from enrichment.
async fn get_anomalies(
    State(state): State<AppState>,
    Path(inv_id): Path<String>,
) -> Result<Json<serde_json::Value>, WebError> {
    // S3 path: load graph and extract anomaly scores from metadata
    if state.s3_client.is_some() {
        let graph = load_graph_from_s3(&state, &inv_id).await.map_err(|e| {
            WebError::NotFound(format!("graph not found for investigation '{inv_id}': {e}"))
        })?;
        let scores = graph
            .metadata
            .get("anomaly_scores")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]));
        return Ok(Json(scores));
    }

    // In-memory fallback
    let invs = state.investigations.read().await;
    let inv = invs
        .get(&inv_id)
        .ok_or_else(|| WebError::NotFound(format!("investigation '{inv_id}' not found")))?;

    let scores = inv
        .graph
        .metadata
        .get("anomaly_scores")
        .cloned()
        .unwrap_or(serde_json::Value::Array(vec![]));
    Ok(Json(scores))
}

/// `POST /api/investigations/{inv_id}/enrich` — re-enrich an investigation.
#[allow(clippy::too_many_lines)]
async fn enrich_investigation(
    State(state): State<AppState>,
    Path(inv_id): Path<String>,
) -> Result<Json<serde_json::Value>, WebError> {
    // Pipeline path: start a new Step Function execution
    if let Some(ref sfn_client) = state.sfn_client
        && let Some(ref ddb_store) = state.dynamo_investigation_store
    {
        let meta = ddb_store
            .get_investigation(&inv_id)
            .await
            .map_err(|e| WebError::Internal(format!("DynamoDB read failed: {e}")))?
            .ok_or_else(|| WebError::NotFound(format!("investigation '{inv_id}' not found")))?;

        // Mark as enriching
        if let Err(e) = ddb_store
            .update_status(&inv_id, "enriching", None, None, None)
            .await
        {
            tracing::error!(investigation_id = %inv_id, error = %e, "failed to mark investigation as enriching");
        }

        let sfn_input = serde_json::json!({
            "action": "enrich",
            "investigation_id": inv_id,
            "rule_id": meta.rule_id,
            "source_name": meta.source_name,
            "enrichment_window_minutes": 120,
            "bucket": state.config.report_bucket,
        });

        sfn_client
            .start_execution()
            .state_machine_arn(&state.config.investigation_state_machine_arn)
            .name(format!("enrich-{inv_id}-{}", Utc::now().timestamp()))
            .input(sfn_input.to_string())
            .send()
            .await
            .map_err(|e| WebError::Internal(format!("failed to start Step Function: {e}")))?;

        audit::investigation_enriched("api", &inv_id, 0, 0);
        return Ok(Json(serde_json::json!({
            "enriching": true,
            "investigation_id": inv_id,
        })));
    }

    // In-memory fallback path
    let inv = {
        let invs = state.investigations.read().await;
        invs.get(&inv_id)
            .cloned()
            .ok_or_else(|| WebError::NotFound(format!("investigation '{inv_id}' not found")))?
    };

    let catalog = state.catalog.read().await;
    let sl_sources = catalog.filter_by_tag("security-lake");
    let source = sl_sources
        .first()
        .copied()
        .cloned()
        .ok_or_else(|| WebError::BadRequest("no Security Lake source configured".into()))?;
    drop(catalog);

    let connector =
        irone_aws::create_connector(source, &state.sdk_config, state.config.use_direct_query).await;

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

    let mut invs = state.investigations.write().await;
    if let Some(existing) = invs.get_mut(&inv_id) {
        existing.graph = graph;
        existing.timeline = timeline;
    }
    drop(invs);

    if let Some(ref store) = state.investigation_store {
        let invs = state.investigations.read().await;
        if let Some(inv) = invs.get(&inv_id) {
            let store = Arc::clone(store);
            let id = inv.id.clone();
            let graph = inv.graph.clone();
            let timeline = inv.timeline.clone();
            match tokio::task::spawn_blocking(move || {
                if let Err(e) = store.save_graph(&id, &graph) {
                    tracing::error!(investigation_id = %id, error = %e, "failed to save enriched graph");
                }
                if let Err(e) = store.save_timeline(&id, &timeline) {
                    tracing::error!(investigation_id = %id, error = %e, "failed to save enriched timeline");
                }
                if let Err(e) = store.delete_artifacts(&id) {
                    tracing::error!(investigation_id = %id, error = %e, "failed to delete stale artifacts");
                }
            })
            .await
            {
                Ok(()) => {}
                Err(e) => tracing::error!(error = %e, "enrichment persist task panicked"),
            }
        }
    }

    audit::investigation_enriched("api", &inv_id, node_count, edge_count);

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
        match tokio::task::spawn_blocking(move || {
            if let Err(e) = store.tag_event(&inv_id, &event_id, &tag, &notes) {
                tracing::error!(investigation_id = %inv_id, event_id = %event_id, error = %e, "failed to persist event tag");
            }
            if let Err(e) = store.delete_artifacts(&inv_id) {
                tracing::error!(investigation_id = %inv_id, error = %e, "failed to delete stale artifacts after tagging");
            }
        })
        .await
        {
            Ok(()) => {}
            Err(e) => tracing::error!(error = %e, "tag persist task panicked"),
        }
    }

    audit::timeline_event_tagged("api", &inv_id, &body.event_id, &body.tag.to_string());

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
    // DynamoDB path
    if let Some(ref ddb_store) = state.dynamo_investigation_store {
        ddb_store
            .delete_investigation(&inv_id)
            .await
            .map_err(|e| WebError::Internal(format!("DynamoDB delete failed: {e}")))?;
        // Also remove from in-memory cache
        state.investigations.write().await.remove(&inv_id);
        // Note: S3 artifacts are left for TTL/lifecycle cleanup
        audit::investigation_deleted("api", &inv_id);
        return Ok(Json(serde_json::json!({ "deleted": inv_id })));
    }

    // In-memory fallback
    let removed = state.investigations.write().await.remove(&inv_id);
    if removed.is_none() {
        return Err(WebError::NotFound(format!(
            "investigation '{inv_id}' not found"
        )));
    }

    if let Some(ref store) = state.investigation_store {
        let store = Arc::clone(store);
        let id = inv_id.clone();
        match tokio::task::spawn_blocking(move || {
            if let Err(e) = store.delete_investigation(&id) {
                tracing::error!(investigation_id = %id, error = %e, "failed to delete investigation from persistence");
            }
        })
        .await
        {
            Ok(()) => {}
            Err(e) => tracing::error!(error = %e, "delete persist task panicked"),
        }
    }

    audit::investigation_deleted("api", &inv_id);
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

/// Load a `SecurityGraph` from S3 for the given investigation.
async fn load_graph_from_s3(state: &AppState, inv_id: &str) -> Result<SecurityGraph, String> {
    let s3_client = state
        .s3_client
        .as_ref()
        .ok_or_else(|| "S3 client not initialized".to_string())?;
    let bucket = &state.config.report_bucket;
    let key = format!("investigations/{inv_id}/graph.json");

    let bytes = s3_client
        .get_object()
        .bucket(bucket)
        .key(&key)
        .send()
        .await
        .map_err(|e| format!("S3 GetObject failed: {e}"))?
        .body
        .collect()
        .await
        .map_err(|e| format!("S3 body read failed: {e}"))?
        .into_bytes();

    serde_json::from_slice(&bytes).map_err(|e| format!("graph deserialization failed: {e}"))
}

/// Load an `InvestigationTimeline` from S3 for the given investigation.
async fn load_timeline_from_s3(
    state: &AppState,
    inv_id: &str,
) -> Result<InvestigationTimeline, String> {
    let s3_client = state
        .s3_client
        .as_ref()
        .ok_or_else(|| "S3 client not initialized".to_string())?;
    let bucket = &state.config.report_bucket;
    let key = format!("investigations/{inv_id}/timeline.json");

    let bytes = s3_client
        .get_object()
        .bucket(bucket)
        .key(&key)
        .send()
        .await
        .map_err(|e| format!("S3 GetObject failed: {e}"))?
        .body
        .collect()
        .await
        .map_err(|e| format!("S3 body read failed: {e}"))?
        .into_bytes();

    serde_json::from_slice(&bytes).map_err(|e| format!("timeline deserialization failed: {e}"))
}

/// Load pre-computed attack paths from S3 for the given investigation.
async fn load_attack_paths_from_s3(
    state: &AppState,
    inv_id: &str,
) -> Result<Vec<AttackNarrative>, String> {
    let s3_client = state
        .s3_client
        .as_ref()
        .ok_or_else(|| "S3 client not initialized".to_string())?;
    let bucket = &state.config.report_bucket;
    let key = format!("investigations/{inv_id}/attack_paths.json");

    let bytes = s3_client
        .get_object()
        .bucket(bucket)
        .key(&key)
        .send()
        .await
        .map_err(|e| format!("S3 GetObject failed: {e}"))?
        .body
        .collect()
        .await
        .map_err(|e| format!("S3 body read failed: {e}"))?
        .into_bytes();

    serde_json::from_slice(&bytes).map_err(|e| format!("attack_paths deserialization failed: {e}"))
}

/// Convert a `SecurityGraph` to Cytoscape.js elements format.
fn graph_to_cytoscape(graph: &SecurityGraph) -> CytoscapeElements {
    let mut elements = Vec::new();

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
    CytoscapeElements { elements, summary }
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

        match tokio::task::spawn_blocking(move || {
            if let Err(e) = store.save_investigation(&id, &name, &graph, Some(created_at), None, &status) {
                tracing::error!(investigation_id = %id, error = %e, "failed to persist investigation");
            }
            if let Err(e) = store.save_timeline(&id, &timeline) {
                tracing::error!(investigation_id = %id, error = %e, "failed to persist timeline");
            }
        })
        .await
        {
            Ok(()) => {}
            Err(e) => tracing::error!(error = %e, "persist_investigation task panicked"),
        }
    }
}
