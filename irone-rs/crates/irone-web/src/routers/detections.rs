use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use irone_core::detections::DetectionResult;
use irone_persistence::store::DetectionRunRecord;

use crate::error::WebError;
use crate::state::AppState;

/// Build the detections sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/rules", get(list_rules))
        .route("/rules/{rule_id}", get(get_rule))
        .route("/detections/history", get(detection_history))
        .route("/detections/{rule_id}/run", post(run_detection))
}

// -- Query params --

#[derive(Debug, Deserialize)]
pub struct RulesFilter {
    #[serde(default = "default_true")]
    pub enabled_only: bool,
}

const fn default_true() -> bool {
    true
}

// -- Request / Response types --

#[derive(Debug, Deserialize)]
pub struct RunDetectionRequest {
    /// If omitted, uses the first Security Lake source from the catalog.
    pub source_name: Option<String>,
    #[serde(default = "default_lookback")]
    pub lookback_minutes: i64,
}

const fn default_lookback() -> i64 {
    60
}

#[derive(Debug, Serialize)]
pub struct RuleSummary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub author: String,
    pub severity: String,
    pub enabled: bool,
    pub tags: Vec<String>,
    pub mitre_attack: Vec<String>,
    pub references: Vec<String>,
    pub data_sources: Vec<String>,
    pub schedule: String,
    pub event_class: Option<String>,
    pub threshold: usize,
    pub filter_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct HistoryFilter {
    #[serde(default = "default_history_limit")]
    pub limit: usize,
    pub rule_id: Option<String>,
}

const fn default_history_limit() -> usize {
    50
}

/// Detection run summary for history API responses.
#[derive(Debug, Clone, Serialize)]
pub struct DetectionRunSummary {
    pub run_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub triggered: bool,
    pub severity: String,
    pub match_count: usize,
    pub execution_time_ms: f64,
    pub executed_at: String,
    pub error: Option<String>,
    pub source_name: Option<String>,
    pub lookback_minutes: i64,
}

impl From<&DetectionRunRecord> for DetectionRunSummary {
    fn from(r: &DetectionRunRecord) -> Self {
        Self {
            run_id: r.run_id.clone(),
            rule_id: r.rule_id.clone(),
            rule_name: r.rule_name.clone(),
            triggered: r.triggered,
            severity: r.severity.clone(),
            match_count: r.match_count,
            execution_time_ms: r.execution_time_ms,
            executed_at: r.executed_at.to_rfc3339(),
            error: r.error.clone(),
            source_name: r.source_name.clone(),
            lookback_minutes: r.lookback_minutes,
        }
    }
}

/// Capped detection result for API responses (max 20 matches).
#[derive(Debug, Serialize)]
pub struct DetectionResponse {
    pub rule_id: String,
    pub rule_name: String,
    pub triggered: bool,
    pub severity: String,
    pub match_count: usize,
    pub matches: Vec<serde_json::Map<String, serde_json::Value>>,
    pub message: String,
    pub executed_at: String,
    pub execution_time_ms: f64,
    pub error: Option<String>,
}

impl From<DetectionResult> for DetectionResponse {
    fn from(r: DetectionResult) -> Self {
        Self {
            rule_id: r.rule_id,
            rule_name: r.rule_name,
            triggered: r.triggered,
            severity: r.severity.to_string(),
            match_count: r.match_count,
            matches: r.matches.into_iter().take(20).collect(),
            message: r.message,
            executed_at: r.executed_at.to_rfc3339(),
            execution_time_ms: r.execution_time_ms,
            error: r.error,
        }
    }
}

// -- Handlers --

/// `GET /api/rules` — list detection rules.
async fn list_rules(
    State(state): State<AppState>,
    Query(filter): Query<RulesFilter>,
) -> Json<Vec<RuleSummary>> {
    let rules = state.runner.list_rules(filter.enabled_only);
    let summaries: Vec<RuleSummary> = rules
        .into_iter()
        .map(|r| {
            let meta = r.metadata();
            RuleSummary {
                id: meta.id.clone(),
                name: meta.name.clone(),
                description: meta.description.clone(),
                author: meta.author.clone(),
                severity: meta.severity.to_string(),
                enabled: meta.enabled,
                tags: meta.tags.clone(),
                mitre_attack: meta.mitre_attack.clone(),
                references: meta.references.clone(),
                data_sources: meta.data_sources.clone(),
                schedule: meta.schedule.clone(),
                event_class: r.event_class_name().map(String::from),
                threshold: r.threshold(),
                filter_count: r.filters().len(),
            }
        })
        .collect();
    Json(summaries)
}

/// `GET /api/rules/{rule_id}` — get a single rule.
async fn get_rule(
    State(state): State<AppState>,
    Path(rule_id): Path<String>,
) -> Result<Json<serde_json::Value>, WebError> {
    let rule = state
        .runner
        .get_rule(&rule_id)
        .ok_or_else(|| WebError::NotFound(format!("rule '{rule_id}' not found")))?;
    Ok(Json(serde_json::Value::Object(rule.to_dict())))
}

/// `GET /api/detections/history` — list recent detection runs.
async fn detection_history(
    State(state): State<AppState>,
    Query(filter): Query<HistoryFilter>,
) -> Json<Vec<DetectionRunSummary>> {
    let runs = state.detection_runs.read().await;
    let limit = filter.limit.min(500);
    let summaries: Vec<DetectionRunSummary> = runs
        .iter()
        .filter(|r| filter.rule_id.as_ref().is_none_or(|id| r.rule_id == *id))
        .take(limit)
        .map(DetectionRunSummary::from)
        .collect();
    Json(summaries)
}

/// `POST /api/detections/{rule_id}/run` — execute a detection rule.
async fn run_detection(
    State(state): State<AppState>,
    Path(rule_id): Path<String>,
    Json(body): Json<RunDetectionRequest>,
) -> Result<Json<DetectionResponse>, WebError> {
    // Check rule exists before building a connector
    let rule = state
        .runner
        .get_rule(&rule_id)
        .ok_or_else(|| WebError::NotFound(format!("rule '{rule_id}' not found")))?;
    let rule_data_sources = rule.metadata().data_sources.clone();

    // Resolve source: explicit name, rule's preferred data_source, or first SL source
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
    let source_name = source.name.clone();
    drop(catalog);

    // Build connector and run detection
    let connector =
        irone_aws::create_connector(source, &state.sdk_config, state.config.use_direct_query).await;
    let result = state
        .runner
        .run_rule(
            &rule_id,
            &connector,
            None,
            Some(Utc::now()),
            body.lookback_minutes,
        )
        .await;

    // Persist detection run record (fire-and-forget)
    let record = DetectionRunRecord {
        run_id: Uuid::new_v4().to_string(),
        rule_id: result.rule_id.clone(),
        rule_name: result.rule_name.clone(),
        triggered: result.triggered,
        severity: result.severity.to_string(),
        match_count: result.match_count,
        execution_time_ms: result.execution_time_ms,
        executed_at: result.executed_at,
        error: result.error.clone(),
        source_name: Some(source_name),
        lookback_minutes: body.lookback_minutes,
    };

    // Insert into in-memory cache (newest first, cap at 500)
    {
        let mut runs = state.detection_runs.write().await;
        runs.insert(0, record.clone());
        runs.truncate(500);
    }

    // Persist to redb (fire-and-forget, same pattern as investigations)
    if let Some(store) = state.investigation_store.clone() {
        let record_clone = record;
        tokio::task::spawn_blocking(move || {
            if let Err(e) = store.save_detection_run(&record_clone) {
                tracing::warn!(err = %e, "failed to persist detection run");
            }
        });
    }

    Ok(Json(result.into()))
}
