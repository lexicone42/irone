use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use iris_core::detections::DetectionResult;

use crate::error::WebError;
use crate::state::AppState;

/// Build the detections sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/rules", get(list_rules))
        .route("/rules/{rule_id}", get(get_rule))
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
    pub source_name: String,
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
    pub severity: String,
    pub enabled: bool,
    pub tags: Vec<String>,
    pub mitre_attack: Vec<String>,
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
                severity: meta.severity.to_string(),
                enabled: meta.enabled,
                tags: meta.tags.clone(),
                mitre_attack: meta.mitre_attack.clone(),
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

/// `POST /api/detections/{rule_id}/run` — execute a detection rule.
async fn run_detection(
    State(state): State<AppState>,
    Path(rule_id): Path<String>,
    Json(body): Json<RunDetectionRequest>,
) -> Result<Json<DetectionResponse>, WebError> {
    // Check rule exists before building a connector
    if state.runner.get_rule(&rule_id).is_none() {
        return Err(WebError::NotFound(format!("rule '{rule_id}' not found")));
    }

    // Resolve source
    let catalog = state.catalog.read().await;
    let source = catalog
        .get_source(&body.source_name)
        .cloned()
        .ok_or_else(|| WebError::NotFound(format!("source '{}' not found", body.source_name)))?;
    drop(catalog);

    // Build connector and run detection
    let connector =
        iris_aws::create_connector(source, &state.sdk_config, state.config.use_direct_query).await;
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

    Ok(Json(result.into()))
}
