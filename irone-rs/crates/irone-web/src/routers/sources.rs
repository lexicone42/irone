use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use irone_aws::health_cache::HealthCacheClient;
use irone_core::catalog::DataSource;
use irone_core::connectors::base::{DataConnector, HealthCheckResult};

use crate::error::WebError;
use crate::state::AppState;

/// Build the sources sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/sources", get(list_sources))
        .route("/sources/health", get(all_sources_health))
        .route("/sources/{name}/health", get(source_health))
        .route("/sources/{name}/health/history", get(source_health_history))
        .route("/sources/refresh", post(refresh_health))
}

// -- Query params --

#[derive(Debug, Deserialize)]
pub struct SourcesFilter {
    pub tag: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HealthQuery {
    /// If `true`, bypass `DynamoDB` cache and run live checks.
    #[serde(default)]
    pub live: bool,
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    #[serde(default = "default_history_limit")]
    pub limit: i32,
}

const fn default_history_limit() -> i32 {
    24
}

// -- Response types --

#[derive(Debug, Serialize)]
pub struct SourceSummary {
    pub name: String,
    pub source_type: String,
    pub description: String,
    pub region: String,
    pub tags: Vec<String>,
}

impl From<&DataSource> for SourceSummary {
    fn from(s: &DataSource) -> Self {
        Self {
            name: s.name.clone(),
            source_type: s.source_type.to_string(),
            description: s.description.clone(),
            region: s.region.clone(),
            tags: s.tags.clone(),
        }
    }
}

// -- Handlers --

/// `GET /api/sources` — list all sources, optional `?tag=` filter.
async fn list_sources(
    State(state): State<AppState>,
    Query(filter): Query<SourcesFilter>,
) -> Json<Vec<SourceSummary>> {
    let catalog = state.catalog.read().await;
    let sources: Vec<SourceSummary> = if let Some(ref tag) = filter.tag {
        catalog
            .filter_by_tag(tag)
            .into_iter()
            .map(Into::into)
            .collect()
    } else {
        catalog.list_sources().into_iter().map(Into::into).collect()
    };
    Json(sources)
}

/// `GET /api/sources/health` — health for all sources.
///
/// Reads from `DynamoDB` cache by default; `?live=true` bypasses cache.
async fn all_sources_health(
    State(state): State<AppState>,
    Query(query): Query<HealthQuery>,
) -> Result<Json<Vec<HealthCheckResult>>, WebError> {
    let catalog = state.catalog.read().await;
    let sources: Vec<DataSource> = catalog.list_sources().into_iter().cloned().collect();
    drop(catalog);

    // Cache-first: read from DynamoDB unless ?live=true
    if !query.live {
        if let Some(cache) = build_health_cache(&state) {
            match cache.get_all_latest().await {
                Ok(cached) => {
                    let results: Vec<HealthCheckResult> = cached
                        .into_iter()
                        .map(|c| {
                            HealthCheckResult::new(&c.source_name, c.healthy)
                                .with_record_count(c.record_count)
                                .with_latency(c.latency_seconds)
                        })
                        .collect();
                    return Ok(Json(results));
                }
                Err(e) => {
                    tracing::warn!(err = %e, "failed to read health cache");
                }
            }
        }
        // No cache configured or cache read failed — return empty rather than
        // running live checks (which can exceed API Gateway's 29s timeout).
        return Ok(Json(Vec::new()));
    }

    // ?live=true: run live queries (may be slow)
    let results =
        run_live_health_checks(&sources, &state.sdk_config, state.config.use_direct_query).await;
    Ok(Json(results))
}

/// `GET /api/sources/{name}/health` — health for a single source.
async fn source_health(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<HealthCheckResult>, WebError> {
    let catalog = state.catalog.read().await;
    let source = catalog
        .get_source(&name)
        .cloned()
        .ok_or_else(|| WebError::NotFound(format!("source '{name}' not found")))?;
    drop(catalog);

    // Try cache first
    if let Some(cache) = build_health_cache(&state)
        && let Ok(Some(cached)) = cache.get_latest(&name).await
    {
        return Ok(Json(
            HealthCheckResult::new(&cached.source_name, cached.healthy)
                .with_record_count(cached.record_count)
                .with_latency(cached.latency_seconds),
        ));
    }

    // Live check
    let connector =
        irone_aws::create_connector(source, &state.sdk_config, state.config.use_direct_query).await;
    let result = connector.check_health().await.map_err(WebError::from)?;
    Ok(Json(result))
}

/// `GET /api/sources/{name}/health/history` — historical health checks.
async fn source_health_history(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<Vec<serde_json::Value>>, WebError> {
    let cache = build_health_cache(&state)
        .ok_or_else(|| WebError::BadRequest("health cache not configured".into()))?;

    let history = cache
        .get_history(&name, query.limit)
        .await
        .map_err(|e| WebError::Internal(e.to_string()))?;

    let values: Vec<serde_json::Value> = history
        .into_iter()
        .map(|c| serde_json::to_value(c).unwrap_or_default())
        .collect();
    Ok(Json(values))
}

/// `POST /api/sources/refresh` — live-check all sources, write-through to cache.
async fn refresh_health(
    State(state): State<AppState>,
) -> Result<Json<Vec<HealthCheckResult>>, WebError> {
    let catalog = state.catalog.read().await;
    let sources: Vec<DataSource> = catalog.list_sources().into_iter().cloned().collect();
    drop(catalog);

    let results =
        run_live_health_checks(&sources, &state.sdk_config, state.config.use_direct_query).await;

    // Write-through to DynamoDB cache
    if let Some(cache) = build_health_cache(&state)
        && let Err(e) = cache.put_many(&results).await
    {
        tracing::warn!(err = %e, "failed to write health results to cache");
    }

    Ok(Json(results))
}

// -- Helpers --

fn build_health_cache(state: &AppState) -> Option<HealthCacheClient> {
    let table = &state.config.health_cache_table;
    if table.is_empty() {
        return None;
    }
    Some(HealthCacheClient::new(&state.sdk_config, table.clone()))
}

/// Run live health checks for all sources in parallel via `JoinSet`.
async fn run_live_health_checks(
    sources: &[DataSource],
    sdk_config: &aws_config::SdkConfig,
    use_direct_query: bool,
) -> Vec<HealthCheckResult> {
    let mut set = tokio::task::JoinSet::new();
    for source in sources {
        let sdk = sdk_config.clone();
        let src = source.clone();
        let name = source.name.clone();
        set.spawn(async move {
            let connector = irone_aws::create_connector(src, &sdk, use_direct_query).await;
            match connector.check_health().await {
                Ok(result) => result,
                Err(e) => HealthCheckResult::new(name, false).with_error(e.to_string()),
            }
        });
    }
    let mut results = Vec::with_capacity(sources.len());
    while let Some(Ok(result)) = set.join_next().await {
        results.push(result);
    }
    results
}
