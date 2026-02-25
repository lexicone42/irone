use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::routers::detections::DetectionRunSummary;
use crate::state::AppState;

/// Build the dashboard sub-router (auth-protected routes).
pub fn router() -> Router<AppState> {
    Router::new().route("/dashboard", get(dashboard_summary))
}

/// Public routes that bypass auth (health probe + auth config).
pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health_check))
        .route("/auth/config", get(auth_config))
}

// -- Response types --

#[derive(Debug, Serialize)]
pub struct HealthSummary {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub healthy: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unhealthy: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct DashboardSummary {
    pub source_count: usize,
    pub rule_count: usize,
    pub investigation_count: usize,
    pub region: String,
    pub version: &'static str,
    pub health: HealthSummary,
    pub recent_detections: Vec<DetectionRunSummary>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct AuthConfig {
    pub auth_enabled: bool,
    pub cognito_domain: String,
    pub cognito_client_id: String,
    /// Public client ID for browser passkey/password auth (no secret).
    pub passkey_client_id: String,
    pub cognito_region: String,
    pub redirect_uri: String,
}

// -- Handlers --

/// `GET /api/dashboard` — summary counts + health overview.
async fn dashboard_summary(State(state): State<AppState>) -> Json<DashboardSummary> {
    let source_count = state.catalog.read().await.len();
    let rule_count = state.runner.list_rules(true).len();
    let investigation_count = state.investigations.read().await.len();

    // Health summary from DynamoDB cache (if available)
    let health = if state.config.health_cache_table.is_empty() {
        HealthSummary {
            available: false,
            total: None,
            healthy: None,
            unhealthy: None,
        }
    } else {
        let cache = irone_aws::health_cache::HealthCacheClient::new(
            &state.sdk_config,
            state.config.health_cache_table.clone(),
        );
        match cache.get_all_latest().await {
            Ok(results) => {
                let total = results.len();
                let healthy = results.iter().filter(|r| r.healthy).count();
                HealthSummary {
                    available: true,
                    total: Some(total),
                    healthy: Some(healthy),
                    unhealthy: Some(total - healthy),
                }
            }
            Err(_) => HealthSummary {
                available: false,
                total: None,
                healthy: None,
                unhealthy: None,
            },
        }
    };

    // Recent detection runs (last 10 from in-memory cache)
    let recent_detections: Vec<DetectionRunSummary> = state
        .detection_runs
        .read()
        .await
        .iter()
        .take(10)
        .map(DetectionRunSummary::from)
        .collect();

    Json(DashboardSummary {
        source_count,
        rule_count,
        investigation_count,
        region: state.config.region.clone(),
        health,
        version: env!("CARGO_PKG_VERSION"),
        recent_detections,
    })
}

/// `GET /api/health` — liveness probe.
async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// `GET /api/auth/config` — public auth configuration for the frontend.
///
/// Returns Cognito client details so the static frontend can initiate
/// the OIDC flow without hardcoding secrets.
async fn auth_config(State(state): State<AppState>) -> Json<AuthConfig> {
    Json(AuthConfig {
        auth_enabled: state.config.auth_enabled,
        cognito_domain: state.config.cognito_domain.clone(),
        cognito_client_id: state.config.cognito_client_id.clone(),
        passkey_client_id: state.config.cognito_passkey_client_id.clone(),
        cognito_region: state.config.cognito_region.clone(),
        redirect_uri: state.config.cognito_redirect_uri.clone(),
    })
}
