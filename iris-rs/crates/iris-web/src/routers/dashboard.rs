use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::state::AppState;

/// Build the dashboard sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/dashboard", get(dashboard_summary))
        .route("/health", get(health_check))
}

// -- Response types --

#[derive(Debug, Serialize)]
pub struct DashboardSummary {
    pub sources_count: usize,
    pub rules_count: usize,
    pub investigations_count: usize,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

// -- Handlers --

/// `GET /api/dashboard` — summary counts.
async fn dashboard_summary(State(state): State<AppState>) -> Json<DashboardSummary> {
    let sources_count = state.catalog.read().await.len();
    let rules_count = state.runner.list_rules(true).len();
    let investigations_count = state.investigations.read().await.len();

    Json(DashboardSummary {
        sources_count,
        rules_count,
        investigations_count,
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// `GET /api/health` — liveness probe.
async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}
