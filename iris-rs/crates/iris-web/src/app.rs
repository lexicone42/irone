use axum::Router;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::routers::{dashboard, detections, investigations, sources};
use crate::state::AppState;

/// Build the full axum router with all API routes and middleware.
pub fn build_router(state: AppState) -> Router {
    let api = Router::new()
        .merge(sources::router())
        .merge(detections::router())
        .merge(investigations::router())
        .merge(dashboard::router());

    Router::new()
        .nest("/api", api)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}
