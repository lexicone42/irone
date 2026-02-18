use axum::Router;
use axum::middleware::from_fn;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use iris_auth::bridge::AuthComponents;
use iris_auth::middleware::require_auth;

use crate::routers::{dashboard, detections, investigations, sources};
use crate::state::AppState;

/// Build the full axum router with all API routes, auth, and middleware.
pub fn build_router(state: AppState, auth: Option<AuthComponents>) -> Router {
    let api = Router::new()
        .merge(sources::router())
        .merge(detections::router())
        .merge(investigations::router())
        .merge(dashboard::router());

    // When auth is enabled, protect API routes with require_auth guard
    let api = if auth.is_some() {
        api.layer(from_fn(require_auth))
    } else {
        api
    };

    let mut app = Router::new().nest("/api", api).with_state(state);

    // Merge auth routes (already Router<()> with state bound)
    if let Some(auth_components) = auth {
        // Apply session middleware to entire app (covers /auth/* and /api/*)
        let session_layer = auth_components.state.session_layer.clone();
        app = app
            .merge(auth_components.routes)
            .layer(from_fn(move |req, next| {
                let layer = session_layer.clone();
                l42_token_handler::session::middleware::session_middleware(layer, req, next)
            }));
    }

    app.layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
}
