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
    // Protected API routes (behind require_auth when auth enabled)
    let protected_api = Router::new()
        .merge(sources::router())
        .merge(detections::router())
        .merge(investigations::router())
        .merge(dashboard::router());

    let protected_api = if auth.is_some() {
        protected_api.layer(from_fn(require_auth))
    } else {
        protected_api
    };

    // Public API routes (health probe, auth config) — no auth guard
    let public_api = dashboard::public_router();

    let mut app = Router::new()
        .nest("/api", protected_api)
        .nest("/api", public_api)
        .with_state(state);

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
