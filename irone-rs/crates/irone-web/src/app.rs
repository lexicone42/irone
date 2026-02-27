use axum::Router;
use axum::middleware::from_fn;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use irone_auth::bridge::AuthComponents;
use irone_auth::middleware::require_auth;

use crate::routers::{dashboard, detections, investigations, query, sources};
use crate::state::AppState;

/// Build a restrictive CORS layer from the app's configured frontend URL.
///
/// Allows the frontend origin and common local dev origins.
fn build_cors_layer(frontend_url: &str) -> CorsLayer {
    let mut origins: Vec<http::HeaderValue> = vec![
        "http://localhost:3000".parse().unwrap(),
        "http://localhost:8080".parse().unwrap(),
        "http://127.0.0.1:3000".parse().unwrap(),
    ];
    if let Ok(hv) = frontend_url.parse::<http::HeaderValue>()
        && !frontend_url.is_empty()
    {
        origins.push(hv);
    }
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            http::Method::GET,
            http::Method::POST,
            http::Method::PUT,
            http::Method::DELETE,
            http::Method::OPTIONS,
        ])
        .allow_headers([
            http::header::CONTENT_TYPE,
            http::header::AUTHORIZATION,
            http::header::HeaderName::from_static("x-service-token"),
            http::header::HeaderName::from_static("x-csrf-token"),
        ])
        .allow_credentials(true)
}

/// Build the full axum router with all API routes, auth, and middleware.
pub fn build_router(state: AppState, auth: Option<AuthComponents>) -> Router {
    let cors = build_cors_layer(&state.config.frontend_url);

    // Protected API routes (behind require_auth when auth enabled)
    let protected_api = Router::new()
        .merge(sources::router())
        .merge(detections::router())
        .merge(investigations::router())
        .merge(query::router())
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
        .layer(cors)
}
