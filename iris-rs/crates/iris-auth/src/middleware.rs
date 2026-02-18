//! Auth middleware for protecting API routes.
//!
//! When auth is enabled, the session middleware (from l42-token-handler) handles
//! cookie-based sessions on `/auth/*` routes. This module provides a lighter
//! guard for `/api/*` routes that checks whether the session has valid tokens.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use http::StatusCode;
use l42_token_handler::session::middleware::SessionHandle;

/// Guard middleware for API routes.
///
/// Checks that the request has a session with tokens (set by the session middleware).
/// Returns 401 if no valid session exists.
pub async fn require_auth(request: Request, next: Next) -> Result<Response, StatusCode> {
    let session = request.extensions().get::<SessionHandle>().cloned();

    match session {
        Some(handle) => {
            let data = handle.data.lock().await;
            if data.get("tokens").is_some() {
                drop(data);
                Ok(next.run(request).await)
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        // No session middleware = auth not enabled, pass through
        None => Ok(next.run(request).await),
    }
}

/// No-op auth middleware — passes all requests through.
///
/// Used when `auth_enabled = false`.
pub async fn auth_passthrough(request: Request, next: Next) -> Response {
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::middleware;
    use axum::routing::get;
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn passthrough_allows_all_requests() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(auth_passthrough));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn require_auth_passes_without_session_middleware() {
        // When there's no SessionHandle in extensions (auth not enabled),
        // the guard passes through.
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(require_auth));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
