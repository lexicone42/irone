//! Auth middleware for protecting API routes.
//!
//! When auth is enabled, the session middleware (from l42-token-handler) handles
//! cookie-based sessions on `/auth/*` routes. This module provides a lighter
//! guard for `/api/*` routes that checks whether the session has valid tokens.
//!
//! A service token (`X-Service-Token` header) can bypass session auth for
//! headless/programmatic API access (CI, scripts, testing).

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use http::StatusCode;
use l42_token_handler::session::middleware::SessionHandle;

/// The expected service token, set once at startup.
static SERVICE_TOKEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Initialize the service token. Call once at app startup.
pub fn set_service_token(token: String) {
    if !token.is_empty() {
        let _ = SERVICE_TOKEN.set(token);
    }
}

/// Guard middleware for API routes.
///
/// Checks (in order):
/// 1. `X-Service-Token` header matches configured service token → allow
/// 2. Session has valid tokens → allow
/// 3. No session middleware (auth not enabled) → allow
/// 4. Otherwise → 401
pub async fn require_auth(request: Request, next: Next) -> Result<Response, StatusCode> {
    // Check service token header first
    if let Some(configured) = SERVICE_TOKEN.get()
        && let Some(provided) = request.headers().get("x-service-token")
        && provided.as_bytes() == configured.as_bytes()
    {
        return Ok(next.run(request).await);
    }

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
