use axum::{extract::Request, middleware::Next, response::Response};

/// No-op auth middleware — passes all requests through.
///
/// Real implementation will come from `l42-cognito-passkey` and will:
/// - Validate session cookies / bearer tokens
/// - Extract `AuthenticatedUser` into request extensions
/// - Redirect unauthenticated requests to login
pub async fn auth_middleware(request: Request, next: Next) -> Response {
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::middleware;
    use axum::routing::get;
    use http::StatusCode;
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn passthrough_allows_all_requests() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(auth_middleware));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
