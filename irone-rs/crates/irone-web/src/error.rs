use axum::response::{IntoResponse, Response};
use http::StatusCode;
use serde_json::json;

/// Unified error type for all web endpoints.
///
/// Converts to a JSON response with `{"error": "message"}` and the appropriate HTTP status.
#[derive(Debug, thiserror::Error)]
pub enum WebError {
    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    BadRequest(String),

    #[error("{0}")]
    Internal(String),
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg.as_str()),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            Self::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.as_str()),
        };
        let body = json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}

/// Convenience conversion: any boxed error becomes an internal error.
impl From<Box<dyn std::error::Error + Send + Sync>> for WebError {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self::Internal(e.to_string())
    }
}

/// Convenience conversion: persistence errors become internal errors.
impl From<irone_persistence::error::PersistenceError> for WebError {
    fn from(e: irone_persistence::error::PersistenceError) -> Self {
        Self::Internal(format!("persistence error: {e}"))
    }
}

/// Convenience conversion: tokio join errors become internal errors.
impl From<tokio::task::JoinError> for WebError {
    fn from(e: tokio::task::JoinError) -> Self {
        Self::Internal(format!("task join error: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn extract_body(response: Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn not_found_returns_404() {
        let err = WebError::NotFound("source not found".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = extract_body(response).await;
        assert_eq!(body["error"], "source not found");
    }

    #[tokio::test]
    async fn bad_request_returns_400() {
        let err = WebError::BadRequest("missing field".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = extract_body(response).await;
        assert_eq!(body["error"], "missing field");
    }

    #[tokio::test]
    async fn internal_returns_500() {
        let err = WebError::Internal("something broke".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = extract_body(response).await;
        assert_eq!(body["error"], "something broke");
    }
}
