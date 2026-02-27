use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use irone_core::connectors::base::DataConnector;

use crate::error::WebError;
use crate::state::AppState;

/// Destructive SQL keywords that ad-hoc queries must never contain.
const DESTRUCTIVE_KEYWORDS: &[&str] = &[
    "DROP", "DELETE", "INSERT", "UPDATE", "TRUNCATE", "ALTER", "CREATE", "REPLACE", "MERGE",
];

/// Build the query sub-router.
pub fn router() -> Router<AppState> {
    Router::new().route("/query", post(run_query))
}

#[derive(Debug, Deserialize)]
pub struct QueryRequest {
    pub sql: String,
    /// If omitted, uses the first Security Lake source.
    pub source_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct QueryResponse {
    pub columns: Vec<String>,
    pub rows: Vec<serde_json::Map<String, serde_json::Value>>,
    pub row_count: usize,
}

/// `POST /api/query` — execute arbitrary SQL against a data source.
async fn run_query(
    State(state): State<AppState>,
    Json(body): Json<QueryRequest>,
) -> Result<Json<QueryResponse>, WebError> {
    let sql = body.sql.trim();
    if sql.is_empty() {
        return Err(WebError::BadRequest("sql must not be empty".into()));
    }

    // Reject destructive SQL keywords (case-insensitive word-boundary check)
    let sql_upper = sql.to_uppercase();
    for keyword in DESTRUCTIVE_KEYWORDS {
        // Check for keyword as a standalone word (preceded by start/whitespace/semicolon)
        if sql_upper
            .split_ascii_whitespace()
            .any(|word| word.trim_start_matches('(') == *keyword)
        {
            return Err(WebError::BadRequest(format!(
                "destructive SQL keyword '{keyword}' is not allowed in ad-hoc queries"
            )));
        }
    }

    // Resolve source
    let catalog = state.catalog.read().await;
    let source = if let Some(ref name) = body.source_name {
        catalog
            .get_source(name)
            .cloned()
            .ok_or_else(|| WebError::NotFound(format!("source '{name}' not found")))?
    } else {
        catalog
            .filter_by_tag("security-lake")
            .into_iter()
            .next()
            .cloned()
            .ok_or_else(|| WebError::BadRequest("no Security Lake source configured".into()))?
    };
    drop(catalog);

    let connector =
        irone_aws::create_connector(source, &state.sdk_config, state.config.use_direct_query).await;

    let result = connector
        .query(sql)
        .await
        .map_err(|e| WebError::Internal(format!("query error: {e}")))?;

    let row_count = result.len();
    Ok(Json(QueryResponse {
        columns: result.columns().to_vec(),
        rows: result.rows().to_vec(),
        row_count,
    }))
}
