use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::RwLock;

use irone_core::catalog::DataCatalog;
use irone_core::detections::DetectionRunner;
use irone_core::graph::{InvestigationTimeline, SecurityGraph};
use irone_persistence::store::InvestigationStore;

use crate::config::WebConfig;

/// A single in-memory investigation.
#[derive(Debug, Clone, Serialize)]
pub struct Investigation {
    pub id: String,
    pub name: String,
    pub graph: SecurityGraph,
    pub timeline: InvestigationTimeline,
    pub created_at: DateTime<Utc>,
    pub status: String,
}

/// Shared application state, wired into axum via `State<AppState>`.
///
/// All fields are `Arc`-wrapped so cloning is cheap — axum clones state per request.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<WebConfig>,
    pub catalog: Arc<RwLock<DataCatalog>>,
    pub runner: Arc<DetectionRunner>,
    pub investigation_store: Option<Arc<InvestigationStore>>,
    pub investigations: Arc<RwLock<HashMap<String, Investigation>>>,
    pub sdk_config: Arc<aws_config::SdkConfig>,
}

/// Build application state from config.
///
/// Called once at startup and wired into the axum router.
pub async fn create_app_state(config: WebConfig) -> AppState {
    let mut catalog = DataCatalog::new();

    // Load catalog from YAML if configured
    if !config.catalog_path.is_empty() {
        let path = Path::new(&config.catalog_path);
        if path.exists() {
            match catalog.load_from_yaml(path) {
                Ok(n) => tracing::info!(count = n, path = %config.catalog_path, "loaded catalog"),
                Err(e) => tracing::warn!(err = %e, "failed to load catalog"),
            }
        }
    }

    // Auto-register Security Lake sources
    if !config.security_lake_db.is_empty() {
        catalog.register_security_lake_sources(&config.security_lake_db, &config.region);
        tracing::info!(db = %config.security_lake_db, "registered Security Lake sources");
    }

    // Load detection rules
    let mut runner = DetectionRunner::new();
    if !config.rules_dir.is_empty() {
        let path = Path::new(&config.rules_dir);
        if path.is_dir() {
            let count = runner.load_rules_from_directory(path);
            tracing::info!(count, path = %config.rules_dir, "loaded detection rules");
        }
    }

    // Open investigation store + load persisted investigations (all sync, one blocking task)
    let db_path = config.investigations_db_path.clone();
    let (investigation_store, investigations) = if db_path.is_empty() {
        (None, HashMap::new())
    } else {
        match tokio::task::spawn_blocking(
            move || -> Option<(Arc<InvestigationStore>, HashMap<String, Investigation>)> {
                let store = match InvestigationStore::open(Path::new(&db_path)) {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        tracing::error!(err = %e, "failed to open investigation store");
                        return None;
                    }
                };
                let mut investigations = HashMap::new();
                if let Ok(summaries) = store.list_investigations() {
                    for summary in summaries {
                        if let Ok(Some(loaded)) = store.load_investigation(&summary.id) {
                            let timeline = store
                                .load_timeline(&summary.id)
                                .ok()
                                .flatten()
                                .unwrap_or_else(|| InvestigationTimeline::new(&summary.id));
                            investigations.insert(
                                summary.id.clone(),
                                Investigation {
                                    id: summary.id,
                                    name: loaded.name,
                                    graph: loaded.graph,
                                    timeline,
                                    created_at: loaded.created_at,
                                    status: loaded.status,
                                },
                            );
                        }
                    }
                }
                tracing::info!(
                    count = investigations.len(),
                    "loaded persisted investigations"
                );
                Some((store, investigations))
            },
        )
        .await
        .ok()
        .flatten()
        {
            Some((store, invs)) => (Some(store), invs),
            None => (None, HashMap::new()),
        }
    };

    // AWS SDK config
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    AppState {
        config: Arc::new(config),
        catalog: Arc::new(RwLock::new(catalog)),
        runner: Arc::new(runner),
        investigation_store,
        investigations: Arc::new(RwLock::new(investigations)),
        sdk_config: Arc::new(sdk_config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn investigation_struct_serializes() {
        let inv = Investigation {
            id: "inv-1".into(),
            name: "Test".into(),
            graph: SecurityGraph::new(),
            timeline: InvestigationTimeline::new("inv-1"),
            created_at: Utc::now(),
            status: "active".into(),
        };
        let json = serde_json::to_value(&inv).unwrap();
        assert_eq!(json["id"], "inv-1");
        assert_eq!(json["name"], "Test");
    }

    #[tokio::test]
    async fn create_app_state_with_defaults() {
        let config = WebConfig::default();
        let state = create_app_state(config).await;
        assert!(state.investigation_store.is_none());
        assert!(state.investigations.read().await.is_empty());
        assert!(state.catalog.read().await.is_empty());
    }

    #[tokio::test]
    async fn create_app_state_registers_security_lake() {
        let config = WebConfig {
            security_lake_db: "my_sl_db".into(),
            ..WebConfig::default()
        };
        let state = create_app_state(config).await;
        assert_eq!(state.catalog.read().await.len(), 5);
    }
}
