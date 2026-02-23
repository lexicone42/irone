use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::RwLock;

use irone_core::catalog::DataCatalog;
use irone_core::detections::DetectionRunner;
use irone_core::graph::{InvestigationTimeline, SecurityGraph};
use irone_persistence::store::{DetectionRunRecord, InvestigationStore};

use crate::config::WebConfig;
use crate::investigation_store::DynamoInvestigationStore;

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
    pub detection_runs: Arc<RwLock<Vec<DetectionRunRecord>>>,
    pub sdk_config: Arc<aws_config::SdkConfig>,
    /// DynamoDB-backed investigation store (active when `investigations_table` is set).
    pub dynamo_investigation_store: Option<DynamoInvestigationStore>,
    /// S3 client for investigation artifacts (active when pipeline is enabled).
    pub s3_client: Option<aws_sdk_s3::Client>,
    /// Step Functions client for starting enrichment executions.
    pub sfn_client: Option<aws_sdk_sfn::Client>,
}

/// Build application state from config.
///
/// Called once at startup and wired into the axum router.
#[allow(clippy::too_many_lines)]
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

    // Open investigation store + load persisted data (all sync, one blocking task)
    let db_path = config.investigations_db_path.clone();
    let (investigation_store, investigations, detection_runs) = if db_path.is_empty() {
        (None, HashMap::new(), Vec::new())
    } else {
        #[allow(clippy::type_complexity)]
        match tokio::task::spawn_blocking(move || -> Option<(
            Arc<InvestigationStore>,
            HashMap<String, Investigation>,
            Vec<DetectionRunRecord>,
        )> {
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
            let detection_runs = store.list_detection_runs(500, None).unwrap_or_default();
            tracing::info!(
                inv_count = investigations.len(),
                run_count = detection_runs.len(),
                "loaded persisted data"
            );
            Some((store, investigations, detection_runs))
        })
        .await
        .ok()
        .flatten()
        {
            Some((store, invs, runs)) => (Some(store), invs, runs),
            None => (None, HashMap::new(), Vec::new()),
        }
    };

    // AWS SDK config
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    // Pipeline clients (only when investigation_state_machine_arn is set)
    let pipeline_enabled = !config.investigation_state_machine_arn.is_empty();
    let dynamo_investigation_store = if config.investigations_table.is_empty() {
        None
    } else {
        Some(DynamoInvestigationStore::new(
            &sdk_config,
            config.investigations_table.clone(),
        ))
    };
    let s3_client = if pipeline_enabled {
        Some(aws_sdk_s3::Client::new(&sdk_config))
    } else {
        None
    };
    let sfn_client = if pipeline_enabled {
        Some(aws_sdk_sfn::Client::new(&sdk_config))
    } else {
        None
    };

    AppState {
        config: Arc::new(config),
        catalog: Arc::new(RwLock::new(catalog)),
        runner: Arc::new(runner),
        investigation_store,
        investigations: Arc::new(RwLock::new(investigations)),
        detection_runs: Arc::new(RwLock::new(detection_runs)),
        sdk_config: Arc::new(sdk_config),
        dynamo_investigation_store,
        s3_client,
        sfn_client,
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
        assert!(state.detection_runs.read().await.is_empty());
        assert!(state.catalog.read().await.is_empty());
        assert!(state.dynamo_investigation_store.is_none());
        assert!(state.s3_client.is_none());
        assert!(state.sfn_client.is_none());
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
