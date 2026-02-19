use iris_aws::health_cache::HealthCacheClient;
use iris_core::catalog::DataCatalog;
use iris_health_checker::checker::ScheduledChecker;
use lambda_runtime::{Error, LambdaEvent, service_fn};

async fn handler(_event: LambdaEvent<serde_json::Value>) -> Result<serde_json::Value, Error> {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    // Build catalog with Security Lake sources
    let security_lake_db = std::env::var("SECDASH_SECURITY_LAKE_DB").unwrap_or_default();
    let region = std::env::var("SECDASH_REGION").unwrap_or_else(|_| "us-west-2".into());

    let mut catalog = DataCatalog::new();
    if !security_lake_db.is_empty() {
        catalog.register_security_lake_sources(&security_lake_db, &region);
    }

    // Build health cache client
    let cache_table = std::env::var("SECDASH_HEALTH_CACHE_TABLE").unwrap_or_default();
    let health_cache = if cache_table.is_empty() {
        None
    } else {
        Some(HealthCacheClient::new(&sdk_config, cache_table))
    };

    let use_direct_query = std::env::var("SECDASH_USE_DIRECT_QUERY")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    let checker = ScheduledChecker::new(catalog, health_cache, sdk_config, use_direct_query);
    let result = checker.run().await;

    tracing::info!(
        total = result.total_sources,
        healthy = result.healthy,
        unhealthy = result.unhealthy,
        "health check complete"
    );

    Ok(serde_json::to_value(&result)?)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt().json().with_target(false).init();

    lambda_runtime::run(service_fn(handler)).await
}
