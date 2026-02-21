use irone_aws::health_cache::HealthCacheClient;
use irone_core::catalog::DataCatalog;
use irone_core::connectors::base::{DataConnector, HealthCheckResult};

use serde::Serialize;

/// Result of a scheduled health check run.
#[derive(Debug, Serialize)]
pub struct CheckRunResult {
    pub total_sources: usize,
    pub healthy: usize,
    pub unhealthy: usize,
    pub results: Vec<HealthCheckResult>,
}

/// Scheduled health checker — runs parallel health checks and writes to `DynamoDB` cache.
pub struct ScheduledChecker {
    catalog: DataCatalog,
    health_cache: Option<HealthCacheClient>,
    sdk_config: aws_config::SdkConfig,
    use_direct_query: bool,
}

impl ScheduledChecker {
    pub fn new(
        catalog: DataCatalog,
        health_cache: Option<HealthCacheClient>,
        sdk_config: aws_config::SdkConfig,
        use_direct_query: bool,
    ) -> Self {
        Self {
            catalog,
            health_cache,
            sdk_config,
            use_direct_query,
        }
    }

    /// Run health checks for all Security Lake sources in parallel.
    pub async fn run(&self) -> CheckRunResult {
        let sources = self.catalog.filter_by_tag("security-lake");
        let total_sources = sources.len();

        if total_sources == 0 {
            return CheckRunResult {
                total_sources: 0,
                healthy: 0,
                unhealthy: 0,
                results: Vec::new(),
            };
        }

        // Parallel health checks
        let mut set = tokio::task::JoinSet::new();
        for source in sources {
            let sdk = self.sdk_config.clone();
            let src = source.clone();
            let name = source.name.clone();
            let use_direct = self.use_direct_query;
            set.spawn(async move {
                let connector = irone_aws::create_connector(src, &sdk, use_direct).await;
                let health: HealthCheckResult = match connector.check_health().await {
                    Ok(result) => result,
                    Err(e) => HealthCheckResult::new(name, false).with_error(e.to_string()),
                };
                health
            });
        }

        let mut results = Vec::with_capacity(total_sources);
        while let Some(Ok(result)) = set.join_next().await {
            results.push(result);
        }

        let healthy = results.iter().filter(|r| r.healthy).count();
        let unhealthy = results.len() - healthy;

        // Write to DynamoDB cache
        if let Some(ref cache) = self.health_cache
            && let Err(e) = cache.put_many(&results).await
        {
            tracing::warn!(err = %e, "failed to write health results to cache");
        }

        CheckRunResult {
            total_sources,
            healthy,
            unhealthy,
            results,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_run_result_serializes() {
        let result = CheckRunResult {
            total_sources: 3,
            healthy: 2,
            unhealthy: 1,
            results: vec![
                HealthCheckResult::new("cloudtrail", true),
                HealthCheckResult::new("vpc-flow", true),
                HealthCheckResult::new("route53", false).with_error("no data"),
            ],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["total_sources"], 3);
        assert_eq!(json["healthy"], 2);
    }

    #[tokio::test]
    async fn empty_catalog_returns_empty_result() {
        let catalog = DataCatalog::new();
        let sdk_config = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new("us-west-2"))
            .build();
        let checker = ScheduledChecker::new(catalog, None, sdk_config, false);
        let result = checker.run().await;
        assert_eq!(result.total_sources, 0);
        assert!(result.results.is_empty());
    }
}
