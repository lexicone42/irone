pub mod arrow_convert;
pub mod athena;
pub mod error;
pub mod health_cache;
pub mod iceberg;
pub mod security_lake;
pub mod sns;

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use iris_core::catalog::DataSource;
use iris_core::connectors::base::{DataConnector, HealthCheckResult};
use iris_core::connectors::ocsf::{OCSFEventClass, SecurityLakeError, SecurityLakeQueries};
use iris_core::connectors::result::QueryResult;

use crate::iceberg::IcebergConnector;
use crate::security_lake::SecurityLakeConnector;

/// A Security Lake connector that dispatches to either Iceberg (direct S3 reads)
/// or Athena (SQL over Athena service).
///
/// Created via [`create_connector`] which handles the Iceberg-first + Athena-fallback logic.
pub enum ConnectorKind {
    Iceberg(Box<IcebergConnector>),
    Athena(Box<SecurityLakeConnector>),
}

/// Delegate an async method call through the `ConnectorKind` enum.
macro_rules! delegate {
    ($self:ident, $method:ident($($arg:expr),*)) => {
        match $self {
            Self::Iceberg(c) => c.$method($($arg),*).await,
            Self::Athena(c) => c.$method($($arg),*).await,
        }
    };
}

#[allow(async_fn_in_trait)]
impl DataConnector for ConnectorKind {
    async fn query(
        &self,
        sql: &str,
    ) -> Result<QueryResult, Box<dyn std::error::Error + Send + Sync>> {
        delegate!(self, query(sql))
    }

    async fn get_schema(
        &self,
    ) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>> {
        delegate!(self, get_schema())
    }

    async fn check_health(
        &self,
    ) -> Result<HealthCheckResult, Box<dyn std::error::Error + Send + Sync>> {
        delegate!(self, check_health())
    }
}

#[allow(async_fn_in_trait)]
impl SecurityLakeQueries for ConnectorKind {
    async fn query_by_event_class(
        &self,
        event_class: OCSFEventClass,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
        additional_filters: Option<&str>,
    ) -> Result<QueryResult, SecurityLakeError> {
        delegate!(
            self,
            query_by_event_class(event_class, start, end, limit, additional_filters)
        )
    }

    async fn query_authentication_events(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        status: Option<&str>,
        limit: usize,
    ) -> Result<QueryResult, SecurityLakeError> {
        delegate!(self, query_authentication_events(start, end, status, limit))
    }

    async fn query_api_activity(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        service: Option<&str>,
        operation: Option<&str>,
        limit: usize,
    ) -> Result<QueryResult, SecurityLakeError> {
        delegate!(
            self,
            query_api_activity(start, end, service, operation, limit)
        )
    }

    async fn query_network_activity(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        src_ip: Option<&str>,
        dst_ip: Option<&str>,
        dst_port: Option<u16>,
        limit: usize,
    ) -> Result<QueryResult, SecurityLakeError> {
        delegate!(
            self,
            query_network_activity(start, end, src_ip, dst_ip, dst_port, limit)
        )
    }

    async fn query_security_findings(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        severity: Option<&str>,
        limit: usize,
    ) -> Result<QueryResult, SecurityLakeError> {
        delegate!(self, query_security_findings(start, end, severity, limit))
    }

    async fn get_event_summary(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<QueryResult, SecurityLakeError> {
        delegate!(self, get_event_summary(start, end))
    }
}

/// Build a Security Lake connector based on the `use_direct_query` flag.
///
/// When `use_direct_query` is true, attempts to create an `IcebergConnector`
/// for sub-second query latency via direct S3 Parquet reads.
/// Falls back to `SecurityLakeConnector` (Athena) if Iceberg initialization fails.
pub async fn create_connector(
    source: DataSource,
    sdk_config: &aws_config::SdkConfig,
    use_direct_query: bool,
) -> ConnectorKind {
    if use_direct_query {
        match IcebergConnector::new(source.clone(), sdk_config).await {
            Ok(c) => {
                tracing::info!(source = %source.name, connector = "iceberg", "Using direct Iceberg connector");
                return ConnectorKind::Iceberg(Box::new(c));
            }
            Err(e) => {
                tracing::warn!(
                    source = %source.name,
                    err = %e,
                    "Iceberg init failed, falling back to Athena"
                );
            }
        }
    }
    tracing::info!(source = %source.name, connector = "athena", "Using Athena connector");
    ConnectorKind::Athena(Box::new(SecurityLakeConnector::from_source(
        source, sdk_config,
    )))
}
