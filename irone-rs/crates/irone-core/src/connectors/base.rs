use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::result::QueryResult;

/// Typed error for data connector operations.
///
/// Distinguishes between retriable (transient) and permanent errors so callers
/// can implement appropriate retry logic.
#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    /// Transient error — retrying may succeed (e.g., timeout, throttling).
    #[error("transient: {message}")]
    Transient {
        message: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Permanent error — retrying will not help (e.g., table not found, permission denied).
    #[error("permanent: {message}")]
    Permanent {
        message: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Query-specific error (bad SQL, invalid schema reference).
    #[error("query error: {0}")]
    Query(String),
}

impl ConnectorError {
    pub fn transient(msg: impl Into<String>) -> Self {
        Self::Transient {
            message: msg.into(),
            source: None,
        }
    }

    pub fn permanent(msg: impl Into<String>) -> Self {
        Self::Permanent {
            message: msg.into(),
            source: None,
        }
    }

    pub fn transient_with(
        msg: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Transient {
            message: msg.into(),
            source: Some(Box::new(source)),
        }
    }

    pub fn permanent_with(
        msg: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Permanent {
            message: msg.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Whether this error is transient and retrying may help.
    pub fn is_retriable(&self) -> bool {
        matches!(self, Self::Transient { .. })
    }
}

/// Convenience conversion: any boxed error becomes a permanent connector error.
impl From<Box<dyn std::error::Error + Send + Sync>> for ConnectorError {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self::Permanent {
            message: e.to_string(),
            source: Some(e),
        }
    }
}

impl From<super::sql_utils::SqlSanitizationError> for ConnectorError {
    fn from(e: super::sql_utils::SqlSanitizationError) -> Self {
        Self::Query(e.to_string())
    }
}

/// Convenience conversion: wrap any concrete error type into a `ConnectorError`.
///
/// This is the recommended way for connector implementations to convert
/// their internal error types (e.g., `AwsError`) into `ConnectorError`.
impl ConnectorError {
    pub fn from_error(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Permanent {
            message: e.to_string(),
            source: Some(Box::new(e)),
        }
    }
}

/// Result of a health check on a data source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub source_name: String,
    pub healthy: bool,
    pub last_data_time: Option<DateTime<Utc>>,
    pub record_count: i64,
    pub latency_seconds: f64,
    pub error: Option<String>,
    pub details: HashMap<String, Value>,
    pub checked_at: DateTime<Utc>,
}

impl HealthCheckResult {
    /// Create a new health check result. `checked_at` is set to now.
    pub fn new(source_name: impl Into<String>, healthy: bool) -> Self {
        Self {
            source_name: source_name.into(),
            healthy,
            last_data_time: None,
            record_count: 0,
            latency_seconds: 0.0,
            error: None,
            details: HashMap::new(),
            checked_at: Utc::now(),
        }
    }

    /// Builder: set last data time.
    #[must_use]
    pub fn with_last_data_time(mut self, t: DateTime<Utc>) -> Self {
        self.last_data_time = Some(t);
        self
    }

    /// Builder: set record count.
    #[must_use]
    pub fn with_record_count(mut self, n: i64) -> Self {
        self.record_count = n;
        self
    }

    /// Builder: set latency.
    #[must_use]
    pub fn with_latency(mut self, seconds: f64) -> Self {
        self.latency_seconds = seconds;
        self
    }

    /// Builder: set error.
    #[must_use]
    pub fn with_error(mut self, err: impl Into<String>) -> Self {
        self.error = Some(err.into());
        self
    }

    /// Age of the most recent data in minutes, if known.
    #[must_use]
    pub fn data_age_minutes(&self) -> Option<f64> {
        #[allow(clippy::cast_precision_loss)]
        self.last_data_time
            .map(|t| (Utc::now() - t).num_seconds() as f64 / 60.0)
    }
}

/// Trait for data source connectors.
///
/// Implementors provide query execution, schema introspection, and health
/// checking for a specific data source (Athena, `DuckDB`, `CloudWatch`, etc.).
///
/// This is the Rust equivalent of the Python `DataConnector` ABC.
/// Concrete implementations live in `irone-aws` (not in core).
#[allow(async_fn_in_trait)]
pub trait DataConnector: Send + Sync {
    /// Execute a SQL query and return results.
    ///
    /// # Errors
    /// Returns a [`ConnectorError`] distinguishing transient vs permanent failures.
    async fn query(&self, sql: &str) -> Result<QueryResult, ConnectorError>;

    /// Get the schema of the data source (field name → type).
    ///
    /// # Errors
    /// Returns a [`ConnectorError`] if schema introspection fails.
    async fn get_schema(&self) -> Result<HashMap<String, String>, ConnectorError>;

    /// Check if the data source is healthy and producing data.
    ///
    /// # Errors
    /// Returns a [`ConnectorError`] if the health check fails to execute.
    async fn check_health(&self) -> Result<HealthCheckResult, ConnectorError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_check_result_builder() {
        let hcr = HealthCheckResult::new("test-source", true)
            .with_record_count(42)
            .with_latency(1.5);
        assert_eq!(hcr.source_name, "test-source");
        assert!(hcr.healthy);
        assert_eq!(hcr.record_count, 42);
        assert!((hcr.latency_seconds - 1.5).abs() < f64::EPSILON);
        assert!(hcr.error.is_none());
    }

    #[test]
    fn health_check_result_with_error() {
        let hcr = HealthCheckResult::new("failing", false).with_error("connection timeout");
        assert!(!hcr.healthy);
        assert_eq!(hcr.error.as_deref(), Some("connection timeout"));
    }

    #[test]
    fn data_age_minutes_returns_none_without_last_data_time() {
        let hcr = HealthCheckResult::new("test", true);
        assert!(hcr.data_age_minutes().is_none());
    }

    #[test]
    fn data_age_minutes_computes_correctly() {
        let past = Utc::now() - chrono::Duration::minutes(30);
        let hcr = HealthCheckResult::new("test", true).with_last_data_time(past);
        let age = hcr.data_age_minutes().unwrap();
        // Should be approximately 30 minutes (allow some slack for test execution time)
        assert!(age > 29.0 && age < 31.0);
    }

    #[test]
    fn health_check_result_serializes() {
        let hcr = HealthCheckResult::new("test", true).with_record_count(5);
        let json = serde_json::to_value(&hcr).unwrap();
        assert_eq!(json["source_name"], "test");
        assert_eq!(json["healthy"], true);
        assert_eq!(json["record_count"], 5);
    }
}
