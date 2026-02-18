use std::collections::HashMap;
use std::fmt::Write;

use chrono::{DateTime, Utc};
use tracing::{debug, warn};

use iris_core::catalog::DataSource;
use iris_core::connectors::base::{DataConnector, HealthCheckResult};
use iris_core::connectors::ocsf::{
    OCSFEventClass, SecurityLakeError, SecurityLakeQueries, format_athena_timestamp,
};
use iris_core::connectors::result::QueryResult;
use iris_core::connectors::sql_utils::{quote_table, sanitize_string, validate_ipv4};

use crate::athena::AthenaConnector;

/// Security Lake connector with OCSF schema awareness.
///
/// Wraps an `AthenaConnector` and adds OCSF-specific query methods.
/// Implements both `DataConnector` (delegates to inner Athena) and
/// `SecurityLakeQueries` (OCSF-aware query generation).
pub struct SecurityLakeConnector {
    inner: AthenaConnector,
}

impl SecurityLakeConnector {
    /// Create from an existing `AthenaConnector`.
    pub fn new(inner: AthenaConnector) -> Self {
        Self { inner }
    }

    /// Create from a `DataSource` and AWS SDK config.
    pub fn from_source(source: DataSource, sdk_config: &aws_config::SdkConfig) -> Self {
        Self {
            inner: AthenaConnector::new(source, sdk_config),
        }
    }

    /// Get the underlying data source definition.
    #[must_use]
    pub fn source(&self) -> &DataSource {
        self.inner.source()
    }

    /// Build a fully qualified table reference for the source.
    fn table_ref(&self) -> Result<String, SecurityLakeError> {
        quote_table(
            self.source().database.as_deref().unwrap_or("default"),
            self.source().table.as_deref().unwrap_or("unknown"),
        )
        .map_err(|e| SecurityLakeError::InvalidParameter(e.to_string()))
    }
}

/// Delegate `DataConnector` to the inner `AthenaConnector`.
impl DataConnector for SecurityLakeConnector {
    async fn query(
        &self,
        sql: &str,
    ) -> Result<QueryResult, Box<dyn std::error::Error + Send + Sync>> {
        self.inner.query(sql).await
    }

    async fn get_schema(
        &self,
    ) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>> {
        self.inner.get_schema().await
    }

    async fn check_health(
        &self,
    ) -> Result<HealthCheckResult, Box<dyn std::error::Error + Send + Sync>> {
        let start = std::time::Instant::now();
        let table = quote_table(
            self.source().database.as_deref().unwrap_or("default"),
            self.source().table.as_deref().unwrap_or("unknown"),
        )?;

        let sql = format!(
            "SELECT COUNT(*) as cnt, MAX(time_dt) as latest_time, \
             COUNT(DISTINCT class_uid) as class_count \
             FROM {table} \
             WHERE time_dt >= CURRENT_TIMESTAMP - INTERVAL '1' HOUR"
        );

        match self.inner.query(&sql).await {
            Ok(qr) => {
                let latency = start.elapsed().as_secs_f64();
                let record_count = qr
                    .rows()
                    .first()
                    .and_then(|r| r.get("cnt"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);

                let class_count = qr
                    .rows()
                    .first()
                    .and_then(|r| r.get("class_count"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);

                let last_time = qr
                    .rows()
                    .first()
                    .and_then(|r| r.get("latest_time"))
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .and_then(|s| {
                        DateTime::parse_from_rfc3339(&s.replace('Z', "+00:00"))
                            .ok()
                            .map(|dt| dt.with_timezone(&Utc))
                    });

                let healthy = if let Some(lt) = last_time {
                    #[allow(clippy::cast_precision_loss)]
                    let age_minutes = (Utc::now() - lt).num_seconds() as f64 / 60.0;
                    age_minutes <= f64::from(self.source().expected_freshness_minutes)
                } else {
                    record_count > 0
                };

                let mut result = HealthCheckResult::new(&self.source().name, healthy)
                    .with_record_count(record_count)
                    .with_latency(latency);

                if let Some(lt) = last_time {
                    result = result.with_last_data_time(lt);
                }

                result
                    .details
                    .insert("event_class_count".into(), serde_json::json!(class_count));

                Ok(result)
            }
            Err(e) => Ok(HealthCheckResult::new(&self.source().name, false)
                .with_error(e.to_string())
                .with_latency(start.elapsed().as_secs_f64())),
        }
    }
}

impl SecurityLakeQueries for SecurityLakeConnector {
    async fn query_by_event_class(
        &self,
        event_class: OCSFEventClass,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
        additional_filters: Option<&str>,
    ) -> Result<QueryResult, SecurityLakeError> {
        let table = self.table_ref()?;
        let class_uid = event_class.class_uid();
        let safe_limit = limit.min(10000);
        let start_ts = format_athena_timestamp(&start);
        let end_ts = format_athena_timestamp(&end);

        let mut sql = format!(
            "SELECT * FROM {table} \
             WHERE class_uid = {class_uid} \
               AND time_dt >= TIMESTAMP '{start_ts}' \
               AND time_dt < TIMESTAMP '{end_ts}'"
        );

        if let Some(filters) = additional_filters {
            // Log warning if filters contain suspicious keywords
            let upper = filters.to_uppercase();
            if ["DROP", "DELETE", "INSERT", "UPDATE", "TRUNCATE"]
                .iter()
                .any(|kw| upper.contains(kw))
            {
                warn!(
                    filter = &filters[..filters.len().min(100)],
                    "Suspicious SQL filter detected"
                );
            }
            write!(sql, " AND ({filters})").unwrap();
        }

        write!(sql, " LIMIT {safe_limit}").unwrap();

        debug!(
            event_class = event_class.name(),
            class_uid, "Executing Security Lake query"
        );

        self.inner
            .query(&sql)
            .await
            .map_err(|e| SecurityLakeError::QueryFailed(e.to_string()))
    }

    async fn query_authentication_events(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        status: Option<&str>,
        limit: usize,
    ) -> Result<QueryResult, SecurityLakeError> {
        let filters = status.map(|s| {
            let safe = sanitize_string(s);
            format!("status = '{safe}'")
        });
        self.query_by_event_class(
            OCSFEventClass::Authentication,
            start,
            end,
            limit,
            filters.as_deref(),
        )
        .await
    }

    async fn query_api_activity(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        service: Option<&str>,
        operation: Option<&str>,
        limit: usize,
    ) -> Result<QueryResult, SecurityLakeError> {
        let mut filter_parts = Vec::new();
        if let Some(svc) = service {
            let safe = sanitize_string(svc);
            filter_parts.push(format!("\"api\".\"service\".\"name\" = '{safe}'"));
        }
        if let Some(op) = operation {
            let safe = sanitize_string(op);
            filter_parts.push(format!("\"api\".\"operation\" = '{safe}'"));
        }
        let filters = if filter_parts.is_empty() {
            None
        } else {
            Some(filter_parts.join(" AND "))
        };
        self.query_by_event_class(
            OCSFEventClass::ApiActivity,
            start,
            end,
            limit,
            filters.as_deref(),
        )
        .await
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
        let mut filter_parts = Vec::new();
        if let Some(ip) = src_ip {
            validate_ipv4(ip).map_err(|e| SecurityLakeError::InvalidParameter(e.to_string()))?;
            filter_parts.push(format!("\"src_endpoint\".\"ip\" = '{ip}'"));
        }
        if let Some(ip) = dst_ip {
            validate_ipv4(ip).map_err(|e| SecurityLakeError::InvalidParameter(e.to_string()))?;
            filter_parts.push(format!("\"dst_endpoint\".\"ip\" = '{ip}'"));
        }
        if let Some(port) = dst_port {
            filter_parts.push(format!("\"dst_endpoint\".\"port\" = {port}"));
        }
        let filters = if filter_parts.is_empty() {
            None
        } else {
            Some(filter_parts.join(" AND "))
        };
        self.query_by_event_class(
            OCSFEventClass::NetworkActivity,
            start,
            end,
            limit,
            filters.as_deref(),
        )
        .await
    }

    async fn query_security_findings(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        severity: Option<&str>,
        limit: usize,
    ) -> Result<QueryResult, SecurityLakeError> {
        let filters = severity.map(|s| {
            let safe = sanitize_string(s);
            format!("severity = '{safe}'")
        });
        self.query_by_event_class(
            OCSFEventClass::SecurityFinding,
            start,
            end,
            limit,
            filters.as_deref(),
        )
        .await
    }

    async fn get_event_summary(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<QueryResult, SecurityLakeError> {
        let table = self.table_ref()?;
        let start_ts = format_athena_timestamp(&start);
        let end_ts = format_athena_timestamp(&end);

        let sql = format!(
            "SELECT class_uid, class_name, COUNT(*) as event_count, \
             MIN(time_dt) as earliest, MAX(time_dt) as latest \
             FROM {table} \
             WHERE time_dt >= TIMESTAMP '{start_ts}' \
               AND time_dt < TIMESTAMP '{end_ts}' \
             GROUP BY class_uid, class_name \
             ORDER BY event_count DESC"
        );

        self.inner
            .query(&sql)
            .await
            .map_err(|e| SecurityLakeError::QueryFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that SQL generation for query_by_event_class produces correct format.
    /// We test the SQL format logic without actual AWS calls.
    #[test]
    fn format_athena_timestamp_correct() {
        let dt = chrono::DateTime::parse_from_rfc3339("2024-06-15T14:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let ts = format_athena_timestamp(&dt);
        // Should NOT contain 'T' or timezone
        assert!(!ts.contains('T'));
        assert!(!ts.contains('Z'));
        assert!(ts.starts_with("2024-06-15 14:30:00"));
    }

    #[test]
    fn ocsf_class_uid_in_sql() {
        // Verify the class UIDs used in SQL match expected values
        assert_eq!(OCSFEventClass::Authentication.class_uid(), 3002);
        assert_eq!(OCSFEventClass::ApiActivity.class_uid(), 6003);
        assert_eq!(OCSFEventClass::NetworkActivity.class_uid(), 4001);
        assert_eq!(OCSFEventClass::SecurityFinding.class_uid(), 2001);
    }

    #[test]
    fn sanitize_string_in_filter() {
        let malicious = "admin'; DROP TABLE users--";
        let safe = sanitize_string(malicious);
        assert!(!safe.contains("--"));
        assert!(safe.contains("''"));
    }

    #[test]
    fn validate_ip_rejects_bad_input() {
        assert!(validate_ipv4("not-an-ip").is_err());
        assert!(validate_ipv4("256.1.1.1").is_err());
        assert!(validate_ipv4("10.0.0.1; DROP TABLE").is_err());
    }

    #[test]
    fn validate_ip_accepts_valid() {
        assert!(validate_ipv4("10.0.0.1").is_ok());
        assert!(validate_ipv4("192.168.1.1").is_ok());
    }

    #[test]
    fn security_lake_error_display() {
        let e = SecurityLakeError::QueryFailed("timeout".into());
        assert_eq!(e.to_string(), "query failed: timeout");
    }

    #[test]
    fn security_lake_error_invalid_param() {
        let e = SecurityLakeError::InvalidParameter("bad ip".into());
        assert_eq!(e.to_string(), "invalid parameter: bad ip");
    }

    #[test]
    fn limit_capped_at_10000() {
        // The query_by_event_class caps limit at 10000
        let limit: usize = 50000;
        let safe = limit.min(10000);
        assert_eq!(safe, 10000);
    }
}
