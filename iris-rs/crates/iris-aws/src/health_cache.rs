use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_sdk_dynamodb::Client as DynamoClient;
use aws_sdk_dynamodb::types::AttributeValue;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use iris_core::connectors::base::HealthCheckResult;

use crate::error::AwsError;

/// Default TTL: 7 days in seconds.
const DEFAULT_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// A deserialized health check result from `DynamoDB`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedHealthResult {
    pub source_name: String,
    pub checked_at: String,
    pub healthy: bool,
    pub record_count: i64,
    pub latency_seconds: f64,
    pub last_data_time: Option<String>,
    pub error: Option<String>,
    pub details: HashMap<String, serde_json::Value>,
    pub data_age_minutes: Option<f64>,
}

/// DynamoDB-backed health check cache.
///
/// Schema: PK = `source_name`, SK = `checked_at` (ISO-8601), with 7-day TTL.
pub struct HealthCacheClient {
    client: DynamoClient,
    table_name: String,
    ttl_seconds: u64,
}

impl HealthCacheClient {
    /// Create a new client.
    pub fn new(sdk_config: &aws_config::SdkConfig, table_name: impl Into<String>) -> Self {
        Self {
            client: DynamoClient::new(sdk_config),
            table_name: table_name.into(),
            ttl_seconds: DEFAULT_TTL_SECONDS,
        }
    }

    /// Set a custom TTL (seconds).
    #[must_use]
    pub fn with_ttl(mut self, ttl_seconds: u64) -> Self {
        self.ttl_seconds = ttl_seconds;
        self
    }

    /// Write a single health check result.
    pub async fn put(&self, result: &HealthCheckResult) -> Result<(), AwsError> {
        let ttl = current_epoch_secs() + self.ttl_seconds;

        let mut item = HashMap::new();
        item.insert("source_name".into(), av_s(&result.source_name));
        item.insert("checked_at".into(), av_s(&result.checked_at.to_rfc3339()));
        item.insert("healthy".into(), AttributeValue::Bool(result.healthy));
        item.insert("record_count".into(), av_n(result.record_count));
        item.insert("latency_seconds".into(), av_n_f64(result.latency_seconds));
        item.insert("ttl".into(), av_n(i64::try_from(ttl).unwrap_or(i64::MAX)));

        if let Some(ref ldt) = result.last_data_time {
            item.insert("last_data_time".into(), av_s(&ldt.to_rfc3339()));
        }
        if let Some(ref err) = result.error {
            item.insert("error".into(), av_s(err));
        }
        if !result.details.is_empty() {
            let json = serde_json::to_string(&result.details).unwrap_or_default();
            item.insert("details".into(), av_s(&json));
        }

        self.client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|e| AwsError::DynamoDb(e.to_string()))?;

        debug!(source = %result.source_name, "Cached health result");
        Ok(())
    }

    /// Batch-write multiple health check results.
    pub async fn put_many(&self, results: &[HealthCheckResult]) -> Result<(), AwsError> {
        // DynamoDB batch_write_item supports up to 25 items
        for chunk in results.chunks(25) {
            let mut requests = Vec::new();
            for result in chunk {
                let ttl = current_epoch_secs() + self.ttl_seconds;

                let mut item = HashMap::new();
                item.insert("source_name".into(), av_s(&result.source_name));
                item.insert("checked_at".into(), av_s(&result.checked_at.to_rfc3339()));
                item.insert("healthy".into(), AttributeValue::Bool(result.healthy));
                item.insert("record_count".into(), av_n(result.record_count));
                item.insert("latency_seconds".into(), av_n_f64(result.latency_seconds));
                item.insert("ttl".into(), av_n(i64::try_from(ttl).unwrap_or(i64::MAX)));

                if let Some(ref ldt) = result.last_data_time {
                    item.insert("last_data_time".into(), av_s(&ldt.to_rfc3339()));
                }
                if let Some(ref err) = result.error {
                    item.insert("error".into(), av_s(err));
                }
                if !result.details.is_empty() {
                    let json = serde_json::to_string(&result.details).unwrap_or_default();
                    item.insert("details".into(), av_s(&json));
                }

                requests.push(
                    aws_sdk_dynamodb::types::WriteRequest::builder()
                        .put_request(
                            aws_sdk_dynamodb::types::PutRequest::builder()
                                .set_item(Some(item))
                                .build()
                                .map_err(|e| AwsError::DynamoDb(e.to_string()))?,
                        )
                        .build(),
                );
            }

            self.client
                .batch_write_item()
                .request_items(&self.table_name, requests)
                .send()
                .await
                .map_err(|e| AwsError::DynamoDb(e.to_string()))?;
        }

        info!(count = results.len(), "Batch-cached health results");
        Ok(())
    }

    /// Get the most recent health check result for a source.
    pub async fn get_latest(
        &self,
        source_name: &str,
    ) -> Result<Option<CachedHealthResult>, AwsError> {
        let resp = self
            .client
            .query()
            .table_name(&self.table_name)
            .key_condition_expression("source_name = :sn")
            .expression_attribute_values(":sn", av_s(source_name))
            .scan_index_forward(false)
            .limit(1)
            .send()
            .await
            .map_err(|e| AwsError::DynamoDb(e.to_string()))?;

        let items = resp.items();
        if items.is_empty() {
            return Ok(None);
        }

        Ok(Some(deserialize_item(&items[0])))
    }

    /// Get the latest health result for every source (scan).
    pub async fn get_all_latest(&self) -> Result<Vec<CachedHealthResult>, AwsError> {
        let resp = self
            .client
            .scan()
            .table_name(&self.table_name)
            .send()
            .await
            .map_err(|e| AwsError::DynamoDb(e.to_string()))?;

        let items = resp.items();

        // Group by source_name, keep most recent
        let mut latest: HashMap<String, &HashMap<String, AttributeValue>> = HashMap::new();
        for item in items {
            let name = get_s(item, "source_name").unwrap_or_default();
            let checked_at = get_s(item, "checked_at").unwrap_or_default();

            if let Some(existing) = latest.get(&name) {
                let existing_at = get_s(existing, "checked_at").unwrap_or_default();
                if checked_at > existing_at {
                    latest.insert(name, item);
                }
            } else {
                latest.insert(name, item);
            }
        }

        Ok(latest.values().map(|item| deserialize_item(item)).collect())
    }

    /// Get recent health check history for a source (newest first).
    pub async fn get_history(
        &self,
        source_name: &str,
        limit: i32,
    ) -> Result<Vec<CachedHealthResult>, AwsError> {
        let resp = self
            .client
            .query()
            .table_name(&self.table_name)
            .key_condition_expression("source_name = :sn")
            .expression_attribute_values(":sn", av_s(source_name))
            .scan_index_forward(false)
            .limit(limit)
            .send()
            .await
            .map_err(|e| AwsError::DynamoDb(e.to_string()))?;

        Ok(resp.items().iter().map(deserialize_item).collect())
    }
}

/// Deserialize a `DynamoDB` item into a `CachedHealthResult`.
fn deserialize_item(item: &HashMap<String, AttributeValue>) -> CachedHealthResult {
    let source_name = get_s(item, "source_name").unwrap_or_default();
    let checked_at = get_s(item, "checked_at").unwrap_or_default();
    let healthy = item
        .get("healthy")
        .and_then(|v| v.as_bool().ok())
        .copied()
        .unwrap_or(false);
    let record_count = get_n_i64(item, "record_count").unwrap_or(0);
    let latency_seconds = get_n_f64(item, "latency_seconds").unwrap_or(0.0);
    let last_data_time = get_s(item, "last_data_time");
    let error = get_s(item, "error");
    let details: HashMap<String, serde_json::Value> = get_s(item, "details")
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    // Compute data_age_minutes
    let data_age_minutes = last_data_time.as_ref().and_then(|ldt| {
        DateTime::parse_from_rfc3339(ldt).ok().map(|parsed| {
            let dt = parsed.with_timezone(&Utc);
            #[allow(clippy::cast_precision_loss)]
            let age = (Utc::now() - dt).num_seconds() as f64 / 60.0;
            (age * 10.0).round() / 10.0 // round to 1 decimal
        })
    });

    CachedHealthResult {
        source_name,
        checked_at,
        healthy,
        record_count,
        latency_seconds,
        last_data_time,
        error,
        details,
        data_age_minutes,
    }
}

// --- DynamoDB attribute value helpers ---

fn av_s(s: &str) -> AttributeValue {
    AttributeValue::S(s.to_string())
}

fn av_n(n: i64) -> AttributeValue {
    AttributeValue::N(n.to_string())
}

fn av_n_f64(n: f64) -> AttributeValue {
    AttributeValue::N(n.to_string())
}

fn get_s(item: &HashMap<String, AttributeValue>, key: &str) -> Option<String> {
    item.get(key).and_then(|v| v.as_s().ok()).map(String::from)
}

fn get_n_i64(item: &HashMap<String, AttributeValue>, key: &str) -> Option<i64> {
    item.get(key)
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse().ok())
}

fn get_n_f64(item: &HashMap<String, AttributeValue>, key: &str) -> Option<f64> {
    item.get(key)
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse().ok())
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_health_result_serializes() {
        let result = CachedHealthResult {
            source_name: "cloudtrail".into(),
            checked_at: "2024-01-15T10:30:00Z".into(),
            healthy: true,
            record_count: 42,
            latency_seconds: 1.5,
            last_data_time: Some("2024-01-15T10:29:00Z".into()),
            error: None,
            details: HashMap::new(),
            data_age_minutes: Some(1.0),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["source_name"], "cloudtrail");
        assert_eq!(json["healthy"], true);
        assert_eq!(json["record_count"], 42);
    }

    #[test]
    fn deserialize_dynamo_item() {
        let mut item = HashMap::new();
        item.insert("source_name".into(), av_s("test-source"));
        item.insert("checked_at".into(), av_s("2024-01-15T10:30:00+00:00"));
        item.insert("healthy".into(), AttributeValue::Bool(true));
        item.insert("record_count".into(), av_n(100));
        item.insert("latency_seconds".into(), av_n_f64(2.5));

        let result = deserialize_item(&item);
        assert_eq!(result.source_name, "test-source");
        assert!(result.healthy);
        assert_eq!(result.record_count, 100);
        assert!((result.latency_seconds - 2.5).abs() < f64::EPSILON);
        assert!(result.last_data_time.is_none());
        assert!(result.error.is_none());
    }

    #[test]
    fn deserialize_dynamo_item_with_details() {
        let mut item = HashMap::new();
        item.insert("source_name".into(), av_s("test"));
        item.insert("checked_at".into(), av_s("2024-01-15T10:30:00+00:00"));
        item.insert("healthy".into(), AttributeValue::Bool(false));
        item.insert("record_count".into(), av_n(0));
        item.insert("latency_seconds".into(), av_n_f64(0.0));
        item.insert("error".into(), av_s("connection timeout"));
        item.insert("details".into(), av_s(r#"{"event_class_count": 3}"#));

        let result = deserialize_item(&item);
        assert!(!result.healthy);
        assert_eq!(result.error.as_deref(), Some("connection timeout"));
        assert_eq!(
            result.details.get("event_class_count"),
            Some(&serde_json::json!(3))
        );
    }

    #[test]
    fn ttl_calculation() {
        let epoch = current_epoch_secs();
        let ttl = epoch + DEFAULT_TTL_SECONDS;
        // TTL should be ~7 days in the future
        assert!(ttl > epoch);
        assert_eq!(ttl - epoch, 7 * 24 * 60 * 60);
    }
}
