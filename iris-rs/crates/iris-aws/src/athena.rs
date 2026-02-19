use std::collections::HashMap;
use std::time::Instant;

use aws_sdk_athena::Client as AthenaClient;
use aws_sdk_s3::Client as S3Client;
use chrono::{DateTime, Utc};
use tracing::debug;

use iris_core::catalog::DataSource;
use iris_core::connectors::base::{DataConnector, HealthCheckResult};
use iris_core::connectors::result::QueryResult;
use iris_core::connectors::sql_utils::{quote_table, sanitize_string};

use crate::error::{AwsError, parse_s3_location};

/// AWS Athena data source connector.
///
/// Executes SQL queries against Athena, polls for completion, then downloads
/// and parses the CSV results from S3.
pub struct AthenaConnector {
    source: DataSource,
    athena: AthenaClient,
    s3: S3Client,
    workgroup: String,
    output_location: Option<String>,
}

impl AthenaConnector {
    /// Create a new `AthenaConnector` from a `DataSource` and AWS SDK config.
    pub fn new(source: DataSource, sdk_config: &aws_config::SdkConfig) -> Self {
        let workgroup = source
            .connector_config
            .get("workgroup")
            .and_then(|v| v.as_str())
            .unwrap_or("primary")
            .to_string();
        let output_location = source
            .connector_config
            .get("output_location")
            .and_then(|v| v.as_str())
            .map(String::from);

        Self {
            source,
            athena: AthenaClient::new(sdk_config),
            s3: S3Client::new(sdk_config),
            workgroup,
            output_location,
        }
    }

    /// Get the underlying data source definition.
    #[must_use]
    pub fn source(&self) -> &DataSource {
        &self.source
    }

    /// Poll Athena until the query completes or times out.
    async fn wait_for_query(&self, query_id: &str, max_wait_seconds: u64) -> Result<(), AwsError> {
        let start = Instant::now();

        loop {
            let resp = self
                .athena
                .get_query_execution()
                .query_execution_id(query_id)
                .send()
                .await
                .map_err(|e| AwsError::Sdk(Box::new(e)))?;

            let status = resp
                .query_execution()
                .and_then(|qe| qe.status())
                .and_then(|s| s.state())
                .map(|s| s.as_str().to_string())
                .unwrap_or_default();

            match status.as_str() {
                "SUCCEEDED" => return Ok(()),
                "FAILED" | "CANCELLED" => {
                    let reason = resp
                        .query_execution()
                        .and_then(|qe| qe.status())
                        .and_then(|s| s.state_change_reason())
                        .unwrap_or("Unknown error");
                    if status == "CANCELLED" {
                        return Err(AwsError::QueryCancelled(reason.to_string()));
                    }
                    return Err(AwsError::QueryFailed(format!("Query {status}: {reason}")));
                }
                _ => {}
            }

            if start.elapsed().as_secs() >= max_wait_seconds {
                return Err(AwsError::QueryTimeout {
                    query_id: query_id.to_string(),
                    max_wait_seconds,
                });
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    /// Download CSV results from S3 and parse into a `QueryResult`.
    async fn read_results(&self, s3_location: &str) -> Result<QueryResult, AwsError> {
        let (bucket, key) = parse_s3_location(s3_location)?;

        let resp = self
            .s3
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| AwsError::ResultReadFailed(e.to_string()))?;

        let bytes = resp
            .body
            .collect()
            .await
            .map_err(|e| AwsError::ResultReadFailed(e.to_string()))?
            .into_bytes();

        parse_csv_to_query_result(&bytes)
    }
}

impl DataConnector for AthenaConnector {
    async fn query(
        &self,
        sql: &str,
    ) -> Result<QueryResult, Box<dyn std::error::Error + Send + Sync>> {
        let database = self.source.database.as_deref().unwrap_or("default");

        let mut req = self
            .athena
            .start_query_execution()
            .query_string(sql)
            .query_execution_context(
                aws_sdk_athena::types::QueryExecutionContext::builder()
                    .database(database)
                    .build(),
            )
            .work_group(&self.workgroup);

        if let Some(ref loc) = self.output_location {
            req = req.result_configuration(
                aws_sdk_athena::types::ResultConfiguration::builder()
                    .output_location(loc)
                    .build(),
            );
        }

        let resp = req.send().await.map_err(|e| {
            // Extract the full error chain for diagnostics — SDK Display often just says "service error"
            AwsError::QueryFailed(format!("StartQueryExecution failed: {e:?}"))
        })?;

        let query_id = resp
            .query_execution_id()
            .ok_or_else(|| AwsError::QueryFailed("no query execution ID returned".into()))?;

        debug!(query_id, "Athena query started");

        self.wait_for_query(query_id, 300).await?;

        // Get the output location from the completed query
        let exec_resp = self
            .athena
            .get_query_execution()
            .query_execution_id(query_id)
            .send()
            .await
            .map_err(|e| AwsError::Sdk(Box::new(e)))?;

        let result_location = exec_resp
            .query_execution()
            .and_then(|qe| qe.result_configuration())
            .and_then(|rc| rc.output_location())
            .ok_or_else(|| AwsError::ResultReadFailed("no output location".into()))?;

        let qr = self.read_results(result_location).await?;
        Ok(qr)
    }

    async fn get_schema(
        &self,
    ) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>> {
        let Some(ref table) = self.source.table else {
            return Ok(HashMap::new());
        };

        let safe_db = sanitize_string(self.source.database.as_deref().unwrap_or("default"));
        let safe_table = sanitize_string(table);

        let sql = format!(
            "SELECT column_name, data_type \
             FROM information_schema.columns \
             WHERE table_schema = '{safe_db}' \
               AND table_name = '{safe_table}'"
        );

        let qr = self.query(&sql).await?;
        let mut schema = HashMap::new();
        for row in qr.rows() {
            if let (Some(col), Some(dtype)) = (
                row.get("column_name").and_then(|v| v.as_str()),
                row.get("data_type").and_then(|v| v.as_str()),
            ) {
                schema.insert(col.to_string(), dtype.to_string());
            }
        }
        Ok(schema)
    }

    async fn check_health(
        &self,
    ) -> Result<HealthCheckResult, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();

        let sql = if let Some(ref custom_query) = self.source.health_check_query {
            custom_query.clone()
        } else {
            let table = quote_table(
                self.source.database.as_deref().unwrap_or("default"),
                self.source.table.as_deref().unwrap_or("unknown"),
            )?;
            format!(
                "SELECT COUNT(*) as cnt, MAX(time) as latest_time \
                 FROM {table} \
                 WHERE time >= CURRENT_TIMESTAMP - INTERVAL '1' HOUR"
            )
        };

        match self.query(&sql).await {
            Ok(qr) => {
                let latency = start_time.elapsed().as_secs_f64();
                let record_count = qr
                    .rows()
                    .first()
                    .and_then(|r| r.get("cnt"))
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
                    age_minutes <= f64::from(self.source.expected_freshness_minutes)
                } else {
                    record_count > 0
                };

                Ok(HealthCheckResult::new(&self.source.name, healthy)
                    .with_record_count(record_count)
                    .with_latency(latency))
            }
            Err(e) => Ok(HealthCheckResult::new(&self.source.name, false)
                .with_error(e.to_string())
                .with_latency(start_time.elapsed().as_secs_f64())),
        }
    }
}

/// Parse CSV bytes into a `QueryResult`.
pub fn parse_csv_to_query_result(data: &[u8]) -> Result<QueryResult, AwsError> {
    let mut reader = csv::ReaderBuilder::new().from_reader(data);

    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| AwsError::CsvParse(e.to_string()))?
        .iter()
        .map(String::from)
        .collect();

    if headers.is_empty() {
        return Ok(QueryResult::empty());
    }

    let mut rows = Vec::new();
    for result in reader.records() {
        let record = result.map_err(|e| AwsError::CsvParse(e.to_string()))?;
        let mut row = serde_json::Map::new();
        for (i, field) in record.iter().enumerate() {
            if let Some(col_name) = headers.get(i) {
                row.insert(
                    col_name.clone(),
                    serde_json::Value::String(field.to_string()),
                );
            }
        }
        rows.push(row);
    }

    Ok(QueryResult::new(headers, rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_csv_basic() {
        let csv_data = b"name,age,city\nalice,30,seattle\nbob,25,portland\n";
        let qr = parse_csv_to_query_result(csv_data).unwrap();
        assert_eq!(qr.len(), 2);
        assert_eq!(qr.columns(), &["name", "age", "city"]);
        assert_eq!(
            qr.rows()[0].get("name").and_then(|v| v.as_str()),
            Some("alice")
        );
    }

    #[test]
    fn parse_csv_empty() {
        let csv_data = b"name,age\n";
        let qr = parse_csv_to_query_result(csv_data).unwrap();
        assert!(qr.is_empty());
        assert_eq!(qr.columns(), &["name", "age"]);
    }

    #[test]
    fn parse_csv_single_row() {
        let csv_data = b"cnt,latest_time\n42,2024-01-15T10:30:00Z\n";
        let qr = parse_csv_to_query_result(csv_data).unwrap();
        assert_eq!(qr.len(), 1);
        assert_eq!(qr.rows()[0].get("cnt").and_then(|v| v.as_str()), Some("42"));
    }

    #[test]
    fn parse_csv_with_commas_in_quoted_fields() {
        let csv_data = b"msg,count\n\"hello, world\",5\n";
        let qr = parse_csv_to_query_result(csv_data).unwrap();
        assert_eq!(qr.len(), 1);
        assert_eq!(
            qr.rows()[0].get("msg").and_then(|v| v.as_str()),
            Some("hello, world")
        );
    }

    #[test]
    fn parse_csv_empty_bytes() {
        // Completely empty input
        let qr = parse_csv_to_query_result(b"");
        assert!(qr.is_ok());
        assert!(qr.unwrap().is_empty());
    }

    #[test]
    fn parse_csv_special_characters() {
        let csv_data = b"user,query\nalice,\"SELECT * FROM t WHERE x = 'val'\"\n";
        let qr = parse_csv_to_query_result(csv_data).unwrap();
        assert_eq!(qr.len(), 1);
        assert!(
            qr.rows()[0]
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap()
                .contains("SELECT")
        );
    }
}
