//! Direct Iceberg connector for Security Lake.
//!
//! Uses the "plan with iceberg, read with arrow-rs" bypass pattern:
//! 1. `iceberg-catalog-glue` connects to AWS Glue to load Iceberg table metadata
//! 2. iceberg's scan planning resolves manifest files → produces `FileScanTask`s
//!    (S3 Parquet file paths) with partition pruning
//! 3. **Bypass** iceberg's `.to_arrow()` which fails on nested OCSF structs
//! 4. Read Parquet files directly with `parquet` crate (handles nested structs)
//! 5. Convert Arrow `RecordBatch`es to `QueryResult` via `arrow_convert`
//!
//! This gives sub-second query latency vs 1-3s with Athena.

use std::collections::HashMap;

use aws_sdk_s3::Client as S3Client;
use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use iceberg::expr::{Predicate, Reference};
use iceberg::scan::TableScan;
use iceberg::spec::Datum;
use iceberg::table::Table;
use iceberg::{Catalog, CatalogBuilder, TableIdent};
use iceberg_catalog_glue::GlueCatalogBuilder;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use tracing::{debug, warn};

use iris_core::catalog::DataSource;
use iris_core::connectors::base::{DataConnector, HealthCheckResult};
use iris_core::connectors::ocsf::{OCSFEventClass, SecurityLakeError, SecurityLakeQueries};
use iris_core::connectors::result::QueryResult;

use crate::arrow_convert::record_batches_to_query_result;
use crate::error::{AwsError, parse_s3_location};

/// Direct Iceberg connector for Security Lake tables.
///
/// Reads Parquet files directly from S3 using the Iceberg catalog for metadata,
/// bypassing Athena for sub-second query latency.
pub struct IcebergConnector {
    source: DataSource,
    catalog: iceberg_catalog_glue::GlueCatalog,
    s3: S3Client,
    table_ident: TableIdent,
}

impl IcebergConnector {
    /// Create a new `IcebergConnector`.
    ///
    /// # Errors
    /// Returns an error if the Glue catalog cannot be initialized.
    pub async fn new(
        source: DataSource,
        sdk_config: &aws_config::SdkConfig,
    ) -> Result<Self, AwsError> {
        let database = source
            .database
            .as_deref()
            .ok_or_else(|| AwsError::Config("database is required for Iceberg connector".into()))?;
        let table_name = source
            .table
            .as_deref()
            .ok_or_else(|| AwsError::Config("table is required for Iceberg connector".into()))?;

        let region = sdk_config
            .region()
            .map_or_else(|| source.region.clone(), std::string::ToString::to_string);

        // warehouse must be a valid S3 URL — it's used only for FileIO scheme
        // detection (S3 vs GCS vs local). Actual data paths come from Iceberg
        // metadata resolved via Glue. Any valid s3:// URL works.
        let warehouse = format!("s3://aws-security-data-lake-{region}");
        let props = HashMap::from([
            ("warehouse".to_string(), warehouse),
            ("region_name".to_string(), region),
        ]);

        let catalog = GlueCatalogBuilder::default()
            .load("iris-glue", props)
            .await
            .map_err(|e| AwsError::Config(format!("failed to init Glue catalog: {e}")))?;

        let table_ident = TableIdent::new(
            iceberg::NamespaceIdent::new(database.to_string()),
            table_name.to_string(),
        );

        Ok(Self {
            source,
            catalog,
            s3: S3Client::new(sdk_config),
            table_ident,
        })
    }

    /// Get the underlying data source definition.
    #[must_use]
    pub fn source(&self) -> &DataSource {
        &self.source
    }

    /// Load the Iceberg table from the Glue catalog.
    async fn load_table(&self) -> Result<Table, AwsError> {
        self.catalog
            .load_table(&self.table_ident)
            .await
            .map_err(|e| AwsError::QueryFailed(format!("failed to load Iceberg table: {e}")))
    }

    /// Build a table scan with optional predicates.
    fn build_scan(table: &Table, predicates: Option<Predicate>) -> Result<TableScan, AwsError> {
        let mut builder = table.scan();
        if let Some(pred) = predicates {
            builder = builder.with_filter(pred);
        }
        builder
            .build()
            .map_err(|e| AwsError::QueryFailed(format!("failed to build scan: {e}")))
    }

    /// Execute a scan: plan files, download Parquet from S3, convert to `QueryResult`.
    ///
    /// This is the core bypass: we use iceberg for scan planning (manifest
    /// filtering, partition pruning), then read Parquet files with arrow-rs
    /// which handles nested OCSF structs correctly.
    async fn execute_scan(
        &self,
        scan: TableScan,
        limit: Option<usize>,
    ) -> Result<QueryResult, AwsError> {
        // Plan: get the list of Parquet files to read
        let plan = scan
            .plan_files()
            .await
            .map_err(|e| AwsError::QueryFailed(format!("scan planning failed: {e}")))?;

        let tasks: Vec<_> = plan
            .try_collect()
            .await
            .map_err(|e| AwsError::QueryFailed(format!("failed to collect scan tasks: {e}")))?;

        tracing::info!(file_count = tasks.len(), "Iceberg scan planned");

        if tasks.is_empty() {
            return Ok(QueryResult::empty());
        }

        let mut all_batches = Vec::new();
        let mut total_rows: usize = 0;
        let row_limit = limit.unwrap_or(10_000);

        for task in &tasks {
            if total_rows >= row_limit {
                break;
            }

            let file_path = &task.data_file_path;
            debug!(path = %file_path, "Reading Parquet file");

            let parquet_bytes = self.download_parquet(file_path).await?;
            let batches = read_parquet_bytes(&parquet_bytes, row_limit - total_rows)?;

            for batch in batches {
                total_rows += batch.num_rows();
                all_batches.push(batch);
                if total_rows >= row_limit {
                    break;
                }
            }
        }

        tracing::info!(
            total_rows,
            files_read = tasks.len(),
            "Iceberg scan complete"
        );
        Ok(record_batches_to_query_result(&all_batches))
    }

    /// Download a Parquet file from S3.
    async fn download_parquet(&self, s3_uri: &str) -> Result<bytes::Bytes, AwsError> {
        let (bucket, key) = parse_s3_location(s3_uri)?;

        let resp = self
            .s3
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| AwsError::ResultReadFailed(format!("S3 GetObject failed: {e}")))?;

        resp.body
            .collect()
            .await
            .map(aws_sdk_s3::primitives::AggregatedBytes::into_bytes)
            .map_err(|e| AwsError::ResultReadFailed(format!("S3 body read failed: {e}")))
    }

    /// Build a time-range predicate for `time_dt` column.
    fn time_range_predicate(start: &DateTime<Utc>, end: &DateTime<Utc>) -> Predicate {
        let start_datum = Datum::timestamptz_from_datetime(*start);
        let end_datum = Datum::timestamptz_from_datetime(*end);

        Predicate::and(
            Reference::new("time_dt").greater_than_or_equal_to(start_datum),
            Reference::new("time_dt").less_than(end_datum),
        )
    }

    /// Build a predicate for `class_uid` filtering.
    fn class_uid_predicate(class_uid: u32) -> Predicate {
        // OCSF class_uid values are always < 10000, so this cast is safe
        #[allow(clippy::cast_possible_wrap)]
        Reference::new("class_uid").equal_to(Datum::int(class_uid as i32))
    }
}

/// Read Parquet bytes into Arrow `RecordBatch`es.
fn read_parquet_bytes(
    data: &bytes::Bytes,
    max_rows: usize,
) -> Result<Vec<arrow_array::RecordBatch>, AwsError> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(data.clone())
        .map_err(|e| AwsError::ResultReadFailed(format!("Parquet reader init failed: {e}")))?;

    let reader = builder
        .with_batch_size(max_rows.min(8192))
        .build()
        .map_err(|e| AwsError::ResultReadFailed(format!("Parquet reader build failed: {e}")))?;

    let mut batches = Vec::new();
    let mut total = 0;
    for batch_result in reader {
        let batch: arrow_array::RecordBatch = batch_result
            .map_err(|e| AwsError::ResultReadFailed(format!("Parquet batch read failed: {e}")))?;
        total += batch.num_rows();
        batches.push(batch);
        if total >= max_rows {
            break;
        }
    }

    Ok(batches)
}

impl DataConnector for IcebergConnector {
    async fn query(
        &self,
        sql: &str,
    ) -> Result<QueryResult, Box<dyn std::error::Error + Send + Sync>> {
        // The Iceberg connector doesn't support arbitrary SQL.
        // For SQL queries, callers should use the Athena connector.
        // This method exists for trait compatibility and does a full table scan
        // with an optional row limit.
        warn!(
            sql = &sql[..sql.len().min(100)],
            "IcebergConnector.query() called — Iceberg doesn't support SQL; doing full scan"
        );

        let table = self.load_table().await?;
        let scan = Self::build_scan(&table, None)?;
        let qr = self.execute_scan(scan, Some(1000)).await?;
        Ok(qr)
    }

    async fn get_schema(
        &self,
    ) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>> {
        let table = self.load_table().await?;
        let schema = table.metadata().current_schema();
        let mut result = HashMap::new();
        for field in schema.as_struct().fields() {
            result.insert(field.name.clone(), format!("{}", field.field_type));
        }
        Ok(result)
    }

    async fn check_health(
        &self,
    ) -> Result<HealthCheckResult, Box<dyn std::error::Error + Send + Sync>> {
        let start = std::time::Instant::now();
        let now = Utc::now();
        let one_hour_ago = now - chrono::Duration::hours(1);

        let table = match self.load_table().await {
            Ok(t) => t,
            Err(e) => {
                return Ok(HealthCheckResult::new(&self.source.name, false)
                    .with_error(e.to_string())
                    .with_latency(start.elapsed().as_secs_f64()));
            }
        };

        let predicate = Self::time_range_predicate(&one_hour_ago, &now);
        let scan = match Self::build_scan(&table, Some(predicate)) {
            Ok(s) => s,
            Err(e) => {
                return Ok(HealthCheckResult::new(&self.source.name, false)
                    .with_error(e.to_string())
                    .with_latency(start.elapsed().as_secs_f64()));
            }
        };

        match self.execute_scan(scan, Some(1)).await {
            Ok(qr) => {
                let latency = start.elapsed().as_secs_f64();
                let healthy = !qr.is_empty();

                #[allow(clippy::cast_possible_wrap)]
                Ok(HealthCheckResult::new(&self.source.name, healthy)
                    .with_record_count(qr.len() as i64)
                    .with_latency(latency))
            }
            Err(e) => Ok(HealthCheckResult::new(&self.source.name, false)
                .with_error(e.to_string())
                .with_latency(start.elapsed().as_secs_f64())),
        }
    }
}

impl SecurityLakeQueries for IcebergConnector {
    async fn query_by_event_class(
        &self,
        event_class: OCSFEventClass,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
        additional_filters: Option<&str>,
    ) -> Result<QueryResult, SecurityLakeError> {
        if additional_filters.is_some() {
            // Iceberg predicates don't support arbitrary SQL WHERE clauses.
            // For complex filters, the caller should fall back to Athena.
            warn!(
                "IcebergConnector ignoring additional_filters (not supported in Iceberg predicates)"
            );
        }

        let safe_limit = limit.min(10_000);
        let table = self
            .load_table()
            .await
            .map_err(|e| SecurityLakeError::QueryFailed(e.to_string()))?;

        let time_pred = Self::time_range_predicate(&start, &end);
        let class_pred = Self::class_uid_predicate(event_class.class_uid());
        let predicate = Predicate::and(time_pred, class_pred);

        debug!(
            event_class = event_class.name(),
            class_uid = event_class.class_uid(),
            "Executing Iceberg scan"
        );

        let scan = Self::build_scan(&table, Some(predicate))
            .map_err(|e| SecurityLakeError::QueryFailed(e.to_string()))?;

        self.execute_scan(scan, Some(safe_limit))
            .await
            .map_err(|e| SecurityLakeError::QueryFailed(e.to_string()))
    }

    async fn query_authentication_events(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        _status: Option<&str>,
        limit: usize,
    ) -> Result<QueryResult, SecurityLakeError> {
        // Status filtering would require post-scan filtering since it's not
        // an Iceberg partition column. For now, get all auth events and let
        // the caller filter.
        self.query_by_event_class(OCSFEventClass::Authentication, start, end, limit, None)
            .await
    }

    async fn query_api_activity(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        _service: Option<&str>,
        _operation: Option<&str>,
        limit: usize,
    ) -> Result<QueryResult, SecurityLakeError> {
        self.query_by_event_class(OCSFEventClass::ApiActivity, start, end, limit, None)
            .await
    }

    async fn query_network_activity(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        _src_ip: Option<&str>,
        _dst_ip: Option<&str>,
        _dst_port: Option<u16>,
        limit: usize,
    ) -> Result<QueryResult, SecurityLakeError> {
        self.query_by_event_class(OCSFEventClass::NetworkActivity, start, end, limit, None)
            .await
    }

    async fn query_security_findings(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        _severity: Option<&str>,
        limit: usize,
    ) -> Result<QueryResult, SecurityLakeError> {
        self.query_by_event_class(OCSFEventClass::SecurityFinding, start, end, limit, None)
            .await
    }

    async fn get_event_summary(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<QueryResult, SecurityLakeError> {
        // Iceberg can't do GROUP BY — scan all events and aggregate in memory.
        // For large time ranges this could be expensive; consider using Athena
        // for summaries if performance is a concern.
        let table = self
            .load_table()
            .await
            .map_err(|e| SecurityLakeError::QueryFailed(e.to_string()))?;

        let predicate = Self::time_range_predicate(&start, &end);
        let scan = Self::build_scan(&table, Some(predicate))
            .map_err(|e| SecurityLakeError::QueryFailed(e.to_string()))?;

        let qr = self
            .execute_scan(scan, Some(10_000))
            .await
            .map_err(|e| SecurityLakeError::QueryFailed(e.to_string()))?;

        // Aggregate: group by class_uid + class_name
        let mut summary: HashMap<(String, String), usize> = HashMap::new();
        for row in qr.rows() {
            let class_uid = row
                .get("class_uid")
                .map(std::string::ToString::to_string)
                .unwrap_or_default();
            let class_name = row
                .get("class_name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();
            *summary.entry((class_uid, class_name)).or_insert(0) += 1;
        }

        let mut rows: Vec<serde_json::Map<String, serde_json::Value>> = summary
            .into_iter()
            .map(|((uid, name), count)| {
                let mut row = serde_json::Map::new();
                row.insert("class_uid".into(), serde_json::json!(uid));
                row.insert("class_name".into(), serde_json::json!(name));
                row.insert("event_count".into(), serde_json::json!(count));
                row
            })
            .collect();

        // Sort by event_count descending
        rows.sort_by(|a, b| {
            let ca = a
                .get("event_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let cb = b
                .get("event_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            cb.cmp(&ca)
        });

        Ok(QueryResult::from_maps(rows))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_parquet_from_bytes() {
        // Create a minimal Parquet file in memory and verify round-trip
        use arrow_array::{Int64Array, RecordBatch, StringArray};
        use arrow_schema::{Field, Schema};
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(vec![
            Field::new("name", arrow_schema::DataType::Utf8, false),
            Field::new("value", arrow_schema::DataType::Int64, false),
        ]));

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(StringArray::from(vec!["alice", "bob"])),
                Arc::new(Int64Array::from(vec![10, 20])),
            ],
        )
        .unwrap();

        // Write to Parquet bytes
        let mut buf = Vec::new();
        let mut writer = parquet::arrow::ArrowWriter::try_new(&mut buf, schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();

        let parquet_bytes = bytes::Bytes::from(buf);
        let batches = read_parquet_bytes(&parquet_bytes, 100).unwrap();

        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].num_rows(), 2);

        let qr = record_batches_to_query_result(&batches);
        assert_eq!(qr.len(), 2);
        assert_eq!(qr.rows()[0]["name"], serde_json::json!("alice"));
        assert_eq!(qr.rows()[1]["value"], serde_json::json!(20));
    }

    #[test]
    fn read_parquet_with_row_limit() {
        use arrow_array::{Int64Array, RecordBatch};
        use arrow_schema::{Field, Schema};
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(vec![Field::new(
            "id",
            arrow_schema::DataType::Int64,
            false,
        )]));

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(Int64Array::from(vec![1, 2, 3, 4, 5]))],
        )
        .unwrap();

        let mut buf = Vec::new();
        let mut writer = parquet::arrow::ArrowWriter::try_new(&mut buf, schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();

        let parquet_bytes = bytes::Bytes::from(buf);

        // Request only 2 rows
        let batches = read_parquet_bytes(&parquet_bytes, 2).unwrap();
        let total_rows: usize = batches.iter().map(arrow_array::RecordBatch::num_rows).sum();
        // batch_size=2 means at most 2 rows per batch; we stop after first batch
        assert!(total_rows <= 2);
    }

    #[test]
    fn read_parquet_nested_struct() {
        // Verify the key bypass: nested structs that iceberg-rust can't handle
        use arrow_array::{Int64Array, RecordBatch, StringArray, StructArray};
        use arrow_schema::{DataType, Field, Schema};
        use std::sync::Arc;

        let name_field = Field::new("name", DataType::Utf8, true);
        let user_type = DataType::Struct(vec![name_field.clone()].into());
        let user_field = Field::new("user", user_type.clone(), true);
        let actor_type = DataType::Struct(vec![user_field.clone()].into());

        let schema = Arc::new(Schema::new(vec![
            Field::new("class_uid", DataType::Int64, false),
            Field::new("actor", actor_type, true),
        ]));

        // Build nested struct
        let names = StringArray::from(vec![Some("admin")]);
        let user_struct = StructArray::from(vec![(
            Arc::new(name_field),
            Arc::new(names) as Arc<dyn arrow_array::Array>,
        )]);
        let actor_struct = StructArray::from(vec![(
            Arc::new(user_field),
            Arc::new(user_struct) as Arc<dyn arrow_array::Array>,
        )]);

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![3002])),
                Arc::new(actor_struct),
            ],
        )
        .unwrap();

        // Write to Parquet and read back
        let mut buf = Vec::new();
        let mut writer = parquet::arrow::ArrowWriter::try_new(&mut buf, schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();

        let parquet_bytes = bytes::Bytes::from(buf);
        let batches = read_parquet_bytes(&parquet_bytes, 100).unwrap();

        let qr = record_batches_to_query_result(&batches);
        assert_eq!(qr.len(), 1);
        assert_eq!(
            qr.rows()[0]["actor"]["user"]["name"],
            serde_json::json!("admin")
        );
        assert_eq!(qr.rows()[0]["class_uid"], serde_json::json!(3002));
    }

    #[test]
    fn time_range_predicate_builds() {
        let start = Utc::now() - chrono::Duration::hours(1);
        let end = Utc::now();
        let pred = IcebergConnector::time_range_predicate(&start, &end);
        // Just verify it doesn't panic — predicate internals are opaque
        let _ = format!("{pred:?}");
    }

    #[test]
    fn class_uid_predicate_builds() {
        let pred = IcebergConnector::class_uid_predicate(3002);
        let _ = format!("{pred:?}");
    }
}
