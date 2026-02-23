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

use arrow_array::{
    Array, BooleanArray, Int32Array, ListArray, RecordBatch, StringArray, cast::AsArray,
};
use arrow_ord::cmp::eq;
use arrow_schema::DataType;
use arrow_select::filter::filter_record_batch;
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

use irone_core::catalog::DataSource;
use irone_core::connectors::base::{DataConnector, HealthCheckResult};
use irone_core::connectors::ocsf::{
    ColumnFilter, OCSFEventClass, SecurityLakeError, SecurityLakeQueries,
};
use irone_core::connectors::result::QueryResult;

use crate::arrow_convert::record_batches_to_query_result;
use crate::error::{AwsError, parse_s3_location};

/// Arrow-level row filter applied after reading Parquet files.
///
/// Needed because our "plan with iceberg, read with arrow-rs" bypass skips
/// iceberg's row-level filtering — Iceberg predicates only prune at the
/// manifest/file level, so without this, queries like `class_uid = 3002`
/// return unfiltered rows.
enum ArrowRowFilter {
    /// Filter rows where a top-level int column equals a specific value.
    IntEquals { column: String, value: i32 },
    /// Filter rows where a nested string column equals a specific value.
    NestedStringEquals { path: Vec<String>, value: String },
    /// Filter rows where a nested string column matches any of the given values.
    NestedStringIn {
        path: Vec<String>,
        values: Vec<String>,
    },
    /// Disjunction of filters.
    Or(Vec<ArrowRowFilter>),
    /// Conjunction of filters.
    And(Vec<ArrowRowFilter>),
    /// Match rows where a List<Struct> column contains an element with a field
    /// equal to the given value (Arrow equivalent of `any_match`).
    ListContains {
        list_path: Vec<String>,
        field: String,
        value: String,
    },
    /// Match rows where a List<Struct> column contains an element with a field
    /// matching any of the given values.
    ListContainsAny {
        list_path: Vec<String>,
        field: String,
        values: Vec<String>,
    },
}

impl ArrowRowFilter {
    /// Compute a boolean mask for filtering a `RecordBatch`.
    fn compute_mask(&self, batch: &RecordBatch) -> Result<BooleanArray, AwsError> {
        match self {
            Self::IntEquals { column, value } => {
                let col_idx = batch.schema().index_of(column).map_err(|_| {
                    AwsError::QueryFailed(format!("filter column '{column}' not found in batch"))
                })?;
                let col = batch.column(col_idx);
                let target = Int32Array::from(vec![*value; batch.num_rows()]);
                let col_i32 = if *col.data_type() == DataType::Int32 {
                    col.as_primitive::<arrow_array::types::Int32Type>().clone()
                } else {
                    arrow_cast::cast(col, &DataType::Int32)
                        .map_err(|e| {
                            AwsError::QueryFailed(format!(
                                "failed to cast column '{column}' to Int32: {e}"
                            ))
                        })?
                        .as_primitive::<arrow_array::types::Int32Type>()
                        .clone()
                };
                eq(&col_i32, &target)
                    .map_err(|e| AwsError::QueryFailed(format!("filter comparison failed: {e}")))
            }

            Self::NestedStringEquals { path, value } => {
                let str_col = resolve_nested_string_column(batch, path)?;
                let bits: Vec<bool> = (0..batch.num_rows())
                    .map(|i| !str_col.is_null(i) && str_col.value(i) == value)
                    .collect();
                Ok(BooleanArray::from(bits))
            }

            Self::NestedStringIn { path, values } => {
                let str_col = resolve_nested_string_column(batch, path)?;
                let bits: Vec<bool> = (0..batch.num_rows())
                    .map(|i| !str_col.is_null(i) && values.iter().any(|v| v == str_col.value(i)))
                    .collect();
                Ok(BooleanArray::from(bits))
            }

            Self::Or(filters) => {
                if filters.is_empty() {
                    return Ok(BooleanArray::from(vec![false; batch.num_rows()]));
                }
                let first = filters[0].compute_mask(batch)?;
                let mut result = first;
                for f in &filters[1..] {
                    let mask = f.compute_mask(batch)?;
                    result = arrow_arith::boolean::or(&result, &mask)
                        .map_err(|e| AwsError::QueryFailed(format!("boolean OR failed: {e}")))?;
                }
                Ok(result)
            }

            Self::And(filters) => {
                if filters.is_empty() {
                    return Ok(BooleanArray::from(vec![true; batch.num_rows()]));
                }
                let first = filters[0].compute_mask(batch)?;
                let mut result = first;
                for f in &filters[1..] {
                    let mask = f.compute_mask(batch)?;
                    result = arrow_arith::boolean::and(&result, &mask)
                        .map_err(|e| AwsError::QueryFailed(format!("boolean AND failed: {e}")))?;
                }
                Ok(result)
            }

            Self::ListContains {
                list_path,
                field,
                value,
            } => list_any_match(batch, list_path, field, |s| s == value),

            Self::ListContainsAny {
                list_path,
                field,
                values,
            } => list_any_match(batch, list_path, field, |s| values.iter().any(|v| v == s)),
        }
    }

    /// Apply this filter to a `RecordBatch`, returning only matching rows.
    fn apply(&self, batch: &RecordBatch) -> Result<RecordBatch, AwsError> {
        let mask = self.compute_mask(batch)?;
        filter_record_batch(batch, &mask)
            .map_err(|e| AwsError::QueryFailed(format!("filter_record_batch failed: {e}")))
    }
}

/// Traverse nested `StructArray` columns to resolve any leaf column.
///
/// Given a path like `["actor", "user", "name"]`, navigates
/// `batch→actor (StructArray)→user (StructArray)→name (any Array)`.
/// Returns the raw `Arc<dyn Array>` at the leaf — callers handle type casting.
fn resolve_nested_column(
    batch: &RecordBatch,
    path: &[String],
) -> Result<std::sync::Arc<dyn Array>, AwsError> {
    if path.is_empty() {
        return Err(AwsError::QueryFailed("empty column path".into()));
    }

    let col_idx = batch
        .schema()
        .index_of(&path[0])
        .map_err(|_| AwsError::QueryFailed(format!("column '{}' not found in batch", path[0])))?;
    let mut current: std::sync::Arc<dyn Array> = std::sync::Arc::clone(batch.column(col_idx));

    for segment in &path[1..] {
        let struct_arr = current
            .as_any()
            .downcast_ref::<arrow_array::StructArray>()
            .ok_or_else(|| {
                AwsError::QueryFailed(format!(
                    "expected StructArray at '{}', got {:?}",
                    segment,
                    current.data_type()
                ))
            })?;
        let field_idx = struct_arr
            .fields()
            .iter()
            .position(|f| f.name() == segment)
            .ok_or_else(|| {
                AwsError::QueryFailed(format!("field '{segment}' not found in struct"))
            })?;
        current = std::sync::Arc::clone(struct_arr.column(field_idx));
    }

    Ok(current)
}

/// Traverse nested `StructArray` columns to resolve a string leaf.
///
/// Delegates to [`resolve_nested_column`] then handles `Utf8`/`LargeUtf8` casting.
fn resolve_nested_string_column(
    batch: &RecordBatch,
    path: &[String],
) -> Result<StringArray, AwsError> {
    let leaf = resolve_nested_column(batch, path)?;
    match leaf.data_type() {
        DataType::Utf8 => {
            let arr = leaf
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| AwsError::QueryFailed("downcast to StringArray failed".into()))?;
            Ok(arr.clone())
        }
        DataType::LargeUtf8 => {
            let casted = arrow_cast::cast(&leaf, &DataType::Utf8)
                .map_err(|e| AwsError::QueryFailed(format!("LargeUtf8→Utf8 cast failed: {e}")))?;
            let arr = casted
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| {
                    AwsError::QueryFailed("downcast to StringArray after cast failed".into())
                })?;
            Ok(arr.clone())
        }
        dt => Err(AwsError::QueryFailed(format!(
            "expected string column at end of path, got {dt:?}"
        ))),
    }
}

/// Check if any element in a `List<Struct>` column has a string field matching a predicate.
///
/// For each row, resolves the list column at `list_path`, iterates its elements
/// (which must be structs), extracts the named `field` as a string, and returns
/// `true` if `predicate(field_value)` is true for any element.
///
/// This is the Arrow equivalent of Athena's `any_match(list, x -> x.field = value)`.
fn list_any_match(
    batch: &RecordBatch,
    list_path: &[String],
    field: &str,
    predicate: impl Fn(&str) -> bool,
) -> Result<BooleanArray, AwsError> {
    let list_col = resolve_nested_column(batch, list_path)?;
    let list_arr = list_col
        .as_any()
        .downcast_ref::<ListArray>()
        .ok_or_else(|| {
            AwsError::QueryFailed(format!(
                "expected ListArray at '{}', got {:?}",
                list_path.last().unwrap_or(&String::new()),
                list_col.data_type()
            ))
        })?;

    // The values inside the list must be a StructArray
    let values = list_arr.values();
    let struct_arr = values
        .as_any()
        .downcast_ref::<arrow_array::StructArray>()
        .ok_or_else(|| {
            AwsError::QueryFailed(format!(
                "expected List<Struct>, got List<{:?}>",
                values.data_type()
            ))
        })?;

    // Find the target field within the struct
    let field_idx = struct_arr
        .fields()
        .iter()
        .position(|f| f.name() == field)
        .ok_or_else(|| {
            AwsError::QueryFailed(format!(
                "field '{field}' not found in list struct (fields: {:?})",
                struct_arr
                    .fields()
                    .iter()
                    .map(|f| f.name().as_str())
                    .collect::<Vec<_>>()
            ))
        })?;
    let field_col = struct_arr.column(field_idx);

    // Get the string values — handle Utf8 and LargeUtf8
    let str_values: StringArray = match field_col.data_type() {
        DataType::Utf8 => field_col
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or_else(|| AwsError::QueryFailed("downcast to StringArray failed".into()))?
            .clone(),
        DataType::LargeUtf8 => {
            let casted = arrow_cast::cast(field_col, &DataType::Utf8)
                .map_err(|e| AwsError::QueryFailed(format!("LargeUtf8→Utf8 cast: {e}")))?;
            casted
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| AwsError::QueryFailed("downcast after cast failed".into()))?
                .clone()
        }
        dt => {
            return Err(AwsError::QueryFailed(format!(
                "expected string field '{field}' in list struct, got {dt:?}"
            )));
        }
    };

    // For each row, check if any element in its list slice matches.
    // Offsets are non-negative i32 from Arrow's ListArray, so the cast is safe.
    #[allow(clippy::cast_sign_loss)]
    let bits: Vec<bool> = (0..batch.num_rows())
        .map(|row| {
            if list_arr.is_null(row) {
                return false;
            }
            let offsets = list_arr.value_offsets();
            let start = offsets[row] as usize;
            let end = offsets[row + 1] as usize;
            (start..end).any(|elem_idx| {
                !str_values.is_null(elem_idx) && predicate(str_values.value(elem_idx))
            })
        })
        .collect();

    Ok(BooleanArray::from(bits))
}

/// Convert `ColumnFilter` predicates to an `ArrowRowFilter`.
///
/// `RawSql` variants are silently skipped (with a warning) since they can't
/// be expressed as Arrow operations. Returns `None` if all filters are `RawSql`.
fn column_filters_to_arrow(filters: &[ColumnFilter]) -> Option<ArrowRowFilter> {
    let mut arrow_filters: Vec<ArrowRowFilter> = Vec::new();

    for f in filters {
        if let Some(af) = single_column_filter_to_arrow(f) {
            arrow_filters.push(af);
        }
    }

    match arrow_filters.len() {
        0 => None,
        1 => Some(arrow_filters.remove(0)),
        _ => Some(ArrowRowFilter::And(arrow_filters)),
    }
}

fn single_column_filter_to_arrow(filter: &ColumnFilter) -> Option<ArrowRowFilter> {
    match filter {
        ColumnFilter::StringEquals { path, value } => Some(ArrowRowFilter::NestedStringEquals {
            path: path.split('.').map(String::from).collect(),
            value: value.clone(),
        }),
        ColumnFilter::StringIn { path, values } => Some(ArrowRowFilter::NestedStringIn {
            path: path.split('.').map(String::from).collect(),
            values: values.clone(),
        }),
        ColumnFilter::Or(inner) => {
            let converted: Vec<ArrowRowFilter> = inner
                .iter()
                .filter_map(single_column_filter_to_arrow)
                .collect();
            if converted.is_empty() {
                None
            } else {
                Some(ArrowRowFilter::Or(converted))
            }
        }
        ColumnFilter::And(inner) => {
            let converted: Vec<ArrowRowFilter> = inner
                .iter()
                .filter_map(single_column_filter_to_arrow)
                .collect();
            if converted.is_empty() {
                None
            } else {
                Some(ArrowRowFilter::And(converted))
            }
        }
        ColumnFilter::RawSql(sql) => {
            warn!(
                sql = &sql[..sql.len().min(80)],
                "Iceberg ignoring RawSql filter"
            );
            None
        }
        ColumnFilter::ListContains {
            list_path,
            field,
            value,
        } => Some(ArrowRowFilter::ListContains {
            list_path: list_path.split('.').map(String::from).collect(),
            field: field.clone(),
            value: value.clone(),
        }),
        ColumnFilter::ListContainsAny {
            list_path,
            field,
            values,
        } => Some(ArrowRowFilter::ListContainsAny {
            list_path: list_path.split('.').map(String::from).collect(),
            field: field.clone(),
            values: values.clone(),
        }),
    }
}

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
            .load("irone-glue", props)
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
    ///
    /// The optional `row_filter` applies Arrow-level row filtering after reading
    /// each Parquet file. This is necessary because Iceberg predicates only prune
    /// at the manifest/file level — our bypass skips iceberg's row-level filtering.
    async fn execute_scan(
        &self,
        scan: TableScan,
        limit: Option<usize>,
        row_filter: Option<ArrowRowFilter>,
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
                let filtered = if let Some(ref filter) = row_filter {
                    filter.apply(&batch)?
                } else {
                    batch
                };
                if filtered.num_rows() > 0 {
                    total_rows += filtered.num_rows();
                    all_batches.push(filtered);
                }
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
        let qr = self.execute_scan(scan, Some(1000), None).await?;
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

        match self.execute_scan(scan, Some(1), None).await {
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
        filters: Option<&[ColumnFilter]>,
    ) -> Result<QueryResult, SecurityLakeError> {
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
            has_filters = filters.is_some(),
            "Executing Iceberg scan"
        );

        let scan = Self::build_scan(&table, Some(predicate))
            .map_err(|e| SecurityLakeError::QueryFailed(e.to_string()))?;

        // Build Arrow-level row filter: always include class_uid filter,
        // plus any ColumnFilter predicates converted to Arrow operations.
        #[allow(clippy::cast_possible_wrap)]
        let class_filter = ArrowRowFilter::IntEquals {
            column: "class_uid".into(),
            value: event_class.class_uid() as i32,
        };

        let row_filter = if let Some(extra) = filters.and_then(column_filters_to_arrow) {
            ArrowRowFilter::And(vec![class_filter, extra])
        } else {
            class_filter
        };

        self.execute_scan(scan, Some(safe_limit), Some(row_filter))
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
            .execute_scan(scan, Some(10_000), None)
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

    #[test]
    fn arrow_row_filter_int_equals() {
        use arrow_array::{Int32Array, RecordBatch, StringArray};
        use arrow_schema::{Field, Schema};
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(vec![
            Field::new("class_uid", DataType::Int32, false),
            Field::new("class_name", DataType::Utf8, false),
        ]));

        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(Int32Array::from(vec![6003, 3002, 6003, 3002, 4001])),
                Arc::new(StringArray::from(vec![
                    "API Activity",
                    "Authentication",
                    "API Activity",
                    "Authentication",
                    "Network Activity",
                ])),
            ],
        )
        .unwrap();

        let filter = ArrowRowFilter::IntEquals {
            column: "class_uid".into(),
            value: 3002,
        };
        let filtered = filter.apply(&batch).unwrap();

        assert_eq!(filtered.num_rows(), 2);
        let names = filtered
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(names.value(0), "Authentication");
        assert_eq!(names.value(1), "Authentication");
    }

    #[test]
    fn arrow_row_filter_int_equals_casts_int64() {
        use arrow_array::{Int64Array, RecordBatch};
        use arrow_schema::{Field, Schema};
        use std::sync::Arc;

        // Security Lake stores class_uid as Int64, filter should cast
        let schema = Arc::new(Schema::new(vec![Field::new(
            "class_uid",
            DataType::Int64,
            false,
        )]));

        let batch = RecordBatch::try_new(
            schema,
            vec![Arc::new(Int64Array::from(vec![6003, 3002, 4001]))],
        )
        .unwrap();

        let filter = ArrowRowFilter::IntEquals {
            column: "class_uid".into(),
            value: 3002,
        };
        let filtered = filter.apply(&batch).unwrap();
        assert_eq!(filtered.num_rows(), 1);
    }

    #[test]
    fn arrow_row_filter_no_matches_returns_empty() {
        use arrow_array::{Int32Array, RecordBatch};
        use arrow_schema::{Field, Schema};
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(vec![Field::new(
            "class_uid",
            DataType::Int32,
            false,
        )]));

        let batch =
            RecordBatch::try_new(schema, vec![Arc::new(Int32Array::from(vec![6003, 4001]))])
                .unwrap();

        let filter = ArrowRowFilter::IntEquals {
            column: "class_uid".into(),
            value: 9999,
        };
        let filtered = filter.apply(&batch).unwrap();
        assert_eq!(filtered.num_rows(), 0);
    }

    #[test]
    fn arrow_row_filter_missing_column_errors() {
        use arrow_array::{Int32Array, RecordBatch};
        use arrow_schema::{Field, Schema};
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(vec![Field::new(
            "other_col",
            DataType::Int32,
            false,
        )]));

        let batch =
            RecordBatch::try_new(schema, vec![Arc::new(Int32Array::from(vec![1]))]).unwrap();

        let filter = ArrowRowFilter::IntEquals {
            column: "class_uid".into(),
            value: 3002,
        };
        let result = filter.apply(&batch);
        assert!(result.is_err());
    }

    /// Helper: build a batch with nested struct actor.user.name.
    fn nested_actor_batch(names: &[Option<&str>]) -> RecordBatch {
        use arrow_array::{RecordBatch, StringArray, StructArray};
        use arrow_schema::{Field, Schema};
        use std::sync::Arc;

        let name_field = Field::new("name", DataType::Utf8, true);
        let user_type = DataType::Struct(vec![name_field.clone()].into());
        let user_field = Field::new("user", user_type, true);
        let actor_type = DataType::Struct(vec![user_field.clone()].into());

        let schema = Arc::new(Schema::new(vec![Field::new("actor", actor_type, true)]));

        let name_arr = StringArray::from(names.to_vec());
        let user_struct = StructArray::from(vec![(
            Arc::new(name_field),
            Arc::new(name_arr) as Arc<dyn arrow_array::Array>,
        )]);
        let actor_struct = StructArray::from(vec![(
            Arc::new(user_field),
            Arc::new(user_struct) as Arc<dyn arrow_array::Array>,
        )]);

        RecordBatch::try_new(schema, vec![Arc::new(actor_struct)]).unwrap()
    }

    #[test]
    fn nested_string_equals_filters_rows() {
        let batch = nested_actor_batch(&[Some("alice"), Some("bob"), Some("alice")]);

        let filter = ArrowRowFilter::NestedStringEquals {
            path: vec!["actor".into(), "user".into(), "name".into()],
            value: "alice".into(),
        };
        let filtered = filter.apply(&batch).unwrap();
        assert_eq!(filtered.num_rows(), 2);
    }

    #[test]
    fn nested_string_in_filters_rows() {
        let batch = nested_actor_batch(&[Some("alice"), Some("bob"), Some("charlie")]);

        let filter = ArrowRowFilter::NestedStringIn {
            path: vec!["actor".into(), "user".into(), "name".into()],
            values: vec!["alice".into(), "charlie".into()],
        };
        let filtered = filter.apply(&batch).unwrap();
        assert_eq!(filtered.num_rows(), 2);
    }

    #[test]
    fn nested_string_equals_handles_nulls() {
        let batch = nested_actor_batch(&[Some("alice"), None, Some("alice")]);

        let filter = ArrowRowFilter::NestedStringEquals {
            path: vec!["actor".into(), "user".into(), "name".into()],
            value: "alice".into(),
        };
        let filtered = filter.apply(&batch).unwrap();
        assert_eq!(filtered.num_rows(), 2);
    }

    #[test]
    fn or_filter_combines_masks() {
        use arrow_array::{RecordBatch, StringArray};
        use arrow_schema::{Field, Schema};
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(vec![
            Field::new("src_ip", DataType::Utf8, true),
            Field::new("dst_ip", DataType::Utf8, true),
        ]));
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(StringArray::from(vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"])),
                Arc::new(StringArray::from(vec!["8.8.8.8", "10.0.0.1", "1.1.1.1"])),
            ],
        )
        .unwrap();

        let filter = ArrowRowFilter::Or(vec![
            ArrowRowFilter::NestedStringEquals {
                path: vec!["src_ip".into()],
                value: "10.0.0.1".into(),
            },
            ArrowRowFilter::NestedStringEquals {
                path: vec!["dst_ip".into()],
                value: "10.0.0.1".into(),
            },
        ]);
        let filtered = filter.apply(&batch).unwrap();
        // Row 0: src=10.0.0.1 matches; Row 1: dst=10.0.0.1 matches; Row 2: no match
        assert_eq!(filtered.num_rows(), 2);
    }

    #[test]
    fn and_filter_intersects_masks() {
        use arrow_array::{Int32Array, RecordBatch, StringArray};
        use arrow_schema::{Field, Schema};
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(vec![
            Field::new("class_uid", DataType::Int32, false),
            Field::new("status", DataType::Utf8, true),
        ]));
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(Int32Array::from(vec![3002, 3002, 6003])),
                Arc::new(StringArray::from(vec!["Success", "Failure", "Success"])),
            ],
        )
        .unwrap();

        let filter = ArrowRowFilter::And(vec![
            ArrowRowFilter::IntEquals {
                column: "class_uid".into(),
                value: 3002,
            },
            ArrowRowFilter::NestedStringEquals {
                path: vec!["status".into()],
                value: "Success".into(),
            },
        ]);
        let filtered = filter.apply(&batch).unwrap();
        assert_eq!(filtered.num_rows(), 1);
    }

    #[test]
    fn nested_string_missing_field_errors() {
        let batch = nested_actor_batch(&[Some("alice")]);

        let filter = ArrowRowFilter::NestedStringEquals {
            path: vec!["actor".into(), "session".into(), "id".into()],
            value: "x".into(),
        };
        let result = filter.apply(&batch);
        assert!(result.is_err());
    }

    #[test]
    fn large_utf8_column_resolved() {
        use arrow_array::{LargeStringArray, RecordBatch};
        use arrow_schema::{Field, Schema};
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(vec![Field::new(
            "name",
            DataType::LargeUtf8,
            true,
        )]));
        let batch = RecordBatch::try_new(
            schema,
            vec![Arc::new(LargeStringArray::from(vec!["alice", "bob"]))],
        )
        .unwrap();

        let filter = ArrowRowFilter::NestedStringEquals {
            path: vec!["name".into()],
            value: "bob".into(),
        };
        let filtered = filter.apply(&batch).unwrap();
        assert_eq!(filtered.num_rows(), 1);
    }

    #[test]
    fn column_filters_to_arrow_converts_predicates() {
        let filters = vec![
            ColumnFilter::StringEquals {
                path: "actor.user.name".into(),
                value: "alice".into(),
            },
            ColumnFilter::RawSql("any_match(...)".into()),
        ];

        let result = column_filters_to_arrow(&filters);
        assert!(result.is_some(), "should produce a filter despite RawSql");
    }

    #[test]
    fn column_filters_to_arrow_all_raw_returns_none() {
        let filters = vec![ColumnFilter::RawSql("any_match(...)".into())];
        let result = column_filters_to_arrow(&filters);
        assert!(result.is_none());
    }

    /// Helper: build a batch with a `resources` column of type List<Struct{uid, type}>.
    fn resources_batch(rows: &[Option<Vec<(&str, &str)>>]) -> RecordBatch {
        use arrow_array::{
            RecordBatch,
            builder::{ListBuilder, StringBuilder, StructBuilder},
        };
        use arrow_schema::{Field, Fields, Schema};
        use std::sync::Arc;

        let uid_field = Field::new("uid", DataType::Utf8, true);
        let type_field = Field::new("type", DataType::Utf8, true);
        let struct_fields = Fields::from(vec![uid_field.clone(), type_field.clone()]);

        let mut list_builder = ListBuilder::new(StructBuilder::from_fields(
            struct_fields.clone(),
            rows.len(),
        ));

        for row in rows {
            match row {
                Some(elements) => {
                    let struct_builder = list_builder.values();
                    for (uid, typ) in elements {
                        struct_builder
                            .field_builder::<StringBuilder>(0)
                            .unwrap()
                            .append_value(uid);
                        struct_builder
                            .field_builder::<StringBuilder>(1)
                            .unwrap()
                            .append_value(typ);
                        struct_builder.append(true);
                    }
                    list_builder.append(true);
                }
                None => {
                    list_builder.append_null();
                }
            }
        }

        let list_arr = list_builder.finish();
        let struct_type = DataType::Struct(struct_fields);
        let list_type = DataType::List(Arc::new(Field::new_list_field(struct_type, true)));

        let schema = Arc::new(Schema::new(vec![Field::new("resources", list_type, true)]));

        RecordBatch::try_new(schema, vec![Arc::new(list_arr)]).unwrap()
    }

    #[test]
    fn list_contains_matches_single_element() {
        let batch = resources_batch(&[
            Some(vec![("arn:aws:s3:::bucket1", "AWS::S3::Bucket")]),
            Some(vec![(
                "arn:aws:ec2:us-west-2:123:instance/i-abc",
                "AWS::EC2::Instance",
            )]),
            Some(vec![
                ("arn:aws:s3:::bucket1", "AWS::S3::Bucket"),
                ("arn:aws:s3:::bucket2", "AWS::S3::Bucket"),
            ]),
        ]);

        let filter = ArrowRowFilter::ListContains {
            list_path: vec!["resources".into()],
            field: "uid".into(),
            value: "arn:aws:s3:::bucket1".into(),
        };
        let filtered = filter.apply(&batch).unwrap();
        assert_eq!(filtered.num_rows(), 2); // rows 0 and 2
    }

    #[test]
    fn list_contains_no_match() {
        let batch = resources_batch(&[
            Some(vec![("arn:aws:s3:::bucket1", "AWS::S3::Bucket")]),
            Some(vec![("arn:aws:s3:::bucket2", "AWS::S3::Bucket")]),
        ]);

        let filter = ArrowRowFilter::ListContains {
            list_path: vec!["resources".into()],
            field: "uid".into(),
            value: "arn:aws:s3:::nonexistent".into(),
        };
        let filtered = filter.apply(&batch).unwrap();
        assert_eq!(filtered.num_rows(), 0);
    }

    #[test]
    fn list_contains_handles_null_rows() {
        let batch = resources_batch(&[
            Some(vec![("arn:aws:s3:::bucket1", "AWS::S3::Bucket")]),
            None, // null list
            Some(vec![("arn:aws:s3:::bucket1", "AWS::S3::Bucket")]),
        ]);

        let filter = ArrowRowFilter::ListContains {
            list_path: vec!["resources".into()],
            field: "uid".into(),
            value: "arn:aws:s3:::bucket1".into(),
        };
        let filtered = filter.apply(&batch).unwrap();
        assert_eq!(filtered.num_rows(), 2);
    }

    #[test]
    fn list_contains_any_matches_multiple_values() {
        let batch = resources_batch(&[
            Some(vec![("arn:aws:s3:::bucket1", "AWS::S3::Bucket")]),
            Some(vec![("arn:aws:s3:::bucket2", "AWS::S3::Bucket")]),
            Some(vec![("arn:aws:s3:::bucket3", "AWS::S3::Bucket")]),
        ]);

        let filter = ArrowRowFilter::ListContainsAny {
            list_path: vec!["resources".into()],
            field: "uid".into(),
            values: vec!["arn:aws:s3:::bucket1".into(), "arn:aws:s3:::bucket3".into()],
        };
        let filtered = filter.apply(&batch).unwrap();
        assert_eq!(filtered.num_rows(), 2);
    }

    #[test]
    fn list_contains_empty_list_no_match() {
        let batch = resources_batch(&[Some(vec![])]);

        let filter = ArrowRowFilter::ListContains {
            list_path: vec!["resources".into()],
            field: "uid".into(),
            value: "arn:aws:s3:::bucket1".into(),
        };
        let filtered = filter.apply(&batch).unwrap();
        assert_eq!(filtered.num_rows(), 0);
    }

    #[test]
    fn column_filter_list_contains_converts_to_arrow() {
        let filters = vec![ColumnFilter::ListContains {
            list_path: "resources".into(),
            field: "uid".into(),
            value: "arn:aws:s3:::bucket1".into(),
        }];
        let result = column_filters_to_arrow(&filters);
        assert!(result.is_some());
    }
}
