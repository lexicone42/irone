//! Benchmark test for scan path optimizations.
//!
//! Creates realistic OCSF-shaped Parquet data (nested structs, 20 columns,
//! 10K rows) and measures the three scan paths:
//! 1. Full scan (all columns, full JSON materialization)
//! 2. Projected scan (only filter columns decoded)
//! 3. Zero-materialization (count + small sample only)
//!
//! Run with: cargo test -p irone-aws --test scan_benchmark -- --nocapture

use std::sync::Arc;
use std::time::Instant;

use arrow_array::{Int32Array, RecordBatch, StringArray, StructArray};
use arrow_schema::{DataType, Field, Schema};
use bytes::Bytes;

/// Number of rows in the benchmark dataset.
const ROW_COUNT: usize = 10_000;

/// Build a realistic OCSF-like schema with nested structs.
fn build_ocsf_schema() -> Arc<Schema> {
    let name_field = Field::new("name", DataType::Utf8, true);
    let type_field = Field::new("type", DataType::Utf8, true);
    let user_type = DataType::Struct(vec![name_field, type_field].into());
    let user_field = Field::new("user", user_type, true);
    let actor_type = DataType::Struct(vec![user_field].into());

    let op_field = Field::new("operation", DataType::Utf8, true);
    let svc_field = Field::new("service_name", DataType::Utf8, true);
    let api_type = DataType::Struct(vec![op_field, svc_field].into());

    let ip_field = Field::new("ip", DataType::Utf8, true);
    let endpoint_type = DataType::Struct(vec![ip_field].into());

    let mut fields = vec![
        Field::new("class_uid", DataType::Int32, false),
        Field::new("actor", actor_type, true),
        Field::new("api", api_type, true),
        Field::new("src_endpoint", endpoint_type, true),
        Field::new("status", DataType::Utf8, true),
    ];

    // 15 padding columns to simulate real OCSF width
    for i in 0..15 {
        fields.push(Field::new(format!("pad_{i}"), DataType::Utf8, true));
    }

    Arc::new(Schema::new(fields))
}

fn build_ocsf_batch(schema: &Arc<Schema>, n: usize) -> RecordBatch {
    let operations = [
        "AssumeRole",
        "GetCallerIdentity",
        "ListBuckets",
        "AttachUserPolicy",
        "PutRolePolicy",
        "CreateAccessKey",
        "ConsoleLogin",
        "StopLogging",
    ];
    let services = [
        "sts.amazonaws.com",
        "iam.amazonaws.com",
        "s3.amazonaws.com",
        "cloudtrail.amazonaws.com",
    ];
    let users = ["alice", "bob", "root", "ci-deploy", "config-service"];
    let user_types = ["IAMUser", "Root", "AssumedRole", "AWSService"];
    let ips = ["10.0.1.15", "198.51.100.1", "203.0.113.55", "172.16.0.1"];

    let class_uids = Int32Array::from(vec![6003; n]);

    // actor.user.{name, type}
    let actor_names: Vec<&str> = (0..n).map(|i| users[i % users.len()]).collect();
    let actor_types: Vec<&str> = (0..n).map(|i| user_types[i % user_types.len()]).collect();

    let name_field = Field::new("name", DataType::Utf8, true);
    let type_field = Field::new("type", DataType::Utf8, true);
    let user_struct = StructArray::from(vec![
        (
            Arc::new(name_field) as Arc<Field>,
            Arc::new(StringArray::from(actor_names)) as Arc<dyn arrow_array::Array>,
        ),
        (
            Arc::new(type_field) as Arc<Field>,
            Arc::new(StringArray::from(actor_types)) as Arc<dyn arrow_array::Array>,
        ),
    ]);

    let user_field = Field::new(
        "user",
        DataType::Struct(
            vec![
                Field::new("name", DataType::Utf8, true),
                Field::new("type", DataType::Utf8, true),
            ]
            .into(),
        ),
        true,
    );
    let actor_struct = StructArray::from(vec![(
        Arc::new(user_field) as Arc<Field>,
        Arc::new(user_struct) as Arc<dyn arrow_array::Array>,
    )]);

    // api.{operation, service_name}
    let op_vals: Vec<&str> = (0..n).map(|i| operations[i % operations.len()]).collect();
    let svc_vals: Vec<&str> = (0..n).map(|i| services[i % services.len()]).collect();

    let op_field = Field::new("operation", DataType::Utf8, true);
    let svc_field = Field::new("service_name", DataType::Utf8, true);
    let api_struct = StructArray::from(vec![
        (
            Arc::new(op_field) as Arc<Field>,
            Arc::new(StringArray::from(op_vals)) as Arc<dyn arrow_array::Array>,
        ),
        (
            Arc::new(svc_field) as Arc<Field>,
            Arc::new(StringArray::from(svc_vals)) as Arc<dyn arrow_array::Array>,
        ),
    ]);

    // src_endpoint.ip
    let ip_vals: Vec<&str> = (0..n).map(|i| ips[i % ips.len()]).collect();
    let ip_field = Field::new("ip", DataType::Utf8, true);
    let endpoint_struct = StructArray::from(vec![(
        Arc::new(ip_field) as Arc<Field>,
        Arc::new(StringArray::from(ip_vals)) as Arc<dyn arrow_array::Array>,
    )]);

    // status
    let statuses: Vec<&str> = (0..n)
        .map(|i| if i % 10 == 0 { "Failure" } else { "Success" })
        .collect();
    let status_arr = StringArray::from(statuses);

    // padding columns
    let pad_val = "x".repeat(50);
    let pad_vals: Vec<&str> = vec![pad_val.as_str(); n];

    let mut columns: Vec<Arc<dyn arrow_array::Array>> = vec![
        Arc::new(class_uids),
        Arc::new(actor_struct),
        Arc::new(api_struct),
        Arc::new(endpoint_struct),
        Arc::new(status_arr),
    ];

    for _ in 0..15 {
        columns.push(Arc::new(StringArray::from(pad_vals.clone())));
    }

    RecordBatch::try_new(schema.clone(), columns).unwrap()
}

fn to_parquet(schema: &Arc<Schema>, batch: &RecordBatch) -> Bytes {
    let mut buf = Vec::new();
    let mut writer = parquet::arrow::ArrowWriter::try_new(&mut buf, schema.clone(), None).unwrap();
    writer.write(batch).unwrap();
    writer.close().unwrap();
    Bytes::from(buf)
}

#[test]
fn scan_path_benchmark() {
    let schema = build_ocsf_schema();
    let batch = build_ocsf_batch(&schema, ROW_COUNT);
    let parquet_bytes = to_parquet(&schema, &batch);
    let col_count = schema.fields().len();

    let sep = "=".repeat(60);
    eprintln!("\n{sep}");
    eprintln!("  SCAN PATH BENCHMARK ({ROW_COUNT} rows, {col_count} columns)");
    eprintln!(
        "  Parquet size: {:.1} KB",
        parquet_bytes.len() as f64 / 1024.0
    );
    eprintln!("{sep}\n");

    // ── 1. Full scan (no projection, no filter) ──────────────────────
    let t = Instant::now();
    let batches =
        irone_aws::iceberg_test_utils::read_parquet_bytes_pub(&parquet_bytes, ROW_COUNT, None)
            .unwrap();
    let full_decode_ms = t.elapsed().as_secs_f64() * 1000.0;
    let full_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    let full_cols = batches[0].num_columns();

    let t = Instant::now();
    let qr = irone_aws::arrow_convert::record_batches_to_query_result(&batches);
    let full_materialize_ms = t.elapsed().as_secs_f64() * 1000.0;

    eprintln!("1. FULL SCAN (all {full_cols} columns, full materialization)");
    eprintln!(
        "   Parquet decode:       {full_decode_ms:>8.2} ms ({full_rows} rows, {full_cols} cols)"
    );
    eprintln!(
        "   JSON materialization: {full_materialize_ms:>8.2} ms ({} JSON maps)",
        qr.len()
    );
    eprintln!(
        "   TOTAL:                {:>8.2} ms\n",
        full_decode_ms + full_materialize_ms
    );

    // ── 2. Projected scan (only filter-relevant columns) ─────────────
    let proj = vec![
        "class_uid".to_string(),
        "actor".to_string(),
        "api".to_string(),
    ];
    let t = Instant::now();
    let batches = irone_aws::iceberg_test_utils::read_parquet_bytes_pub(
        &parquet_bytes,
        ROW_COUNT,
        Some(&proj),
    )
    .unwrap();
    let proj_decode_ms = t.elapsed().as_secs_f64() * 1000.0;
    let proj_cols = batches[0].num_columns();

    let t = Instant::now();
    let qr = irone_aws::arrow_convert::record_batches_to_query_result(&batches);
    let proj_materialize_ms = t.elapsed().as_secs_f64() * 1000.0;

    eprintln!("2. PROJECTED SCAN ({proj_cols} of {full_cols} columns, full materialization)");
    eprintln!(
        "   Parquet decode:       {proj_decode_ms:>8.2} ms ({full_rows} rows, {proj_cols} cols)"
    );
    eprintln!(
        "   JSON materialization: {proj_materialize_ms:>8.2} ms ({} JSON maps)",
        qr.len()
    );
    eprintln!(
        "   TOTAL:                {:>8.2} ms",
        proj_decode_ms + proj_materialize_ms
    );
    eprintln!(
        "   vs full:              {:.0}% decode, {:.0}% materialize\n",
        proj_decode_ms / full_decode_ms * 100.0,
        proj_materialize_ms / full_materialize_ms * 100.0
    );

    // ── 3. Zero-materialization (count + 100-row sample) ─────────────
    let sample_size = 100;
    let t = Instant::now();
    let batches = irone_aws::iceberg_test_utils::read_parquet_bytes_pub(
        &parquet_bytes,
        ROW_COUNT,
        Some(&proj),
    )
    .unwrap();
    let zm_decode_ms = t.elapsed().as_secs_f64() * 1000.0;
    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();

    let t = Instant::now();
    let mut sample_batches: Vec<RecordBatch> = Vec::new();
    let mut sample_rows = 0;
    for b in &batches {
        if sample_rows >= sample_size {
            break;
        }
        let take = (sample_size - sample_rows).min(b.num_rows());
        if take < b.num_rows() {
            sample_batches.push(b.slice(0, take));
        } else {
            sample_batches.push(b.clone());
        }
        sample_rows += take;
    }
    let sample_qr = irone_aws::arrow_convert::record_batches_to_query_result(&sample_batches);
    let zm_materialize_ms = t.elapsed().as_secs_f64() * 1000.0;

    let zm_total = zm_decode_ms + zm_materialize_ms;
    let full_total = full_decode_ms + full_materialize_ms;
    let proj_total = proj_decode_ms + proj_materialize_ms;

    eprintln!("3. ZERO-MATERIALIZATION ({proj_cols} cols, {sample_size}-row sample)");
    eprintln!(
        "   Parquet decode:       {zm_decode_ms:>8.2} ms ({total_rows} rows, {proj_cols} cols)"
    );
    eprintln!(
        "   Sample materialize:   {zm_materialize_ms:>8.2} ms ({} of {total_rows} rows)",
        sample_qr.len()
    );
    eprintln!("   TOTAL:                {zm_total:>8.2} ms");
    eprintln!(
        "   vs full scan:         {:.1}x faster\n",
        full_total / zm_total
    );

    // ── Summary ──────────────────────────────────────────────────────
    eprintln!("SUMMARY:");
    eprintln!("   Full scan total:      {full_total:>8.2} ms");
    eprintln!(
        "   Projected total:      {proj_total:>8.2} ms ({:.0}% of full)",
        proj_total / full_total * 100.0
    );
    eprintln!(
        "   Zero-mat total:       {zm_total:>8.2} ms ({:.0}% of full)",
        zm_total / full_total * 100.0
    );
    let sep2 = "-".repeat(60);
    eprintln!("{sep2}");
    eprintln!(
        "   DECODE saved:         {:.2} ms ({:.0}%)",
        full_decode_ms - proj_decode_ms,
        (1.0 - proj_decode_ms / full_decode_ms) * 100.0
    );
    eprintln!(
        "   MATERIALIZE saved:    {:.2} ms ({:.0}%)",
        full_materialize_ms - zm_materialize_ms,
        (1.0 - zm_materialize_ms / full_materialize_ms) * 100.0
    );
    eprintln!(
        "   TOTAL saved:          {:.2} ms ({:.0}%)\n",
        full_total - zm_total,
        (1.0 - zm_total / full_total) * 100.0
    );

    // Sanity
    assert_eq!(full_rows, ROW_COUNT);
    assert_eq!(total_rows, ROW_COUNT);
    assert!(sample_qr.len() <= sample_size);
}
