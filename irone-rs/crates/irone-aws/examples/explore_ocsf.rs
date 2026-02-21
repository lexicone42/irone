//! Explore OCSF data in Security Lake via direct Iceberg reads.
//!
//! Usage: `cargo run -p irone-aws --example explore_ocsf --release`

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use irone_core::catalog::{DataSource, DataSourceType};
use irone_core::connectors::base::DataConnector;
use irone_core::connectors::ocsf::{OCSFEventClass, SecurityLakeQueries};
use std::collections::HashMap;

use irone_aws::iceberg::IcebergConnector;

const DB: &str = "amazon_security_lake_glue_db_us_west_2";

fn source(name: &str, table: &str) -> DataSource {
    DataSource {
        name: name.into(),
        source_type: DataSourceType::SecurityLake,
        description: String::new(),
        database: Some(DB.into()),
        table: Some(table.into()),
        s3_location: None,
        region: "us-west-2".into(),
        schema_fields: HashMap::new(),
        connector_class: None,
        connector_config: HashMap::new(),
        health_check_query: None,
        expected_freshness_minutes: 60,
        tags: vec!["security-lake".into()],
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info,irone_aws=debug")
        .init();

    let sdk = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-west-2"))
        .load()
        .await;

    let sources = vec![
        source(
            "cloudtrail",
            "amazon_security_lake_table_us_west_2_cloud_trail_mgmt_2_0",
        ),
        source(
            "lambda-execution",
            "amazon_security_lake_table_us_west_2_lambda_execution_2_0",
        ),
        source(
            "security-hub",
            "amazon_security_lake_table_us_west_2_sh_findings_2_0",
        ),
        source(
            "vpc-flow",
            "amazon_security_lake_table_us_west_2_vpc_flow_2_0",
        ),
        source(
            "route53",
            "amazon_security_lake_table_us_west_2_route53_2_0",
        ),
        source(
            "eks-audit",
            "amazon_security_lake_table_us_west_2_eks_audit_2_0",
        ),
    ];

    let now = Utc::now();
    let one_day_ago = now - Duration::days(1);

    println!("\n{}", "=".repeat(70));
    println!("  OCSF Data Explorer - Iceberg Direct Reads");
    println!(
        "  Time window: {} to {}",
        one_day_ago.format("%Y-%m-%d %H:%M"),
        now.format("%H:%M UTC")
    );
    println!("{}\n", "=".repeat(70));

    for src in &sources {
        println!(
            "\n--- {} ({}) ---",
            src.name,
            src.table.as_deref().unwrap_or("?")
        );

        let connector = match IcebergConnector::new(src.clone(), &sdk).await {
            Ok(c) => c,
            Err(e) => {
                println!("  SKIP: {e}");
                continue;
            }
        };

        // 1. Schema
        match connector.get_schema().await {
            Ok(schema) => {
                println!("  Schema: {} columns", schema.len());
                let mut cols: Vec<_> = schema.iter().collect();
                cols.sort_by_key(|(k, _)| (*k).clone());
                for (name, typ) in &cols {
                    println!("    {name}: {typ}");
                }
            }
            Err(e) => println!("  Schema error: {e}"),
        }

        // 2. Health check (last 1h)
        match connector.check_health().await {
            Ok(h) => {
                println!(
                    "  Health (1h): {} | {} records | {:.3}s",
                    if h.healthy { "HEALTHY" } else { "UNHEALTHY" },
                    h.record_count,
                    h.latency_seconds
                );
            }
            Err(e) => println!("  Health error: {e}"),
        }

        // 3. Sample data per event class (last 24h, 5 rows)
        let event_classes = [
            OCSFEventClass::ApiActivity,
            OCSFEventClass::Authentication,
            OCSFEventClass::NetworkActivity,
            OCSFEventClass::SecurityFinding,
        ];

        for ec in &event_classes {
            match connector
                .query_by_event_class(*ec, one_day_ago, now, 5, None)
                .await
            {
                Ok(qr) if !qr.is_empty() => {
                    println!(
                        "\n  Event class: {} (class_uid={}) - {} rows",
                        ec.name(),
                        ec.class_uid(),
                        qr.len()
                    );

                    if let Some(row) = qr.rows().first() {
                        println!("  Top-level keys:");
                        let mut keys: Vec<_> = row.keys().collect();
                        keys.sort();
                        for key in &keys {
                            let val = &row[*key];
                            let shape = describe_shape(val, 0);
                            println!("    {key}: {shape}");
                        }

                        // Show interesting nested fields
                        for nested_key in &[
                            "actor",
                            "api",
                            "src_endpoint",
                            "dst_endpoint",
                            "user",
                            "finding_info",
                            "resources",
                            "cloud",
                            "metadata",
                        ] {
                            print_nested(row, nested_key, 2);
                        }
                    }
                }
                Ok(_) => {} // empty, skip
                Err(e) => println!("  {}: error: {e}", ec.name()),
            }
        }

        // 4. Event summary (24h)
        match connector.get_event_summary(one_day_ago, now).await {
            Ok(qr) if !qr.is_empty() => {
                println!("\n  Event summary (24h):");
                for row in qr.rows() {
                    let uid = row
                        .get("class_uid")
                        .map(std::string::ToString::to_string)
                        .unwrap_or_default();
                    let name = row
                        .get("class_name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("?");
                    let count = row
                        .get("event_count")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                    println!("    class_uid={uid} ({name}): {count} events");
                }
            }
            Ok(_) => println!("  Event summary: no data in 24h"),
            Err(e) => println!("  Event summary error: {e}"),
        }
    }

    println!("\n{}", "=".repeat(70));
    println!("  Exploration complete.");
    println!("{}", "=".repeat(70));
}

fn describe_shape(val: &serde_json::Value, depth: usize) -> String {
    match val {
        serde_json::Value::Null => "null".into(),
        serde_json::Value::Bool(_) => "bool".into(),
        serde_json::Value::Number(n) => {
            if n.is_i64() {
                format!("int({n})")
            } else {
                format!("float({n})")
            }
        }
        serde_json::Value::String(s) => {
            if s.len() > 60 {
                format!("str(\"{}...\")", &s[..57])
            } else {
                format!("str({s:?})")
            }
        }
        serde_json::Value::Array(arr) => {
            if arr.is_empty() {
                "[]".into()
            } else {
                let inner = describe_shape(&arr[0], depth + 1);
                format!("[{inner}; len={}]", arr.len())
            }
        }
        serde_json::Value::Object(map) => {
            if depth > 2 {
                format!("{{...{} keys}}", map.len())
            } else {
                let keys: Vec<_> = map.keys().take(5).cloned().collect();
                let suffix = if map.len() > 5 {
                    format!(", +{}", map.len() - 5)
                } else {
                    String::new()
                };
                format!("{{{}{suffix}}}", keys.join(", "))
            }
        }
    }
}

fn print_nested(row: &serde_json::Map<String, serde_json::Value>, key: &str, indent: usize) {
    if let Some(val) = row.get(key)
        && (val.is_object() || val.is_array())
    {
        let pad = " ".repeat(indent * 2);
        let pretty = serde_json::to_string_pretty(val).unwrap_or_default();
        if pretty.len() > 800 {
            println!("{pad}{key} (nested, truncated):");
            for line in pretty.lines().take(20) {
                println!("{pad}  {line}");
            }
            println!("{pad}  ... ({} chars total)", pretty.len());
        } else {
            println!("{pad}{key}:");
            for line in pretty.lines() {
                println!("{pad}  {line}");
            }
        }
    }
}
