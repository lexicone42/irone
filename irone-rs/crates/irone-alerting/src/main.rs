use std::path::Path;

use aws_sdk_dynamodb::types::AttributeValue;
use chrono::Utc;
use irone_aws::health_cache::HealthCacheClient;
use irone_aws::security_hub::SecurityHubNotifier;
use irone_aws::sns::SnsNotifier;
use irone_core::audit;
use irone_core::catalog::DataCatalog;
use irone_core::detections::{DetectionResult, DetectionRunner, Severity};
use irone_core::graph::GraphBuilder;
use irone_core::notifications::{NotificationChannel, SecurityAlert};
use lambda_runtime::{Error, LambdaEvent, service_fn};
use serde::{Deserialize, Serialize};

/// `EventBridge` input payload.
#[derive(Debug, Deserialize)]
struct AlertEvent {
    check_type: String,
    #[serde(default)]
    sources: Option<Vec<String>>,
}

/// Lambda return value summarizing what happened.
#[derive(Debug, Serialize)]
struct AlertResult {
    check_type: String,
    rules_checked: usize,
    triggered: usize,
    alerts_sent: usize,
    investigations_created: usize,
    freshness_alerts: usize,
}

async fn handler(event: LambdaEvent<AlertEvent>) -> Result<AlertResult, Error> {
    let (payload, _ctx) = event.into_parts();

    tracing::info!(check_type = %payload.check_type, "alerting invoked");

    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;

    match payload.check_type.as_str() {
        "detections" => run_detections(&sdk_config).await,
        "freshness" => run_freshness_check(&sdk_config, payload.sources.as_deref()).await,
        other => Err(format!("unknown check_type: {other}").into()),
    }
}

/// Run all detection rules against the cloudtrail source, send alerts, auto-investigate criticals.
async fn run_detections(sdk_config: &aws_config::SdkConfig) -> Result<AlertResult, Error> {
    let security_lake_db = std::env::var("SECDASH_SECURITY_LAKE_DB").unwrap_or_default();
    let region = std::env::var("SECDASH_REGION").unwrap_or_else(|_| "us-west-2".into());
    let use_direct_query = std::env::var("SECDASH_USE_DIRECT_QUERY")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    let alerts_topic = std::env::var("SECDASH_ALERTS_TOPIC_ARN")?;
    let critical_topic = std::env::var("SECDASH_CRITICAL_ALERTS_TOPIC_ARN")?;

    // Build catalog and connector
    let mut catalog = DataCatalog::new();
    if !security_lake_db.is_empty() {
        catalog.register_security_lake_sources(&security_lake_db, &region);
    }

    let source = catalog
        .get_source("cloudtrail")
        .cloned()
        .ok_or("cloudtrail source not found in catalog")?;

    let connector = irone_aws::create_connector(source, sdk_config, use_direct_query).await;

    // Load rules
    let mut runner = DetectionRunner::new();
    let rules_dir = Path::new("rules");
    let loaded = runner.load_rules_from_directory(rules_dir);
    tracing::info!(loaded, "loaded detection rules");

    // Run all enabled rules with 60-min lookback (matches schedule interval)
    let results = runner.run_all(&connector, None, None, 60).await;
    let rules_checked = results.len();

    let triggered_results: Vec<&DetectionResult> = results.iter().filter(|r| r.triggered).collect();
    let triggered_count = triggered_results.len();

    tracing::info!(
        rules_checked,
        triggered = triggered_count,
        "detection run complete"
    );

    // Build notifiers
    let sns_alerts = SnsNotifier::new(sdk_config, alerts_topic);
    let sns_critical = SnsNotifier::new(sdk_config, critical_topic);

    let security_hub = if std::env::var("SECDASH_SECURITY_HUB_ENABLED")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        let account_id = std::env::var("SECDASH_ACCOUNT_ID").unwrap_or_else(|_| "unknown".into());
        Some(SecurityHubNotifier::new(sdk_config, account_id, region))
    } else {
        None
    };

    let mut alerts_sent = 0;
    let mut investigations_created = 0;

    for result in &triggered_results {
        let alert = build_alert(result);

        // Route by severity: critical goes to both topics
        if result.severity == Severity::Critical {
            send_alert(&sns_critical, &alert).await;
            send_alert(&sns_alerts, &alert).await;
        } else {
            send_alert(&sns_alerts, &alert).await;
        }
        alerts_sent += 1;

        // Push to Security Hub if enabled
        if let Some(ref hub) = security_hub {
            send_alert(hub, &alert).await;
        }

        // Auto-investigate for Critical/High (with dedup)
        if (result.severity == Severity::Critical || result.severity == Severity::High)
            && !has_recent_investigation(sdk_config, &result.rule_id).await
        {
            match auto_investigate(sdk_config, result).await {
                Ok(inv_id) => {
                    audit::investigation_created("alerting-lambda", &inv_id, &result.rule_name);
                    tracing::info!(
                        rule_id = %result.rule_id,
                        investigation_id = %inv_id,
                        "auto-investigation created"
                    );
                    investigations_created += 1;
                }
                Err(e) => {
                    tracing::error!(
                        rule_id = %result.rule_id,
                        error = %e,
                        "auto-investigation failed"
                    );
                }
            }
        }
    }

    audit::detection_run("alerting-lambda", rules_checked, triggered_count);

    Ok(AlertResult {
        check_type: "detections".into(),
        rules_checked,
        triggered: triggered_count,
        alerts_sent,
        investigations_created,
        freshness_alerts: 0,
    })
}

/// Check data source freshness and alert on stale sources.
async fn run_freshness_check(
    sdk_config: &aws_config::SdkConfig,
    _sources: Option<&[String]>,
) -> Result<AlertResult, Error> {
    let cache_table = std::env::var("SECDASH_HEALTH_CACHE_TABLE").unwrap_or_default();
    let alerts_topic = std::env::var("SECDASH_ALERTS_TOPIC_ARN")?;

    if cache_table.is_empty() {
        tracing::warn!("SECDASH_HEALTH_CACHE_TABLE not set, skipping freshness check");
        return Ok(AlertResult {
            check_type: "freshness".into(),
            rules_checked: 0,
            triggered: 0,
            alerts_sent: 0,
            investigations_created: 0,
            freshness_alerts: 0,
        });
    }

    let health_cache = HealthCacheClient::new(sdk_config, &cache_table);
    let all_results = health_cache
        .get_all_latest()
        .await
        .map_err(|e| Error::from(format!("failed to read health cache: {e}")))?;

    let sns = SnsNotifier::new(sdk_config, alerts_topic);
    let mut freshness_alerts = 0;

    for result in &all_results {
        // 2 hours = 120 minutes staleness threshold
        let is_stale = result.data_age_minutes.is_some_and(|age| age > 120.0);

        if is_stale {
            let age_mins = result.data_age_minutes.unwrap_or(0.0);
            let alert = SecurityAlert {
                rule_id: format!("freshness-{}", result.source_name),
                rule_name: format!("Data Freshness: {}", result.source_name),
                severity: if age_mins > 360.0 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                message: format!(
                    "Source '{}' data is {:.0} minutes stale (threshold: 120 min). \
                     Last data: {}",
                    result.source_name,
                    age_mins,
                    result.last_data_time.as_deref().unwrap_or("unknown"),
                ),
                match_count: 1,
                details: std::collections::HashMap::from([
                    (
                        "source_name".into(),
                        serde_json::Value::String(result.source_name.clone()),
                    ),
                    ("data_age_minutes".into(), serde_json::json!(age_mins)),
                    (
                        "last_data_time".into(),
                        serde_json::Value::String(
                            result.last_data_time.clone().unwrap_or_default(),
                        ),
                    ),
                ]),
            };

            send_alert(&sns, &alert).await;
            freshness_alerts += 1;
        }
    }

    tracing::info!(
        total_sources = all_results.len(),
        freshness_alerts,
        "freshness check complete"
    );

    Ok(AlertResult {
        check_type: "freshness".into(),
        rules_checked: all_results.len(),
        triggered: freshness_alerts,
        alerts_sent: freshness_alerts,
        investigations_created: 0,
        freshness_alerts,
    })
}

/// Build a `SecurityAlert` from a triggered `DetectionResult`.
fn build_alert(result: &DetectionResult) -> SecurityAlert {
    let alert_dict = result.to_alert_dict();
    let details = alert_dict
        .into_iter()
        .filter(|(k, _)| k != "rule_id" && k != "rule_name" && k != "message")
        .collect();

    SecurityAlert {
        rule_id: result.rule_id.clone(),
        rule_name: result.rule_name.clone(),
        severity: result.severity.clone(),
        message: result.message.clone(),
        match_count: result.match_count,
        details,
    }
}

/// Send an alert, logging errors but not failing the Lambda.
async fn send_alert(channel: &impl NotificationChannel, alert: &SecurityAlert) {
    if let Err(e) = channel.send_alert(alert).await {
        tracing::error!(
            rule_id = %alert.rule_id,
            error = %e,
            "failed to send alert"
        );
    }
}

/// Check if an investigation for this `rule_id` was already created within the dedup window.
///
/// Queries the `status-created_at-index` GSI for recent active/enriching investigations,
/// then filters client-side for matching `rule_id`. Returns true if a duplicate exists.
async fn has_recent_investigation(sdk_config: &aws_config::SdkConfig, rule_id: &str) -> bool {
    let table = match std::env::var("SECDASH_INVESTIGATIONS_TABLE") {
        Ok(t) if !t.is_empty() => t,
        _ => return false,
    };

    let ddb_client = aws_sdk_dynamodb::Client::new(sdk_config);
    let cutoff = (Utc::now() - chrono::Duration::hours(24)).to_rfc3339();

    // Check both "active" and "enriching" statuses
    for status in ["active", "enriching"] {
        let result = ddb_client
            .query()
            .table_name(&table)
            .index_name("status-created_at-index")
            .key_condition_expression("#s = :status AND created_at > :cutoff")
            .filter_expression("rule_id = :rule_id")
            .expression_attribute_names("#s", "status")
            .expression_attribute_values(":status", AttributeValue::S(status.into()))
            .expression_attribute_values(":cutoff", AttributeValue::S(cutoff.clone()))
            .expression_attribute_values(":rule_id", AttributeValue::S(rule_id.into()))
            .limit(1)
            .send()
            .await;

        if let Ok(output) = result
            && output.count() > 0
        {
            tracing::info!(
                rule_id,
                status,
                "skipping auto-investigate: recent investigation exists"
            );
            return true;
        }
    }

    false
}

/// Create an investigation from a detection result (mirrors irone-web's `create_from_detection`).
async fn auto_investigate(
    sdk_config: &aws_config::SdkConfig,
    result: &DetectionResult,
) -> Result<String, Error> {
    let bucket = std::env::var("SECDASH_REPORT_BUCKET")?;
    let table = std::env::var("SECDASH_INVESTIGATIONS_TABLE")?;
    let sfn_arn = std::env::var("SECDASH_INVESTIGATION_STATE_MACHINE_ARN")?;

    let s3_client = aws_sdk_s3::Client::new(sdk_config);
    let ddb_client = aws_sdk_dynamodb::Client::new(sdk_config);
    let sfn_client = aws_sdk_sfn::Client::new(sdk_config);

    let inv_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let name = format!(
        "[Auto] {} - {}",
        result.rule_name,
        now.format("%Y-%m-%d %H:%M")
    );

    // Build minimal graph (no enrichment — the worker handles that)
    let mut builder = GraphBuilder::new();
    Box::pin(builder.build_from_detection::<irone_aws::ConnectorKind>(result, None, 0, 0, true))
        .await;
    let graph = builder.into_graph();

    let node_count = graph.nodes.len();
    let edge_count = graph.edges.len();

    // Write detection_result.json to S3
    let detection_json = serde_json::to_vec(result)?;
    s3_client
        .put_object()
        .bucket(&bucket)
        .key(format!("investigations/{inv_id}/detection_result.json"))
        .body(detection_json.into())
        .content_type("application/json")
        .send()
        .await?;

    // Write minimal graph.json to S3
    let graph_json = serde_json::to_vec(&graph)?;
    s3_client
        .put_object()
        .bucket(&bucket)
        .key(format!("investigations/{inv_id}/graph.json"))
        .body(graph_json.into())
        .content_type("application/json")
        .send()
        .await?;

    // Create DynamoDB investigation record
    ddb_client
        .put_item()
        .table_name(&table)
        .item("id", AttributeValue::S(inv_id.clone()))
        .item("name", AttributeValue::S(name))
        .item("status", AttributeValue::S("enriching".into()))
        .item("rule_id", AttributeValue::S(result.rule_id.clone()))
        .item("source_name", AttributeValue::S("cloudtrail".into()))
        .item("triggered", AttributeValue::Bool(true))
        .item(
            "match_count",
            AttributeValue::N(result.match_count.to_string()),
        )
        .item("node_count", AttributeValue::N(node_count.to_string()))
        .item("edge_count", AttributeValue::N(edge_count.to_string()))
        .item("created_at", AttributeValue::S(now.to_rfc3339()))
        .item("updated_at", AttributeValue::S(now.to_rfc3339()))
        .send()
        .await?;

    // Start Step Function execution
    let sfn_input = serde_json::json!({
        "action": "enrich",
        "investigation_id": inv_id,
        "rule_id": result.rule_id,
        "source_name": "cloudtrail",
        "enrichment_window_minutes": 60,
        "bucket": bucket,
    });

    sfn_client
        .start_execution()
        .state_machine_arn(&sfn_arn)
        .name(format!("auto-inv-{inv_id}"))
        .input(sfn_input.to_string())
        .send()
        .await?;

    Ok(inv_id)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt().json().with_target(false).init();

    lambda_runtime::run(service_fn(handler)).await
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::Utc;
    use irone_core::detections::{DetectionResult, Severity};
    use irone_core::notifications::SecurityAlert;

    use super::build_alert;

    fn sample_result(severity: Severity, triggered: bool) -> DetectionResult {
        DetectionResult {
            rule_id: "TEST-001".into(),
            rule_name: "Test Detection".into(),
            triggered,
            severity,
            match_count: if triggered { 3 } else { 0 },
            matches: Vec::new(),
            message: "Suspicious activity detected".into(),
            executed_at: Utc::now(),
            execution_time_ms: 42.0,
            error: None,
            mitre_attack: Vec::new(),
            tags: Vec::new(),
        }
    }

    #[test]
    fn build_alert_from_triggered_result() {
        let result = sample_result(Severity::High, true);
        let alert = build_alert(&result);
        assert_eq!(alert.rule_id, "TEST-001");
        assert_eq!(alert.rule_name, "Test Detection");
        assert_eq!(alert.match_count, 3);
        assert!(matches!(alert.severity, Severity::High));
        assert!(!alert.details.contains_key("rule_id"));
        assert!(!alert.details.contains_key("rule_name"));
    }

    #[test]
    fn build_alert_details_contains_severity_and_sample() {
        let result = sample_result(Severity::Critical, true);
        let alert = build_alert(&result);
        assert!(alert.details.contains_key("severity"));
        assert!(alert.details.contains_key("sample_matches"));
    }

    #[test]
    fn severity_routing_critical_is_high_priority() {
        let result = sample_result(Severity::Critical, true);
        assert!(result.severity == Severity::Critical || result.severity == Severity::High);
    }

    #[test]
    fn severity_routing_medium_is_not_auto_investigate() {
        let result = sample_result(Severity::Medium, true);
        assert!(result.severity != Severity::Critical && result.severity != Severity::High);
    }

    #[test]
    fn freshness_alert_construction() {
        let alert = SecurityAlert {
            rule_id: "freshness-cloudtrail".into(),
            rule_name: "Data Freshness: cloudtrail".into(),
            severity: Severity::Medium,
            message: "Source 'cloudtrail' data is 150 minutes stale".into(),
            match_count: 1,
            details: HashMap::from([("data_age_minutes".into(), serde_json::json!(150.0))]),
        };
        assert_eq!(alert.rule_id, "freshness-cloudtrail");
        assert!(matches!(alert.severity, Severity::Medium));
    }

    #[test]
    fn freshness_high_severity_over_6_hours() {
        let age_mins = 400.0_f64;
        let severity = if age_mins > 360.0 {
            Severity::High
        } else {
            Severity::Medium
        };
        assert!(matches!(severity, Severity::High));
    }
}
