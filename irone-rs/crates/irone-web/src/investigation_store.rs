//! DynamoDB-backed single-table store for investigations and detection runs.
//!
//! Uses a single-table design with `record_type` attribute to distinguish
//! entity types. The `type-created_at-index` GSI enables efficient listing
//! by record type (replacing full-table SCANs).
//!
//! | record_type      | id format     | GSI queries via                |
//! |------------------|---------------|--------------------------------|
//! | "investigation"  | `<uuid>`      | type-created_at, status-created_at |
//! | "detection_run"  | `dr#<uuid>`   | type-created_at               |

use aws_sdk_dynamodb::types::AttributeValue;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Investigation metadata stored in `DynamoDB`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationMetadata {
    pub id: String,
    pub name: String,
    pub status: String,
    pub rule_id: String,
    pub source_name: String,
    pub triggered: bool,
    pub match_count: usize,
    pub node_count: usize,
    pub edge_count: usize,
    pub created_at: String,
    pub updated_at: String,
    pub sfn_execution_arn: Option<String>,
    pub error: Option<String>,
}

/// Detection run record stored in `DynamoDB`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRunDynamo {
    pub run_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub triggered: bool,
    pub severity: String,
    pub match_count: usize,
    pub execution_time_ms: f64,
    pub executed_at: String,
    pub error: Option<String>,
    pub source_name: Option<String>,
    pub lookback_minutes: i64,
}

/// Maximum time an investigation can remain in "enriching" status before
/// being auto-reverted to "active" on read.
const ENRICHING_TIMEOUT_MINUTES: i64 = 60;

/// TTL for detection runs: 30 days in seconds.
const DETECTION_RUN_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;

/// GSI name for querying by record type + `created_at`.
const TYPE_INDEX: &str = "type-created_at-index";

/// Thin wrapper around `DynamoDB` client for the single-table store.
#[derive(Clone)]
pub struct DynamoInvestigationStore {
    client: aws_sdk_dynamodb::Client,
    table_name: String,
}

impl DynamoInvestigationStore {
    pub fn new(sdk_config: &aws_config::SdkConfig, table_name: String) -> Self {
        Self {
            client: aws_sdk_dynamodb::Client::new(sdk_config),
            table_name,
        }
    }

    // -------------------------------------------------------------------
    // Investigation operations
    // -------------------------------------------------------------------

    /// Create a new investigation record.
    pub async fn create_investigation(
        &self,
        meta: &InvestigationMetadata,
    ) -> Result<(), aws_sdk_dynamodb::Error> {
        let mut builder = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .item("id", AttributeValue::S(meta.id.clone()))
            .item("record_type", AttributeValue::S("investigation".into()))
            .item("name", AttributeValue::S(meta.name.clone()))
            .item("status", AttributeValue::S(meta.status.clone()))
            .item("rule_id", AttributeValue::S(meta.rule_id.clone()))
            .item("source_name", AttributeValue::S(meta.source_name.clone()))
            .item("triggered", AttributeValue::Bool(meta.triggered))
            .item(
                "match_count",
                AttributeValue::N(meta.match_count.to_string()),
            )
            .item("node_count", AttributeValue::N(meta.node_count.to_string()))
            .item("edge_count", AttributeValue::N(meta.edge_count.to_string()))
            .item("created_at", AttributeValue::S(meta.created_at.clone()))
            .item("updated_at", AttributeValue::S(meta.updated_at.clone()));

        if let Some(ref arn) = meta.sfn_execution_arn {
            builder = builder.item("sfn_execution_arn", AttributeValue::S(arn.clone()));
        }

        builder.send().await?;
        Ok(())
    }

    /// Update investigation status and optionally set counts.
    pub async fn update_status(
        &self,
        id: &str,
        status: &str,
        node_count: Option<usize>,
        edge_count: Option<usize>,
        error: Option<&str>,
    ) -> Result<(), aws_sdk_dynamodb::Error> {
        let now = Utc::now().to_rfc3339();

        let mut expr_parts = vec!["#status = :status", "updated_at = :updated_at"];
        let expr_names = vec![("#status".to_string(), "status".to_string())];
        let mut expr_values = vec![
            (":status".to_string(), AttributeValue::S(status.to_string())),
            (":updated_at".to_string(), AttributeValue::S(now)),
        ];

        if let Some(nc) = node_count {
            expr_parts.push("node_count = :nc");
            expr_values.push((":nc".to_string(), AttributeValue::N(nc.to_string())));
        }
        if let Some(ec) = edge_count {
            expr_parts.push("edge_count = :ec");
            expr_values.push((":ec".to_string(), AttributeValue::N(ec.to_string())));
        }
        if let Some(err) = error {
            expr_parts.push("error_message = :err");
            expr_values.push((":err".to_string(), AttributeValue::S(err.to_string())));
        }

        let update_expr = format!("SET {}", expr_parts.join(", "));

        let mut builder = self
            .client
            .update_item()
            .table_name(&self.table_name)
            .key("id", AttributeValue::S(id.to_string()))
            .update_expression(update_expr);

        for (name, val) in &expr_names {
            builder = builder.expression_attribute_names(name, val);
        }
        for (name, val) in expr_values {
            builder = builder.expression_attribute_values(name, val);
        }

        builder.send().await?;
        Ok(())
    }

    /// Get a single investigation by ID.
    ///
    /// If the investigation has been stuck in "enriching" status for longer
    /// than [`ENRICHING_TIMEOUT_MINUTES`], it is automatically reverted to "active".
    pub async fn get_investigation(
        &self,
        id: &str,
    ) -> Result<Option<InvestigationMetadata>, aws_sdk_dynamodb::Error> {
        let result = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key("id", AttributeValue::S(id.to_string()))
            .send()
            .await?;

        match result.item.and_then(|item| parse_investigation(&item)) {
            Some(mut meta) => {
                if self.recover_stale_enriching(&mut meta).await {
                    tracing::warn!(
                        investigation_id = %meta.id,
                        "auto-recovered stuck enriching investigation"
                    );
                }
                Ok(Some(meta))
            }
            None => Ok(None),
        }
    }

    /// List all investigations, most recent first.
    ///
    /// Uses the `type-created_at-index` GSI to query only investigation records
    /// (no full-table scan). Falls back to scan if the GSI isn't available yet
    /// (e.g., during migration).
    pub async fn list_investigations(
        &self,
    ) -> Result<Vec<InvestigationMetadata>, aws_sdk_dynamodb::Error> {
        let mut items = Vec::new();
        let mut last_key = None;

        loop {
            let mut builder = self
                .client
                .query()
                .table_name(&self.table_name)
                .index_name(TYPE_INDEX)
                .key_condition_expression("record_type = :rt")
                .expression_attribute_values(":rt", AttributeValue::S("investigation".into()))
                .scan_index_forward(false); // newest first

            if let Some(key) = last_key {
                builder = builder.set_exclusive_start_key(Some(key));
            }

            let Ok(result) = builder.send().await else {
                // GSI not yet available — fall back to scan
                tracing::warn!("type-created_at-index not available, falling back to scan");
                return self.list_investigations_scan().await;
            };

            if let Some(page_items) = result.items {
                for item in &page_items {
                    if let Some(mut meta) = parse_investigation(item) {
                        if self.recover_stale_enriching(&mut meta).await {
                            tracing::warn!(
                                investigation_id = %meta.id,
                                "auto-recovered stuck enriching investigation"
                            );
                        }
                        items.push(meta);
                    }
                }
            }

            last_key = result.last_evaluated_key;
            if last_key.is_none() {
                break;
            }
        }

        Ok(items)
    }

    /// Fallback scan for listing investigations (used when GSI isn't available).
    async fn list_investigations_scan(
        &self,
    ) -> Result<Vec<InvestigationMetadata>, aws_sdk_dynamodb::Error> {
        let mut items = Vec::new();
        let mut last_key = None;

        loop {
            let mut builder = self.client.scan().table_name(&self.table_name);

            if let Some(key) = last_key {
                builder = builder.set_exclusive_start_key(Some(key));
            }

            let result = builder.send().await?;

            if let Some(page_items) = result.items {
                for item in &page_items {
                    if let Some(mut meta) = parse_investigation(item) {
                        if self.recover_stale_enriching(&mut meta).await {
                            tracing::warn!(
                                investigation_id = %meta.id,
                                "auto-recovered stuck enriching investigation"
                            );
                        }
                        items.push(meta);
                    }
                }
            }

            last_key = result.last_evaluated_key;
            if last_key.is_none() {
                break;
            }
        }

        items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(items)
    }

    /// Check if an investigation is stuck in "enriching" and auto-recover to "active".
    async fn recover_stale_enriching(&self, meta: &mut InvestigationMetadata) -> bool {
        if meta.status != "enriching" {
            return false;
        }

        let is_stale = DateTime::parse_from_rfc3339(&meta.updated_at)
            .map(|updated| {
                let age = Utc::now() - updated.with_timezone(&Utc);
                age.num_minutes() > ENRICHING_TIMEOUT_MINUTES
            })
            .unwrap_or(true);

        if !is_stale {
            return false;
        }

        meta.status = "active".into();
        meta.error = Some("enrichment timed out after 1 hour".into());

        if let Err(e) = self
            .update_status(
                &meta.id,
                "active",
                None,
                None,
                Some("enrichment timed out after 1 hour"),
            )
            .await
        {
            tracing::error!(
                investigation_id = %meta.id,
                error = %e,
                "failed to update stale enriching status in DynamoDB"
            );
        }

        true
    }

    /// Delete an investigation record.
    pub async fn delete_investigation(&self, id: &str) -> Result<(), aws_sdk_dynamodb::Error> {
        self.client
            .delete_item()
            .table_name(&self.table_name)
            .key("id", AttributeValue::S(id.to_string()))
            .send()
            .await?;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Detection run operations
    // -------------------------------------------------------------------

    /// Save a detection run record to `DynamoDB` with 30-day TTL.
    pub async fn save_detection_run(
        &self,
        record: &DetectionRunDynamo,
    ) -> Result<(), aws_sdk_dynamodb::Error> {
        let ttl = Utc::now().timestamp() + DETECTION_RUN_TTL_SECONDS;

        let mut builder = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .item("id", AttributeValue::S(format!("dr#{}", record.run_id)))
            .item("record_type", AttributeValue::S("detection_run".into()))
            .item("created_at", AttributeValue::S(record.executed_at.clone()))
            .item("ttl", AttributeValue::N(ttl.to_string()))
            .item("run_id", AttributeValue::S(record.run_id.clone()))
            .item("rule_id", AttributeValue::S(record.rule_id.clone()))
            .item("rule_name", AttributeValue::S(record.rule_name.clone()))
            .item("triggered", AttributeValue::Bool(record.triggered))
            .item("severity", AttributeValue::S(record.severity.clone()))
            .item(
                "match_count",
                AttributeValue::N(record.match_count.to_string()),
            )
            .item(
                "execution_time_ms",
                AttributeValue::N(format!("{:.2}", record.execution_time_ms)),
            )
            .item("executed_at", AttributeValue::S(record.executed_at.clone()))
            .item(
                "lookback_minutes",
                AttributeValue::N(record.lookback_minutes.to_string()),
            );

        if let Some(ref err) = record.error {
            builder = builder.item("error_message", AttributeValue::S(err.clone()));
        }
        if let Some(ref src) = record.source_name {
            builder = builder.item("source_name", AttributeValue::S(src.clone()));
        }

        builder.send().await?;
        Ok(())
    }

    /// Save a batch of detection run records (up to 25 per `DynamoDB` batch).
    pub async fn save_detection_runs_batch(
        &self,
        records: &[DetectionRunDynamo],
    ) -> Result<(), aws_sdk_dynamodb::Error> {
        use aws_sdk_dynamodb::types::WriteRequest;

        let ttl = Utc::now().timestamp() + DETECTION_RUN_TTL_SECONDS;

        for chunk in records.chunks(25) {
            let requests: Vec<WriteRequest> = chunk
                .iter()
                .map(|record| {
                    let mut item = std::collections::HashMap::new();
                    item.insert(
                        "id".into(),
                        AttributeValue::S(format!("dr#{}", record.run_id)),
                    );
                    item.insert(
                        "record_type".into(),
                        AttributeValue::S("detection_run".into()),
                    );
                    item.insert(
                        "created_at".into(),
                        AttributeValue::S(record.executed_at.clone()),
                    );
                    item.insert("ttl".into(), AttributeValue::N(ttl.to_string()));
                    item.insert("run_id".into(), AttributeValue::S(record.run_id.clone()));
                    item.insert("rule_id".into(), AttributeValue::S(record.rule_id.clone()));
                    item.insert(
                        "rule_name".into(),
                        AttributeValue::S(record.rule_name.clone()),
                    );
                    item.insert("triggered".into(), AttributeValue::Bool(record.triggered));
                    item.insert(
                        "severity".into(),
                        AttributeValue::S(record.severity.clone()),
                    );
                    item.insert(
                        "match_count".into(),
                        AttributeValue::N(record.match_count.to_string()),
                    );
                    item.insert(
                        "execution_time_ms".into(),
                        AttributeValue::N(format!("{:.2}", record.execution_time_ms)),
                    );
                    item.insert(
                        "executed_at".into(),
                        AttributeValue::S(record.executed_at.clone()),
                    );
                    item.insert(
                        "lookback_minutes".into(),
                        AttributeValue::N(record.lookback_minutes.to_string()),
                    );
                    if let Some(ref err) = record.error {
                        item.insert("error_message".into(), AttributeValue::S(err.clone()));
                    }
                    if let Some(ref src) = record.source_name {
                        item.insert("source_name".into(), AttributeValue::S(src.clone()));
                    }

                    WriteRequest::builder()
                        .put_request(
                            aws_sdk_dynamodb::types::PutRequest::builder()
                                .set_item(Some(item))
                                .build()
                                .expect("valid put request"),
                        )
                        .build()
                })
                .collect();

            self.client
                .batch_write_item()
                .request_items(&self.table_name, requests)
                .send()
                .await?;
        }
        Ok(())
    }

    /// List recent detection runs, sorted newest first.
    ///
    /// Uses the `type-created_at-index` GSI for efficient querying.
    pub async fn list_detection_runs(
        &self,
        limit: usize,
        rule_id_filter: Option<&str>,
    ) -> Result<Vec<DetectionRunDynamo>, aws_sdk_dynamodb::Error> {
        let mut items = Vec::new();
        let mut last_key = None;
        let limit_i32 = i32::try_from(limit).unwrap_or(500);

        loop {
            let mut builder = self
                .client
                .query()
                .table_name(&self.table_name)
                .index_name(TYPE_INDEX)
                .key_condition_expression("record_type = :rt")
                .expression_attribute_values(":rt", AttributeValue::S("detection_run".into()))
                .scan_index_forward(false) // newest first
                .limit(limit_i32);

            if let Some(rule_id) = rule_id_filter {
                builder = builder
                    .filter_expression("rule_id = :rid")
                    .expression_attribute_values(":rid", AttributeValue::S(rule_id.into()));
            }

            if let Some(key) = last_key {
                builder = builder.set_exclusive_start_key(Some(key));
            }

            let result = builder.send().await?;

            if let Some(page_items) = result.items {
                for item in &page_items {
                    if let Some(record) = parse_detection_run(item) {
                        items.push(record);
                    }
                }
            }

            // Stop if we have enough items or no more pages
            last_key = result.last_evaluated_key;
            if last_key.is_none() || items.len() >= limit {
                break;
            }
        }

        items.truncate(limit);
        Ok(items)
    }
}

// ---------------------------------------------------------------------------
// DynamoDB item parsers
// ---------------------------------------------------------------------------

/// Parse a `DynamoDB` item into `InvestigationMetadata`.
fn parse_investigation(
    item: &std::collections::HashMap<String, AttributeValue>,
) -> Option<InvestigationMetadata> {
    Some(InvestigationMetadata {
        id: item.get("id")?.as_s().ok()?.clone(),
        name: item.get("name")?.as_s().ok()?.clone(),
        status: item.get("status")?.as_s().ok()?.clone(),
        rule_id: get_string(item, "rule_id"),
        source_name: get_string(item, "source_name"),
        triggered: item
            .get("triggered")
            .and_then(|v| v.as_bool().ok())
            .copied()
            .unwrap_or(false),
        match_count: get_number(item, "match_count"),
        node_count: get_number(item, "node_count"),
        edge_count: get_number(item, "edge_count"),
        created_at: get_string(item, "created_at"),
        updated_at: get_string(item, "updated_at"),
        sfn_execution_arn: item
            .get("sfn_execution_arn")
            .and_then(|v| v.as_s().ok())
            .cloned(),
        error: item
            .get("error_message")
            .and_then(|v| v.as_s().ok())
            .cloned(),
    })
}

/// Parse a `DynamoDB` item into a `DetectionRunDynamo`.
fn parse_detection_run(
    item: &std::collections::HashMap<String, AttributeValue>,
) -> Option<DetectionRunDynamo> {
    Some(DetectionRunDynamo {
        run_id: item.get("run_id")?.as_s().ok()?.clone(),
        rule_id: item.get("rule_id")?.as_s().ok()?.clone(),
        rule_name: item.get("rule_name")?.as_s().ok()?.clone(),
        triggered: item
            .get("triggered")
            .and_then(|v| v.as_bool().ok())
            .copied()
            .unwrap_or(false),
        severity: get_string(item, "severity"),
        match_count: get_number(item, "match_count"),
        execution_time_ms: item
            .get("execution_time_ms")
            .and_then(|v| v.as_n().ok())
            .and_then(|n| n.parse().ok())
            .unwrap_or(0.0),
        executed_at: get_string(item, "executed_at"),
        error: item
            .get("error_message")
            .and_then(|v| v.as_s().ok())
            .cloned(),
        source_name: item.get("source_name").and_then(|v| v.as_s().ok()).cloned(),
        lookback_minutes: item
            .get("lookback_minutes")
            .and_then(|v| v.as_n().ok())
            .and_then(|n| n.parse().ok())
            .unwrap_or(60),
    })
}

fn get_string(item: &std::collections::HashMap<String, AttributeValue>, key: &str) -> String {
    item.get(key)
        .and_then(|v| v.as_s().ok())
        .cloned()
        .unwrap_or_default()
}

fn get_number(item: &std::collections::HashMap<String, AttributeValue>, key: &str) -> usize {
    item.get(key)
        .and_then(|v| v.as_n().ok())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}
