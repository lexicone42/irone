//! DynamoDB-backed investigation metadata store.
//!
//! Stores investigation metadata (status, counts, timestamps) in `DynamoDB`.
//! Graph and timeline data live in S3 — this module only handles metadata.

use aws_sdk_dynamodb::types::AttributeValue;
use chrono::Utc;
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

/// Thin wrapper around `DynamoDB` client for investigation operations.
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

        Ok(result.item.and_then(|item| parse_item(&item)))
    }

    /// List all investigations, most recent first.
    pub async fn list_investigations(
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
                    if let Some(meta) = parse_item(item) {
                        items.push(meta);
                    }
                }
            }

            last_key = result.last_evaluated_key;
            if last_key.is_none() {
                break;
            }
        }

        // Sort by created_at descending
        items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(items)
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
}

/// Parse a `DynamoDB` item into `InvestigationMetadata`.
fn parse_item(
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
