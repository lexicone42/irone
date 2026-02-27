use std::collections::HashMap;

use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::connectors::ocsf::{OCSFEventClass, get_nested_value};
use crate::connectors::result::QueryResult;

/// Detection severity levels.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Result of running a detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub rule_id: String,
    pub rule_name: String,
    pub triggered: bool,
    pub severity: Severity,
    pub match_count: usize,
    pub matches: Vec<serde_json::Map<String, Value>>,
    pub message: String,
    pub executed_at: DateTime<Utc>,
    pub execution_time_ms: f64,
    pub error: Option<String>,
    /// MITRE ATT&CK technique IDs from the detection rule (e.g. `["T1110"]`).
    #[serde(default)]
    pub mitre_attack: Vec<String>,
    /// Tags from the detection rule.
    #[serde(default)]
    pub tags: Vec<String>,
}

impl DetectionResult {
    /// Create a result for a rule that was not found.
    #[must_use]
    pub fn not_found(rule_id: &str) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_name: "Unknown".into(),
            triggered: false,
            severity: Severity::Info,
            match_count: 0,
            matches: Vec::new(),
            message: String::new(),
            executed_at: Utc::now(),
            execution_time_ms: 0.0,
            error: Some(format!("Rule not found: {rule_id}")),
            mitre_attack: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Create an error result.
    #[must_use]
    pub fn error(rule_id: &str, rule_name: &str, err: &str) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_name: rule_name.into(),
            triggered: false,
            severity: Severity::Info,
            match_count: 0,
            matches: Vec::new(),
            message: String::new(),
            executed_at: Utc::now(),
            execution_time_ms: 0.0,
            error: Some(err.into()),
            mitre_attack: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Convert to alert payload for notifications (limits matches to 5).
    #[must_use]
    pub fn to_alert_dict(&self) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        map.insert("rule_id".into(), Value::String(self.rule_id.clone()));
        map.insert("rule_name".into(), Value::String(self.rule_name.clone()));
        map.insert("severity".into(), Value::String(self.severity.to_string()));
        map.insert("match_count".into(), Value::Number(self.match_count.into()));
        map.insert("message".into(), Value::String(self.message.clone()));
        map.insert(
            "executed_at".into(),
            Value::String(self.executed_at.to_rfc3339()),
        );
        let sample: Vec<Value> = self
            .matches
            .iter()
            .take(5)
            .map(|m| Value::Object(m.clone()))
            .collect();
        map.insert("sample_matches".into(), Value::Array(sample));
        map
    }
}

/// Metadata for a detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMetadata {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub mitre_attack: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub data_sources: Vec<String>,
    #[serde(default = "default_schedule")]
    pub schedule: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "now_utc")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "now_utc")]
    pub updated_at: DateTime<Utc>,
}

fn default_schedule() -> String {
    "rate(5 minutes)".into()
}
fn default_true() -> bool {
    true
}
fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

/// Target query engine for detection rules.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueryTarget {
    Athena,
    Cloudwatch,
}

impl std::fmt::Display for QueryTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Athena => write!(f, "athena"),
            Self::Cloudwatch => write!(f, "cloudwatch"),
        }
    }
}

/// What data to fetch for a detection rule.
///
/// SQL rules use raw SQL templates; OCSF rules use structured event class queries
/// that work with both Iceberg (direct S3 reads) and Athena.
#[derive(Debug, Clone)]
pub enum DetectionQuery {
    /// A raw SQL query string (with `{start_time}` / `{end_time}` already substituted).
    Sql(String),
    /// An OCSF event class query — dispatched to `SecurityLakeQueries::query_by_event_class`.
    Ocsf {
        event_class: OCSFEventClass,
        limit: usize,
    },
}

/// A declarative filter on OCSF event fields, applied post-query in Rust.
#[derive(Debug, Clone)]
pub struct FieldFilter {
    pub field: String,
    pub op: FilterOp,
}

/// Filter operations for `FieldFilter`.
#[derive(Debug, Clone)]
pub enum FilterOp {
    Equals(String),
    NotEquals(String),
    Contains(String),
    In(Vec<String>),
    Regex(Regex),
}

impl FieldFilter {
    /// Test whether a single OCSF event row matches this filter.
    #[must_use]
    pub fn matches(&self, row: &serde_json::Map<String, Value>) -> bool {
        let val = get_nested_value(row, &self.field);
        match &self.op {
            FilterOp::Equals(expected) => val
                .as_ref()
                .and_then(Value::as_str)
                .is_some_and(|s| s == expected),
            FilterOp::NotEquals(expected) => val
                .as_ref()
                .and_then(Value::as_str)
                .is_none_or(|s| s != expected),
            FilterOp::Contains(needle) => val
                .as_ref()
                .and_then(Value::as_str)
                .is_some_and(|s| s.contains(needle.as_str())),
            FilterOp::In(values) => val
                .as_ref()
                .and_then(Value::as_str)
                .is_some_and(|s| values.iter().any(|v| v == s)),
            FilterOp::Regex(re) => val
                .as_ref()
                .and_then(Value::as_str)
                .is_some_and(|s| re.is_match(s)),
        }
    }
}

/// Apply a set of filters to a `QueryResult`, keeping only rows that match all filters.
///
/// Returns `None` if no filtering was needed (empty filter list), allowing the caller
/// to reuse the original `QueryResult` without cloning.
#[must_use]
pub fn apply_filters(qr: &QueryResult, filters: &[FieldFilter]) -> Option<QueryResult> {
    if filters.is_empty() {
        return None;
    }
    let rows: Vec<serde_json::Map<String, Value>> = qr
        .to_maps()
        .into_iter()
        .filter(|row| filters.iter().all(|f| f.matches(row)))
        .collect();
    Some(QueryResult::from_maps(rows))
}

/// Shared evaluation logic for threshold-based detection rules.
///
/// All rule types use the same pattern: check match count against threshold,
/// take up to 100 sample matches, and produce a `DetectionResult`.
#[must_use]
pub fn threshold_evaluate(
    rule_id: &str,
    rule_name: &str,
    severity: &Severity,
    qr: &QueryResult,
    threshold: usize,
    mitre_attack: &[String],
    tags: &[String],
) -> DetectionResult {
    let match_count = qr.len();
    let triggered = match_count >= threshold;

    let matches = if triggered {
        qr.head(100).to_maps()
    } else {
        Vec::new()
    };

    let message = if triggered {
        format!(
            "Detection '{rule_name}' triggered with {match_count} matches (threshold: {threshold})"
        )
    } else {
        format!(
            "Detection '{rule_name}' did not trigger ({match_count} matches, threshold: {threshold})"
        )
    };

    DetectionResult {
        rule_id: rule_id.into(),
        rule_name: rule_name.into(),
        triggered,
        severity: severity.clone(),
        match_count,
        matches,
        message,
        executed_at: Utc::now(),
        execution_time_ms: 0.0, // Set by caller (run_rule) to include query time
        error: None,
        mitre_attack: mitre_attack.to_vec(),
        tags: tags.to_vec(),
    }
}

/// Common interface for detection rules.
pub trait DetectionRule: Send + Sync {
    /// Rule metadata.
    fn metadata(&self) -> &DetectionMetadata;

    /// Convenience: rule ID.
    fn id(&self) -> &str {
        &self.metadata().id
    }

    /// Convenience: rule name.
    fn name(&self) -> &str {
        &self.metadata().name
    }

    /// Build the query specification for a time window.
    fn build_query(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> DetectionQuery;

    /// Post-query filters applied in Rust (default: none).
    fn filters(&self) -> &[FieldFilter] {
        &[]
    }

    /// Evaluate query results and determine if detection triggered.
    fn evaluate(&self, qr: &QueryResult) -> DetectionResult;

    /// Match threshold (default: 1).
    fn threshold(&self) -> usize {
        1
    }

    /// OCSF event class name, if applicable (default: None).
    fn event_class_name(&self) -> Option<&str> {
        None
    }

    /// Serialize rule metadata to a JSON map.
    fn to_dict(&self) -> serde_json::Map<String, Value> {
        serde_json::to_value(self.metadata())
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default()
    }
}

/// Format a datetime for Athena TIMESTAMP literal.
///
/// Athena requires: `'YYYY-MM-DD HH:MM:SS.ffffff'`
fn format_athena_timestamp(dt: DateTime<Utc>) -> String {
    let naive: NaiveDateTime = dt.naive_utc();
    naive.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
}

/// A detection rule defined primarily by a SQL query template.
#[derive(Debug, Clone)]
pub struct SQLDetectionRule {
    pub meta: DetectionMetadata,
    pub query_template: String,
    pub threshold: usize,
    pub group_by_fields: Vec<String>,
}

impl DetectionRule for SQLDetectionRule {
    fn metadata(&self) -> &DetectionMetadata {
        &self.meta
    }

    fn threshold(&self) -> usize {
        self.threshold
    }

    fn build_query(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> DetectionQuery {
        DetectionQuery::Sql(
            self.query_template
                .replace("{start_time}", &format_athena_timestamp(start))
                .replace("{end_time}", &format_athena_timestamp(end)),
        )
    }

    fn evaluate(&self, qr: &QueryResult) -> DetectionResult {
        threshold_evaluate(
            self.id(),
            self.name(),
            &self.meta.severity,
            qr,
            self.threshold,
            &self.meta.mitre_attack,
            &self.meta.tags,
        )
    }
}

/// A detection rule that supports both `CloudWatch` Logs Insights and Athena SQL.
#[derive(Debug, Clone)]
pub struct DualTargetDetectionRule {
    pub meta: DetectionMetadata,
    pub queries: HashMap<QueryTarget, String>,
    pub threshold: usize,
    pub group_by_fields: Vec<String>,
    pub default_target: QueryTarget,
}

impl DualTargetDetectionRule {
    /// Create from a raw queries map, normalizing key names.
    pub fn new(
        meta: DetectionMetadata,
        raw_queries: HashMap<String, String>,
        threshold: usize,
        group_by_fields: Vec<String>,
    ) -> Self {
        let queries = Self::normalize_queries(raw_queries);
        let default_target = if queries.contains_key(&QueryTarget::Cloudwatch) {
            QueryTarget::Cloudwatch
        } else {
            QueryTarget::Athena
        };
        Self {
            meta,
            queries,
            threshold,
            group_by_fields,
            default_target,
        }
    }

    fn normalize_queries(raw: HashMap<String, String>) -> HashMap<QueryTarget, String> {
        let key_mapping: HashMap<&str, QueryTarget> = [
            ("cloudwatch", QueryTarget::Cloudwatch),
            ("cw", QueryTarget::Cloudwatch),
            ("cloudwatch_logs", QueryTarget::Cloudwatch),
            ("logs_insights", QueryTarget::Cloudwatch),
            ("athena", QueryTarget::Athena),
            ("sql", QueryTarget::Athena),
            ("security_lake", QueryTarget::Athena),
            ("query", QueryTarget::Athena),
        ]
        .into_iter()
        .collect();

        let mut normalized = HashMap::new();
        for (key, query) in raw {
            if let Some(target) = key_mapping.get(key.to_lowercase().as_str()) {
                normalized.insert(target.clone(), query);
            }
        }
        normalized
    }

    /// List of targets this rule supports.
    #[must_use]
    pub fn supported_targets(&self) -> Vec<&QueryTarget> {
        self.queries.keys().collect()
    }

    /// Check if rule supports a specific target.
    #[must_use]
    pub fn has_target(&self, target: &QueryTarget) -> bool {
        self.queries.contains_key(target)
    }

    /// Get query for a specific target with time substitution.
    pub fn get_query_for_target(
        &self,
        target: &QueryTarget,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<String, String> {
        let query = self.queries.get(target).ok_or_else(|| {
            let available: Vec<String> = self.queries.keys().map(ToString::to_string).collect();
            format!(
                "Rule '{}' does not support target '{}'. Available: {:?}",
                self.id(),
                target,
                available
            )
        })?;

        if *target == QueryTarget::Athena {
            Ok(query
                .replace("{start_time}", &format_athena_timestamp(start))
                .replace("{end_time}", &format_athena_timestamp(end)))
        } else {
            Ok(query
                .replace("{start_time}", &start.to_rfc3339())
                .replace("{end_time}", &end.to_rfc3339()))
        }
    }
}

impl DetectionRule for DualTargetDetectionRule {
    fn metadata(&self) -> &DetectionMetadata {
        &self.meta
    }

    fn threshold(&self) -> usize {
        self.threshold
    }

    fn build_query(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> DetectionQuery {
        DetectionQuery::Sql(
            self.get_query_for_target(&self.default_target, start, end)
                .unwrap_or_default(),
        )
    }

    fn evaluate(&self, qr: &QueryResult) -> DetectionResult {
        threshold_evaluate(
            self.id(),
            self.name(),
            &self.meta.severity,
            qr,
            self.threshold,
            &self.meta.mitre_attack,
            &self.meta.tags,
        )
    }
}

/// An OCSF-native detection rule that queries by event class and filters in Rust.
#[derive(Debug, Clone)]
pub struct OCSFDetectionRule {
    pub meta: DetectionMetadata,
    pub event_class: OCSFEventClass,
    pub rule_filters: Vec<FieldFilter>,
    pub threshold: usize,
    pub limit: usize,
    pub group_by_fields: Vec<String>,
}

impl DetectionRule for OCSFDetectionRule {
    fn metadata(&self) -> &DetectionMetadata {
        &self.meta
    }

    fn threshold(&self) -> usize {
        self.threshold
    }

    fn event_class_name(&self) -> Option<&str> {
        Some(self.event_class.name())
    }

    fn build_query(&self, _start: DateTime<Utc>, _end: DateTime<Utc>) -> DetectionQuery {
        DetectionQuery::Ocsf {
            event_class: self.event_class,
            limit: self.limit,
        }
    }

    fn filters(&self) -> &[FieldFilter] {
        &self.rule_filters
    }

    fn evaluate(&self, qr: &QueryResult) -> DetectionResult {
        threshold_evaluate(
            self.id(),
            self.name(),
            &self.meta.severity,
            qr,
            self.threshold,
            &self.meta.mitre_attack,
            &self.meta.tags,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json_row;
    use proptest::prelude::*;

    fn sample_metadata() -> DetectionMetadata {
        DetectionMetadata {
            id: "test-rule".into(),
            name: "Test Rule".into(),
            description: "A test detection rule".into(),
            author: "test".into(),
            severity: Severity::High,
            tags: vec!["test".into()],
            mitre_attack: vec!["T1078".into()],
            references: vec![],
            data_sources: vec!["cloudtrail".into()],
            schedule: "rate(5 minutes)".into(),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(Severity::Info.to_string(), "info");
    }

    #[test]
    fn severity_serde_roundtrip() {
        let json = serde_json::to_string(&Severity::High).unwrap();
        assert_eq!(json, "\"high\"");
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Severity::High);
    }

    #[test]
    fn detection_result_not_found() {
        let r = DetectionResult::not_found("missing-rule");
        assert!(!r.triggered);
        assert!(r.error.is_some());
        assert!(r.error.unwrap().contains("missing-rule"));
    }

    #[test]
    fn detection_result_to_alert_dict_limits_matches() {
        let matches: Vec<serde_json::Map<String, Value>> =
            (0..10).map(|i| json_row!("idx" => i)).collect();
        let r = DetectionResult {
            rule_id: "r1".into(),
            rule_name: "Rule 1".into(),
            triggered: true,
            severity: Severity::High,
            match_count: 10,
            matches,
            message: "triggered".into(),
            mitre_attack: Vec::new(),
            tags: Vec::new(),
            executed_at: Utc::now(),
            execution_time_ms: 1.0,
            error: None,
        };
        let alert = r.to_alert_dict();
        let samples = alert["sample_matches"].as_array().unwrap();
        assert_eq!(samples.len(), 5); // Limited to 5
    }

    #[test]
    fn sql_detection_rule_build_query() {
        let rule = SQLDetectionRule {
            meta: sample_metadata(),
            query_template: "SELECT * FROM t WHERE time >= TIMESTAMP '{start_time}' AND time < TIMESTAMP '{end_time}'".into(),
            threshold: 1,
            group_by_fields: Vec::new(),
        };
        let start = DateTime::parse_from_rfc3339("2024-01-15T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2024-01-15T11:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let DetectionQuery::Sql(query) = rule.build_query(start, end) else {
            panic!("Expected DetectionQuery::Sql");
        };
        assert!(query.contains("2024-01-15 10:00:00"));
        assert!(query.contains("2024-01-15 11:00:00"));
        assert!(!query.contains("{start_time}"));
    }

    #[test]
    fn ocsf_detection_rule_build_query() {
        let rule = OCSFDetectionRule {
            meta: sample_metadata(),
            event_class: OCSFEventClass::ApiActivity,
            rule_filters: vec![FieldFilter {
                field: "api.operation".into(),
                op: FilterOp::In(vec!["AttachUserPolicy".into(), "PutRolePolicy".into()]),
            }],
            threshold: 1,
            limit: 5000,
            group_by_fields: Vec::new(),
        };
        let DetectionQuery::Ocsf { event_class, limit } = rule.build_query(Utc::now(), Utc::now())
        else {
            panic!("Expected DetectionQuery::Ocsf");
        };
        assert_eq!(event_class, OCSFEventClass::ApiActivity);
        assert_eq!(limit, 5000);
        assert_eq!(rule.filters().len(), 1);
    }

    #[test]
    fn field_filter_equals() {
        let filter = FieldFilter {
            field: "status_id".into(),
            op: FilterOp::Equals("1".into()),
        };
        let row = json_row!("status_id" => "1");
        assert!(filter.matches(&row));
        let row_no = json_row!("status_id" => "2");
        assert!(!filter.matches(&row_no));
    }

    #[test]
    fn field_filter_in() {
        use serde_json::json;
        let filter = FieldFilter {
            field: "api.operation".into(),
            op: FilterOp::In(vec!["AttachUserPolicy".into(), "PutRolePolicy".into()]),
        };
        let row: serde_json::Map<String, Value> =
            serde_json::from_value(json!({"api": {"operation": "AttachUserPolicy"}})).unwrap();
        assert!(filter.matches(&row));
        let row_no: serde_json::Map<String, Value> =
            serde_json::from_value(json!({"api": {"operation": "DeleteRole"}})).unwrap();
        assert!(!filter.matches(&row_no));
    }

    #[test]
    fn field_filter_contains() {
        let filter = FieldFilter {
            field: "message".into(),
            op: FilterOp::Contains("error".into()),
        };
        let row = json_row!("message" => "An error occurred");
        assert!(filter.matches(&row));
        let row_no = json_row!("message" => "All good");
        assert!(!filter.matches(&row_no));
    }

    #[test]
    fn field_filter_regex() {
        let filter = FieldFilter {
            field: "user".into(),
            op: FilterOp::Regex(Regex::new(r"^admin-\d+$").unwrap()),
        };
        let row = json_row!("user" => "admin-42");
        assert!(filter.matches(&row));
        let row_no = json_row!("user" => "user-42");
        assert!(!filter.matches(&row_no));
    }

    #[test]
    fn apply_filters_keeps_matching_rows() {
        let qr = QueryResult::from_maps(vec![
            json_row!("status_id" => "1", "user" => "alice"),
            json_row!("status_id" => "2", "user" => "bob"),
            json_row!("status_id" => "1", "user" => "charlie"),
        ]);
        let filters = vec![FieldFilter {
            field: "status_id".into(),
            op: FilterOp::Equals("1".into()),
        }];
        let filtered = apply_filters(&qr, &filters).expect("should filter");
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn apply_filters_returns_none_when_empty() {
        let qr = QueryResult::from_maps(vec![json_row!("x" => "1")]);
        assert!(apply_filters(&qr, &[]).is_none());
    }

    #[test]
    fn sql_detection_rule_evaluate_triggers() {
        let rule = SQLDetectionRule {
            meta: sample_metadata(),
            query_template: String::new(),
            threshold: 2,
            group_by_fields: Vec::new(),
        };
        let qr = QueryResult::from_maps(vec![
            json_row!("user" => "alice"),
            json_row!("user" => "bob"),
            json_row!("user" => "charlie"),
        ]);
        let result = rule.evaluate(&qr);
        assert!(result.triggered);
        assert_eq!(result.match_count, 3);
        assert!(!result.matches.is_empty());
        assert!(result.message.contains("triggered"));
    }

    #[test]
    fn sql_detection_rule_evaluate_no_trigger() {
        let rule = SQLDetectionRule {
            meta: sample_metadata(),
            query_template: String::new(),
            threshold: 10,
            group_by_fields: Vec::new(),
        };
        let qr = QueryResult::from_maps(vec![json_row!("user" => "alice")]);
        let result = rule.evaluate(&qr);
        assert!(!result.triggered);
        assert!(result.matches.is_empty());
        assert!(result.message.contains("did not trigger"));
    }

    #[test]
    fn dual_target_rule_normalize_queries() {
        let mut raw = HashMap::new();
        raw.insert("cloudwatch".into(), "fields @timestamp".into());
        raw.insert("sql".into(), "SELECT * FROM t".into());

        let rule = DualTargetDetectionRule::new(sample_metadata(), raw, 1, Vec::new());

        assert!(rule.has_target(&QueryTarget::Cloudwatch));
        assert!(rule.has_target(&QueryTarget::Athena));
        assert_eq!(rule.supported_targets().len(), 2);
    }

    #[test]
    fn dual_target_rule_query_for_target() {
        let mut raw = HashMap::new();
        raw.insert(
            "athena".into(),
            "SELECT * WHERE t >= TIMESTAMP '{start_time}'".into(),
        );

        let rule = DualTargetDetectionRule::new(sample_metadata(), raw, 1, Vec::new());
        let start = DateTime::parse_from_rfc3339("2024-01-15T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = Utc::now();

        let query = rule
            .get_query_for_target(&QueryTarget::Athena, start, end)
            .unwrap();
        assert!(query.contains("2024-01-15 10:00:00"));
    }

    #[test]
    fn dual_target_rule_unsupported_target_errors() {
        let raw = HashMap::new();
        let rule = DualTargetDetectionRule::new(sample_metadata(), raw, 1, Vec::new());
        let err = rule
            .get_query_for_target(&QueryTarget::Cloudwatch, Utc::now(), Utc::now())
            .unwrap_err();
        assert!(err.contains("does not support"));
    }

    #[test]
    fn metadata_serde_roundtrip() {
        let meta = sample_metadata();
        let json = serde_json::to_string(&meta).unwrap();
        let back: DetectionMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "test-rule");
        assert_eq!(back.severity, Severity::High);
        assert_eq!(back.tags, vec!["test"]);
    }

    #[test]
    fn metadata_yaml_deserialization() {
        let yaml = r"
id: detect-root-login
name: Root Account Login
severity: high
tags:
  - auth
  - root
mitre_attack:
  - T1078.004
threshold: 1
";
        let meta: DetectionMetadata = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(meta.id, "detect-root-login");
        assert_eq!(meta.severity, Severity::High);
        assert!(meta.enabled); // default
    }

    // --- Property tests (sharp-edges driven) ---

    // SE-1: threshold_evaluate invariant — triggered iff match_count >= threshold.
    // Catches threshold=0 always-trigger and off-by-one edge cases.
    proptest! {
        #[test]
        fn threshold_triggered_iff_count_gte_threshold(
            n_rows in 0_usize..200,
            threshold in 0_usize..200,
        ) {
            let rows: Vec<serde_json::Map<String, Value>> =
                (0..n_rows).map(|i| json_row!("i" => i)).collect();
            let qr = QueryResult::from_maps(rows);

            let result = threshold_evaluate("r", "rule", &Severity::High, &qr, threshold, &[], &[]);

            prop_assert_eq!(
                result.triggered,
                n_rows >= threshold,
                "triggered mismatch: {} rows vs threshold {}",
                n_rows,
                threshold,
            );
            prop_assert_eq!(result.match_count, n_rows);
            prop_assert!(result.error.is_none());
        }
    }

    /// SE-1b: threshold=0 means EVERY result triggers, including empty.
    /// This is a documentation-worthy invariant — if you don't want this,
    /// don't set threshold to 0.
    #[test]
    fn threshold_zero_triggers_on_empty() {
        let qr = QueryResult::empty();
        let result = threshold_evaluate("r", "rule", &Severity::High, &qr, 0, &[], &[]);
        assert!(result.triggered);
        assert_eq!(result.match_count, 0);
    }

    // SE-2: NotEquals on missing field returns true (field absent = not equal).
    // Property: for any expected value, a row missing the field always passes NotEquals.
    proptest! {
        #[test]
        fn not_equals_missing_field_always_passes(expected in "\\PC{1,50}") {
            let filter = FieldFilter {
                field: "nonexistent_field".into(),
                op: FilterOp::NotEquals(expected),
            };
            let row = json_row!("other_field" => "value");
            prop_assert!(filter.matches(&row), "NotEquals should pass when field is missing");
        }
    }

    // SE-2 inverse: Equals on missing field always fails.
    proptest! {
        #[test]
        fn equals_missing_field_always_fails(expected in "\\PC{1,50}") {
            let filter = FieldFilter {
                field: "nonexistent_field".into(),
                op: FilterOp::Equals(expected),
            };
            let row = json_row!("other_field" => "value");
            prop_assert!(!filter.matches(&row), "Equals should fail when field is missing");
        }
    }

    // SE-6: Filters only match string values. Numeric JSON values are invisible.
    // Property: Equals("5") never matches a row where the field is the number 5.
    #[test]
    fn equals_filter_does_not_match_numeric_json_value() {
        use serde_json::json;
        let filter = FieldFilter {
            field: "severity_id".into(),
            op: FilterOp::Equals("5".into()),
        };
        // Numeric value — as_str() returns None
        let row: serde_json::Map<String, Value> =
            serde_json::from_value(json!({"severity_id": 5})).unwrap();
        assert!(
            !filter.matches(&row),
            "String filter should not match numeric JSON value"
        );

        // String value — this one matches
        let row_str: serde_json::Map<String, Value> =
            serde_json::from_value(json!({"severity_id": "5"})).unwrap();
        assert!(filter.matches(&row_str));
    }

    // apply_filters monotonicity: filtering can only reduce or preserve row count.
    proptest! {
        #[test]
        fn apply_filters_never_increases_rows(
            n_rows in 0_usize..50,
            filter_value in "[0-9]",
        ) {
            let rows: Vec<serde_json::Map<String, Value>> = (0..n_rows)
                .map(|i| json_row!("x" => i.to_string()))
                .collect();
            let qr = QueryResult::from_maps(rows);
            let filters = vec![FieldFilter {
                field: "x".into(),
                op: FilterOp::Equals(filter_value),
            }];
            let filtered = apply_filters(&qr, &filters).unwrap_or_else(|| qr.clone());
            prop_assert!(filtered.len() <= qr.len());
        }
    }

    // Contains on missing field returns false (field absent = no match).
    proptest! {
        #[test]
        fn contains_missing_field_always_fails(needle in "\\PC{1,50}") {
            let filter = FieldFilter {
                field: "nonexistent_field".into(),
                op: FilterOp::Contains(needle),
            };
            let row = json_row!("other_field" => "value");
            prop_assert!(!filter.matches(&row), "Contains should fail when field is missing");
        }
    }

    // In on missing field returns false.
    proptest! {
        #[test]
        fn in_missing_field_always_fails(
            v1 in "\\PC{1,30}",
            v2 in "\\PC{1,30}",
        ) {
            let filter = FieldFilter {
                field: "nonexistent_field".into(),
                op: FilterOp::In(vec![v1, v2]),
            };
            let row = json_row!("other_field" => "value");
            prop_assert!(!filter.matches(&row), "In should fail when field is missing");
        }
    }

    // apply_filters with empty filters returns None (identity — no clone).
    proptest! {
        #[test]
        fn apply_filters_empty_is_none(n_rows in 0_usize..20) {
            let rows: Vec<serde_json::Map<String, Value>> = (0..n_rows)
                .map(|i| json_row!("x" => i.to_string()))
                .collect();
            let qr = QueryResult::from_maps(rows);
            prop_assert!(apply_filters(&qr, &[]).is_none());
        }
    }

    // threshold_evaluate: matches vector is empty when not triggered,
    // and capped at 100 when triggered.
    proptest! {
        #[test]
        fn evaluate_matches_bounded(
            n_rows in 0_usize..250,
            threshold in 1_usize..50,
        ) {
            let rows: Vec<serde_json::Map<String, Value>> = (0..n_rows)
                .map(|i| json_row!("i" => i))
                .collect();
            let qr = QueryResult::from_maps(rows);
            let result = threshold_evaluate("r", "rule", &Severity::High, &qr, threshold, &[], &[]);

            if result.triggered {
                prop_assert!(result.matches.len() <= 100);
                prop_assert!(!result.matches.is_empty());
            } else {
                prop_assert!(result.matches.is_empty());
            }
        }
    }
}
