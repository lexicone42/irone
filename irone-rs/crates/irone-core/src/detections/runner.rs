use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use tracing::{debug, info, warn};

use super::rule::{
    DetectionMetadata, DetectionQuery, DetectionResult, DetectionRule, DualTargetDetectionRule,
    FieldFilter, FilterOp, OCSFDetectionRule, SQLDetectionRule, Severity, apply_filters,
};
use crate::connectors::base::DataConnector;
use crate::connectors::ocsf::{ColumnFilter, OCSFEventClass, SecurityLakeQueries};

/// Runs detection rules against data source connectors.
///
/// Only YAML rules are loaded from the filesystem — no arbitrary code execution.
pub struct DetectionRunner {
    rules: HashMap<String, Box<dyn DetectionRule>>,
}

impl DetectionRunner {
    /// Create an empty runner.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
        }
    }

    /// Register a detection rule.
    pub fn register_rule(&mut self, rule: Box<dyn DetectionRule>) {
        info!(
            rule_id = rule.id(),
            rule_name = rule.name(),
            "Registered detection rule"
        );
        self.rules.insert(rule.id().to_string(), rule);
    }

    /// Get a rule by ID.
    #[must_use]
    pub fn get_rule(&self, rule_id: &str) -> Option<&dyn DetectionRule> {
        self.rules.get(rule_id).map(AsRef::as_ref)
    }

    /// List all registered rules, optionally filtering to enabled only.
    #[must_use]
    pub fn list_rules(&self, enabled_only: bool) -> Vec<&dyn DetectionRule> {
        self.rules
            .values()
            .filter(|r| !enabled_only || r.metadata().enabled)
            .map(AsRef::as_ref)
            .collect()
    }

    /// Maximum time a detection query may run before being cancelled.
    const QUERY_TIMEOUT: StdDuration = StdDuration::from_secs(30);

    /// Run a single detection rule.
    ///
    /// Dispatches to either `DataConnector::query` (SQL rules) or
    /// `SecurityLakeQueries::query_by_event_class` (OCSF rules), then
    /// applies any post-query filters in Rust before evaluation.
    ///
    /// Queries are subject to a 30-second timeout to prevent hung connections.
    pub async fn run_rule<C: DataConnector + SecurityLakeQueries>(
        &self,
        rule_id: &str,
        connector: &C,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        lookback_minutes: i64,
    ) -> DetectionResult {
        let Some(rule) = self.rules.get(rule_id) else {
            return DetectionResult::not_found(rule_id);
        };

        let end = end.unwrap_or_else(Utc::now);
        let start = start.unwrap_or_else(|| end - Duration::minutes(lookback_minutes));
        let timer = Instant::now();

        let detection_query = rule.build_query(start, end);

        // Split YAML filters: pushable ones become ColumnFilters for the connector,
        // non-pushable ones (Contains, NotEquals, Regex) remain as post-query filters.
        let (pushdown_filters, post_filters) = split_filters(rule.filters());

        let query_future = async {
            match &detection_query {
                DetectionQuery::Sql(sql) => {
                    debug!(
                        rule_id,
                        query_preview = &sql[..sql.len().min(200)],
                        "Executing SQL detection query"
                    );
                    connector.query(sql).await.map_err(|e| e.to_string())
                }
                DetectionQuery::Ocsf { event_class, limit } => {
                    let cf = if pushdown_filters.is_empty() {
                        None
                    } else {
                        Some(pushdown_filters.as_slice())
                    };
                    debug!(
                        rule_id,
                        event_class = %event_class,
                        limit,
                        pushdown = pushdown_filters.len(),
                        post_filter = post_filters.len(),
                        "Executing OCSF detection query"
                    );
                    connector
                        .query_by_event_class(*event_class, start, end, *limit, cf)
                        .await
                        .map_err(|e| e.to_string())
                }
            }
        };

        let qr = match tokio::time::timeout(Self::QUERY_TIMEOUT, query_future).await {
            Ok(Ok(qr)) => qr,
            Ok(Err(e)) => {
                warn!(rule_id, error = %e, "Detection query failed");
                return DetectionResult::error(rule_id, rule.name(), &e);
            }
            Err(_) => {
                warn!(rule_id, "Detection query timed out after 30s");
                return DetectionResult::error(
                    rule_id,
                    rule.name(),
                    "Query timed out after 30 seconds",
                );
            }
        };

        // Apply remaining non-pushable filters post-query
        let filtered = apply_filters(&qr, &post_filters);
        let eval_qr = filtered.as_ref().unwrap_or(&qr);

        let mut result = rule.evaluate(eval_qr);
        result.execution_time_ms = timer.elapsed().as_secs_f64() * 1000.0;
        info!(
            rule_id,
            triggered = result.triggered,
            match_count = result.match_count,
            pre_filter_count = qr.len(),
            execution_time_ms = result.execution_time_ms,
            "Detection completed"
        );
        result
    }

    /// Run all enabled detection rules.
    pub async fn run_all<C: DataConnector + SecurityLakeQueries>(
        &self,
        connector: &C,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        lookback_minutes: i64,
    ) -> Vec<DetectionResult> {
        let mut results = Vec::new();
        for (id, rule) in &self.rules {
            if rule.metadata().enabled {
                results.push(
                    self.run_rule(id, connector, start, end, lookback_minutes)
                        .await,
                );
            }
        }
        results
    }

    /// Load detection rules from YAML files in a directory.
    ///
    /// Returns the number of rules successfully loaded.
    pub fn load_rules_from_directory(&mut self, rules_dir: &Path) -> usize {
        let mut loaded = 0;

        let entries = match std::fs::read_dir(rules_dir) {
            Ok(entries) => entries,
            Err(e) => {
                warn!(dir = %rules_dir.display(), error = %e, "Failed to read rules directory");
                return 0;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
                continue;
            }

            match load_yaml_rules(&path) {
                Ok(rules) => {
                    for rule in rules {
                        self.register_rule(rule);
                        loaded += 1;
                    }
                }
                Err(e) => {
                    warn!(file = %path.display(), error = %e, "Failed to load rules from file");
                }
            }
        }

        loaded
    }

    /// Export all rules to a list of JSON maps.
    #[must_use]
    pub fn export_rules_to_dict(&self) -> Vec<serde_json::Map<String, serde_json::Value>> {
        self.rules.values().map(|r| r.to_dict()).collect()
    }
}

impl Default for DetectionRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Load detection rules from a YAML file.
///
/// Supports:
/// - `OCSFDetectionRule`: OCSF-native rules (has `event_class` field)
/// - `DualTargetDetectionRule`: Rules with `queries` dict or `log_type: cloudwatch_logs`
/// - `SQLDetectionRule`: Traditional SQL/Athena queries (has `query` field)
fn load_yaml_rules(
    file_path: &Path,
) -> Result<Vec<Box<dyn DetectionRule>>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(file_path)?;
    let data: serde_yaml::Value = serde_yaml::from_str(&content)?;

    let rule_defs: Vec<serde_yaml::Value> = match data {
        serde_yaml::Value::Sequence(seq) => seq,
        other => vec![other],
    };

    let mut rules: Vec<Box<dyn DetectionRule>> = Vec::new();

    for rule_def in rule_defs {
        let map = rule_def
            .as_mapping()
            .ok_or("Rule definition must be a mapping")?;

        let event_class_str = map
            .get(yaml_key("event_class"))
            .and_then(serde_yaml::Value::as_str);
        let has_queries = map.contains_key(yaml_key("queries"));
        let log_type = map
            .get(yaml_key("log_type"))
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or("");

        let meta = parse_metadata(map)?;
        #[allow(clippy::cast_possible_truncation)]
        let threshold = map
            .get(yaml_key("threshold"))
            .and_then(serde_yaml::Value::as_u64)
            .unwrap_or(1) as usize;
        let group_by = map
            .get(yaml_key("group_by"))
            .and_then(serde_yaml::Value::as_sequence)
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        if let Some(ec_str) = event_class_str {
            // OCSF-native rule
            let event_class = OCSFEventClass::from_yaml_str(ec_str)
                .ok_or_else(|| format!("Unknown event_class '{}' in rule '{}'", ec_str, meta.id))?;
            #[allow(clippy::cast_possible_truncation)]
            let limit = map
                .get(yaml_key("limit"))
                .and_then(serde_yaml::Value::as_u64)
                .unwrap_or(5000) as usize;
            let filters = parse_filters(map)?;
            let rule = OCSFDetectionRule {
                meta,
                event_class,
                rule_filters: filters,
                threshold,
                limit,
                group_by_fields: group_by,
            };
            rules.push(Box::new(rule));
        } else if has_queries || log_type == "cloudwatch_logs" {
            let raw_queries = parse_queries(map, log_type);
            let rule = DualTargetDetectionRule::new(meta, raw_queries, threshold, group_by);
            rules.push(Box::new(rule));
        } else {
            let query = map
                .get(yaml_key("query"))
                .and_then(serde_yaml::Value::as_str)
                .unwrap_or("")
                .to_string();
            let rule = SQLDetectionRule {
                meta,
                query_template: query,
                threshold,
                group_by_fields: group_by,
            };
            rules.push(Box::new(rule));
        }
    }

    Ok(rules)
}

/// Create a YAML string key for map lookups.
fn yaml_key(key: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(key.into())
}

fn parse_metadata(
    map: &serde_yaml::Mapping,
) -> Result<DetectionMetadata, Box<dyn std::error::Error>> {
    let get_str = |key: &str| -> String {
        map.get(yaml_key(key))
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let get_str_vec = |key: &str| -> Vec<String> {
        map.get(yaml_key(key))
            .and_then(serde_yaml::Value::as_sequence)
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };

    let id = get_str("id");
    if id.is_empty() {
        return Err("Rule must have an 'id' field".into());
    }
    let name = get_str("name");
    if name.is_empty() {
        return Err("Rule must have a 'name' field".into());
    }

    let severity_str = get_str("severity");
    let severity: Severity = if severity_str.is_empty() {
        Severity::Medium
    } else {
        serde_json::from_value(serde_json::Value::String(severity_str))?
    };

    let enabled = map
        .get(yaml_key("enabled"))
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(true);

    Ok(DetectionMetadata {
        id,
        name,
        description: get_str("description"),
        author: get_str("author"),
        severity,
        tags: get_str_vec("tags"),
        mitre_attack: get_str_vec("mitre_attack"),
        data_sources: get_str_vec("data_sources"),
        schedule: {
            let s = get_str("schedule");
            if s.is_empty() {
                "rate(5 minutes)".into()
            } else {
                s
            }
        },
        enabled,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    })
}

fn parse_queries(map: &serde_yaml::Mapping, log_type: &str) -> HashMap<String, String> {
    // Try 'queries' dict first
    if let Some(queries_val) = map.get(yaml_key("queries"))
        && let Some(queries_map) = queries_val.as_mapping()
    {
        return queries_map
            .iter()
            .filter_map(|(k, v)| Some((k.as_str()?.to_string(), v.as_str()?.to_string())))
            .collect();
    }

    // Legacy: single 'query' field
    if let Some(query) = map
        .get(yaml_key("query"))
        .and_then(serde_yaml::Value::as_str)
    {
        let key = if log_type == "cloudwatch_logs" {
            "cloudwatch"
        } else {
            "athena"
        };
        let mut queries = HashMap::new();
        queries.insert(key.to_string(), query.to_string());
        return queries;
    }

    HashMap::new()
}

/// Parse the `filters` array from a YAML rule definition.
fn parse_filters(
    map: &serde_yaml::Mapping,
) -> Result<Vec<FieldFilter>, Box<dyn std::error::Error>> {
    let Some(filters_val) = map.get(yaml_key("filters")) else {
        return Ok(Vec::new());
    };
    let filters_seq = filters_val
        .as_sequence()
        .ok_or("'filters' must be a sequence")?;

    let mut filters = Vec::new();
    for filter_val in filters_seq {
        let fmap = filter_val
            .as_mapping()
            .ok_or("Each filter must be a mapping")?;

        let field = fmap
            .get(yaml_key("field"))
            .and_then(serde_yaml::Value::as_str)
            .ok_or("Filter must have a 'field'")?
            .to_string();

        let op = if let Some(v) = fmap
            .get(yaml_key("equals"))
            .and_then(serde_yaml::Value::as_str)
        {
            FilterOp::Equals(v.to_string())
        } else if let Some(v) = fmap
            .get(yaml_key("not_equals"))
            .and_then(serde_yaml::Value::as_str)
        {
            FilterOp::NotEquals(v.to_string())
        } else if let Some(v) = fmap
            .get(yaml_key("contains"))
            .and_then(serde_yaml::Value::as_str)
        {
            FilterOp::Contains(v.to_string())
        } else if let Some(seq) = fmap
            .get(yaml_key("in"))
            .and_then(serde_yaml::Value::as_sequence)
        {
            let values: Vec<String> = seq
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            FilterOp::In(values)
        } else if let Some(v) = fmap
            .get(yaml_key("regex"))
            .and_then(serde_yaml::Value::as_str)
        {
            let re = Regex::new(v).map_err(|e| format!("Invalid regex '{v}' in filter: {e}"))?;
            FilterOp::Regex(re)
        } else {
            return Err(format!("Filter for field '{field}' has no valid operator").into());
        };

        filters.push(FieldFilter { field, op });
    }

    Ok(filters)
}

/// Split `FieldFilter`s into pushdown `ColumnFilter`s and remaining post-query `FieldFilter`s.
///
/// `Equals` → `StringEquals`, `In` → `StringIn` (pushable).
/// `Contains`, `NotEquals`, `Regex` stay as post-query filters.
fn split_filters(filters: &[FieldFilter]) -> (Vec<ColumnFilter>, Vec<FieldFilter>) {
    let mut pushdown = Vec::new();
    let mut post = Vec::new();
    for f in filters {
        match &f.op {
            FilterOp::Equals(val) => pushdown.push(ColumnFilter::StringEquals {
                path: f.field.clone(),
                value: val.clone(),
            }),
            FilterOp::In(vals) => pushdown.push(ColumnFilter::StringIn {
                path: f.field.clone(),
                values: vals.clone(),
            }),
            _ => post.push(f.clone()),
        }
    }
    (pushdown, post)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::connectors::ocsf::{OCSFEventClass, SecurityLakeError};
    use crate::connectors::result::QueryResult;
    use crate::json_row;

    /// A mock connector that returns preset results for both SQL and OCSF queries.
    struct MockConnector {
        result: QueryResult,
    }

    impl DataConnector for MockConnector {
        async fn query(
            &self,
            _sql: &str,
        ) -> Result<QueryResult, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.result.clone())
        }
        async fn get_schema(
            &self,
        ) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(HashMap::new())
        }
        async fn check_health(
            &self,
        ) -> Result<
            crate::connectors::base::HealthCheckResult,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(crate::connectors::base::HealthCheckResult::new(
                "mock", true,
            ))
        }
    }

    impl SecurityLakeQueries for MockConnector {
        async fn query_by_event_class(
            &self,
            _event_class: OCSFEventClass,
            _start: DateTime<Utc>,
            _end: DateTime<Utc>,
            _limit: usize,
            _filters: Option<&[crate::connectors::ocsf::ColumnFilter]>,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(self.result.clone())
        }
        async fn query_authentication_events(
            &self,
            _start: DateTime<Utc>,
            _end: DateTime<Utc>,
            _status: Option<&str>,
            _limit: usize,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(self.result.clone())
        }
        async fn query_api_activity(
            &self,
            _start: DateTime<Utc>,
            _end: DateTime<Utc>,
            _service: Option<&str>,
            _operation: Option<&str>,
            _limit: usize,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(self.result.clone())
        }
        async fn query_network_activity(
            &self,
            _start: DateTime<Utc>,
            _end: DateTime<Utc>,
            _src_ip: Option<&str>,
            _dst_ip: Option<&str>,
            _dst_port: Option<u16>,
            _limit: usize,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(self.result.clone())
        }
        async fn query_security_findings(
            &self,
            _start: DateTime<Utc>,
            _end: DateTime<Utc>,
            _severity: Option<&str>,
            _limit: usize,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(self.result.clone())
        }
        async fn get_event_summary(
            &self,
            _start: DateTime<Utc>,
            _end: DateTime<Utc>,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(self.result.clone())
        }
    }

    fn sample_sql_rule() -> SQLDetectionRule {
        SQLDetectionRule {
            meta: DetectionMetadata {
                id: "test-rule".into(),
                name: "Test Rule".into(),
                severity: Severity::High,
                enabled: true,
                ..serde_json::from_str::<DetectionMetadata>(
                    r#"{"id":"test-rule","name":"Test Rule","severity":"high"}"#,
                )
                .unwrap()
            },
            query_template: "SELECT * FROM t WHERE time >= TIMESTAMP '{start_time}'".into(),
            threshold: 1,
            group_by_fields: Vec::new(),
        }
    }

    #[test]
    fn register_and_get_rule() {
        let mut runner = DetectionRunner::new();
        runner.register_rule(Box::new(sample_sql_rule()));
        assert!(runner.get_rule("test-rule").is_some());
        assert!(runner.get_rule("missing").is_none());
    }

    #[test]
    fn list_rules_enabled_only() {
        let mut runner = DetectionRunner::new();
        let mut rule = sample_sql_rule();
        runner.register_rule(Box::new(rule.clone()));

        rule.meta.id = "disabled-rule".into();
        rule.meta.name = "Disabled Rule".into();
        rule.meta.enabled = false;
        runner.register_rule(Box::new(rule));

        assert_eq!(runner.list_rules(true).len(), 1);
        assert_eq!(runner.list_rules(false).len(), 2);
    }

    #[tokio::test]
    async fn run_rule_not_found() {
        let runner = DetectionRunner::new();
        let connector = MockConnector {
            result: QueryResult::empty(),
        };
        let result = runner.run_rule("missing", &connector, None, None, 15).await;
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn run_rule_triggers() {
        let mut runner = DetectionRunner::new();
        runner.register_rule(Box::new(sample_sql_rule()));

        let connector = MockConnector {
            result: QueryResult::from_maps(vec![
                json_row!("user" => "alice"),
                json_row!("user" => "bob"),
            ]),
        };
        let result = runner
            .run_rule("test-rule", &connector, None, None, 15)
            .await;
        assert!(result.triggered);
        assert_eq!(result.match_count, 2);
    }

    #[tokio::test]
    async fn run_ocsf_rule_with_pushdown_filters() {
        // Equals filters are pushed down as ColumnFilters to the connector.
        // The mock connector ignores them, so all 3 rows survive.
        let mut runner = DetectionRunner::new();
        let rule = OCSFDetectionRule {
            meta: DetectionMetadata {
                id: "ocsf-test".into(),
                name: "OCSF Test".into(),
                severity: Severity::High,
                enabled: true,
                ..serde_json::from_str::<DetectionMetadata>(
                    r#"{"id":"ocsf-test","name":"OCSF Test","severity":"high"}"#,
                )
                .unwrap()
            },
            event_class: OCSFEventClass::ApiActivity,
            rule_filters: vec![FieldFilter {
                field: "status_id".into(),
                op: FilterOp::Equals("1".into()),
            }],
            threshold: 1,
            limit: 5000,
            group_by_fields: Vec::new(),
        };
        runner.register_rule(Box::new(rule));

        let connector = MockConnector {
            result: QueryResult::from_maps(vec![
                json_row!("status_id" => "1", "op" => "AttachUserPolicy"),
                json_row!("status_id" => "2", "op" => "ListBuckets"),
                json_row!("status_id" => "1", "op" => "PutRolePolicy"),
            ]),
        };
        let result = runner
            .run_rule("ocsf-test", &connector, None, None, 15)
            .await;
        assert!(result.triggered);
        // Mock ignores ColumnFilter, so all 3 rows survive (real connector would filter)
        assert_eq!(result.match_count, 3);
    }

    #[tokio::test]
    async fn run_ocsf_rule_with_post_query_filters() {
        // Contains/NotEquals/Regex filters stay as post-query filters.
        let mut runner = DetectionRunner::new();
        let rule = OCSFDetectionRule {
            meta: DetectionMetadata {
                id: "ocsf-post".into(),
                name: "OCSF Post".into(),
                severity: Severity::High,
                enabled: true,
                ..serde_json::from_str::<DetectionMetadata>(
                    r#"{"id":"ocsf-post","name":"OCSF Post","severity":"high"}"#,
                )
                .unwrap()
            },
            event_class: OCSFEventClass::ApiActivity,
            rule_filters: vec![FieldFilter {
                field: "op".into(),
                op: FilterOp::Contains("Policy".into()),
            }],
            threshold: 1,
            limit: 5000,
            group_by_fields: Vec::new(),
        };
        runner.register_rule(Box::new(rule));

        let connector = MockConnector {
            result: QueryResult::from_maps(vec![
                json_row!("status_id" => "1", "op" => "AttachUserPolicy"),
                json_row!("status_id" => "2", "op" => "ListBuckets"),
                json_row!("status_id" => "1", "op" => "PutRolePolicy"),
            ]),
        };
        let result = runner
            .run_rule("ocsf-post", &connector, None, None, 15)
            .await;
        assert!(result.triggered);
        assert_eq!(result.match_count, 2); // Contains("Policy") matches 2 of 3
    }

    #[test]
    fn split_filters_separates_pushable_and_post() {
        let filters = vec![
            FieldFilter {
                field: "api.operation".into(),
                op: FilterOp::Equals("GetCallerIdentity".into()),
            },
            FieldFilter {
                field: "status".into(),
                op: FilterOp::Contains("Success".into()),
            },
            FieldFilter {
                field: "api.service.name".into(),
                op: FilterOp::In(vec!["sts".into(), "iam".into()]),
            },
            FieldFilter {
                field: "actor".into(),
                op: FilterOp::NotEquals("root".into()),
            },
        ];
        let (pushdown, post) = super::split_filters(&filters);
        assert_eq!(pushdown.len(), 2); // Equals + In
        assert_eq!(post.len(), 2); // Contains + NotEquals
        assert!(
            matches!(&pushdown[0], ColumnFilter::StringEquals { path, .. } if path == "api.operation")
        );
        assert!(
            matches!(&pushdown[1], ColumnFilter::StringIn { path, .. } if path == "api.service.name")
        );
    }

    #[tokio::test]
    async fn run_all_runs_enabled_rules() {
        let mut runner = DetectionRunner::new();
        runner.register_rule(Box::new(sample_sql_rule()));

        let connector = MockConnector {
            result: QueryResult::from_maps(vec![json_row!("x" => 1)]),
        };
        let results = runner.run_all(&connector, None, None, 15).await;
        assert_eq!(results.len(), 1);
        assert!(results[0].triggered);
    }

    #[test]
    fn export_rules_to_dict() {
        let mut runner = DetectionRunner::new();
        runner.register_rule(Box::new(sample_sql_rule()));
        let dicts = runner.export_rules_to_dict();
        assert_eq!(dicts.len(), 1);
        assert_eq!(dicts[0]["id"], "test-rule");
    }

    #[test]
    fn load_yaml_rules_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("rules.yaml");
        let mut f = std::fs::File::create(&file_path).unwrap();
        writeln!(
            f,
            r#"- id: yaml-rule-1
  name: YAML Rule 1
  severity: high
  threshold: 1
  query: "SELECT * FROM t WHERE time >= TIMESTAMP '{{start_time}}'"
- id: yaml-rule-2
  name: YAML Rule 2
  severity: low
  threshold: 5
  query: "SELECT count(*) FROM t"
"#
        )
        .unwrap();

        let mut runner = DetectionRunner::new();
        let loaded = runner.load_rules_from_directory(dir.path());
        assert_eq!(loaded, 2);
        assert!(runner.get_rule("yaml-rule-1").is_some());
        assert!(runner.get_rule("yaml-rule-2").is_some());
    }

    #[test]
    fn load_yaml_dual_target_rule() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("dual.yaml");
        let mut f = std::fs::File::create(&file_path).unwrap();
        writeln!(
            f,
            r#"- id: dual-rule
  name: Dual Target Rule
  severity: medium
  queries:
    cloudwatch: "fields @timestamp | filter @message like /ERROR/"
    athena: "SELECT * FROM t WHERE severity >= 4"
"#
        )
        .unwrap();

        let mut runner = DetectionRunner::new();
        let loaded = runner.load_rules_from_directory(dir.path());
        assert_eq!(loaded, 1);

        let rule = runner.get_rule("dual-rule").unwrap();
        assert_eq!(rule.name(), "Dual Target Rule");
    }

    #[test]
    fn load_yaml_ocsf_rule() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("ocsf.yaml");
        let mut f = std::fs::File::create(&file_path).unwrap();
        writeln!(
            f,
            r#"id: detect-iam-priv-esc
name: IAM Privilege Escalation
severity: high
event_class: api_activity
limit: 5000
threshold: 1
filters:
  - field: api.operation
    in: [AttachUserPolicy, AttachRolePolicy, PutUserPolicy, PutRolePolicy]
  - field: status_id
    equals: "1"
"#
        )
        .unwrap();

        let mut runner = DetectionRunner::new();
        let loaded = runner.load_rules_from_directory(dir.path());
        assert_eq!(loaded, 1);

        let rule = runner.get_rule("detect-iam-priv-esc").unwrap();
        assert_eq!(rule.name(), "IAM Privilege Escalation");
        assert_eq!(rule.filters().len(), 2);

        let DetectionQuery::Ocsf { event_class, limit } = rule.build_query(Utc::now(), Utc::now())
        else {
            panic!("Expected OCSF query");
        };
        assert_eq!(event_class, OCSFEventClass::ApiActivity);
        assert_eq!(limit, 5000);
    }

    #[test]
    fn load_yaml_ocsf_rule_with_regex_filter() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("regex.yaml");
        let mut f = std::fs::File::create(&file_path).unwrap();
        writeln!(
            f,
            r#"id: regex-rule
name: Regex Rule
severity: medium
event_class: authentication
threshold: 1
filters:
  - field: actor.user.name
    regex: "^admin-\\d+$"
"#
        )
        .unwrap();

        let mut runner = DetectionRunner::new();
        let loaded = runner.load_rules_from_directory(dir.path());
        assert_eq!(loaded, 1);
        assert_eq!(runner.get_rule("regex-rule").unwrap().filters().len(), 1);
    }
}
