use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use tracing::{debug, info, warn};

use super::rule::{
    DetectionMetadata, DetectionResult, DetectionRule, DualTargetDetectionRule, SQLDetectionRule,
    Severity,
};
use crate::connectors::base::DataConnector;

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

    /// Run a single detection rule.
    pub fn run_rule(
        &self,
        rule_id: &str,
        connector: &dyn DataConnector,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        lookback_minutes: i64,
    ) -> DetectionResult {
        let Some(rule) = self.rules.get(rule_id) else {
            return DetectionResult::not_found(rule_id);
        };

        let end = end.unwrap_or_else(Utc::now);
        let start = start.unwrap_or_else(|| end - Duration::minutes(lookback_minutes));

        let query = rule.get_query(start, end);
        debug!(
            rule_id,
            query_preview = &query[..query.len().min(200)],
            "Executing detection query"
        );

        match connector.query(&query) {
            Ok(qr) => {
                let result = rule.evaluate(&qr);
                info!(
                    rule_id,
                    triggered = result.triggered,
                    match_count = result.match_count,
                    "Detection completed"
                );
                result
            }
            Err(e) => {
                warn!(rule_id, error = %e, "Detection rule failed");
                DetectionResult::error(rule_id, rule.name(), &e.to_string())
            }
        }
    }

    /// Run all enabled detection rules.
    pub fn run_all(
        &self,
        connector: &dyn DataConnector,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        lookback_minutes: i64,
    ) -> Vec<DetectionResult> {
        self.rules
            .iter()
            .filter(|(_, r)| r.metadata().enabled)
            .map(|(id, _)| self.run_rule(id, connector, start, end, lookback_minutes))
            .collect()
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
/// - `SQLDetectionRule`: Traditional SQL/Athena queries (has `query` field)
/// - `DualTargetDetectionRule`: Rules with `queries` dict or `log_type: cloudwatch_logs`
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

        if has_queries || log_type == "cloudwatch_logs" {
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::connectors::result::QueryResult;
    use crate::json_row;

    /// A mock connector that returns preset results.
    struct MockConnector {
        result: QueryResult,
    }

    impl DataConnector for MockConnector {
        fn query(
            &self,
            _sql: &str,
        ) -> Result<QueryResult, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.result.clone())
        }
        fn get_schema(
            &self,
        ) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(HashMap::new())
        }
        fn check_health(
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

    #[test]
    fn run_rule_not_found() {
        let runner = DetectionRunner::new();
        let connector = MockConnector {
            result: QueryResult::empty(),
        };
        let result = runner.run_rule("missing", &connector, None, None, 15);
        assert!(result.error.is_some());
    }

    #[test]
    fn run_rule_triggers() {
        let mut runner = DetectionRunner::new();
        runner.register_rule(Box::new(sample_sql_rule()));

        let connector = MockConnector {
            result: QueryResult::from_maps(vec![
                json_row!("user" => "alice"),
                json_row!("user" => "bob"),
            ]),
        };
        let result = runner.run_rule("test-rule", &connector, None, None, 15);
        assert!(result.triggered);
        assert_eq!(result.match_count, 2);
    }

    #[test]
    fn run_all_runs_enabled_rules() {
        let mut runner = DetectionRunner::new();
        runner.register_rule(Box::new(sample_sql_rule()));

        let connector = MockConnector {
            result: QueryResult::from_maps(vec![json_row!("x" => 1)]),
        };
        let results = runner.run_all(&connector, None, None, 15);
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
}
