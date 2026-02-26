//! Embedded test cases for detection rules.
//!
//! Test cases live inside rule YAML files under a `test_cases` key.
//! Each test case provides synthetic events and expected outcomes,
//! validated by the integration test in `tests/rule_test_cases.rs`.

use serde_json::Value;

use super::rule::{FieldFilter, Severity, apply_filters, threshold_evaluate};
use crate::connectors::result::QueryResult;

/// A single test case parsed from a rule's `test_cases` YAML array.
#[derive(Debug, Clone)]
pub struct RuleTestCase {
    pub name: String,
    pub events: Vec<serde_json::Map<String, Value>>,
    pub expected: TestExpectation,
}

/// Expected outcome of a test case.
#[derive(Debug, Clone)]
pub struct TestExpectation {
    pub triggered: bool,
    pub match_count: Option<usize>,
    pub threshold_override: Option<usize>,
}

/// Parse `test_cases` from a raw YAML mapping (the top-level rule definition).
///
/// Returns an empty vec if no `test_cases` key exists — backwards compatible.
pub fn parse_test_cases(
    map: &serde_yaml::Mapping,
) -> Result<Vec<RuleTestCase>, Box<dyn std::error::Error>> {
    let key = serde_yaml::Value::String("test_cases".into());
    let Some(val) = map.get(&key) else {
        return Ok(Vec::new());
    };

    let seq = val.as_sequence().ok_or("'test_cases' must be a sequence")?;

    let mut cases = Vec::new();
    for item in seq {
        let tc_map = item
            .as_mapping()
            .ok_or("Each test_case must be a mapping")?;

        let name = tc_map
            .get(serde_yaml::Value::String("name".into()))
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or("unnamed")
            .to_string();

        // Parse events: a sequence of flat key-value maps
        let events = parse_events(tc_map)?;

        // Parse expected outcomes
        let expected = parse_expectation(tc_map)?;

        cases.push(RuleTestCase {
            name,
            events,
            expected,
        });
    }

    Ok(cases)
}

/// Convert YAML event maps to `serde_json::Map` with all values as strings.
///
/// This mirrors how OCSF data arrives from connectors — field values are strings
/// that `FieldFilter::matches` compares with `as_str()`.
fn parse_events(
    tc_map: &serde_yaml::Mapping,
) -> Result<Vec<serde_json::Map<String, Value>>, Box<dyn std::error::Error>> {
    let key = serde_yaml::Value::String("events".into());
    let events_val = tc_map.get(&key).ok_or("test_case must have 'events'")?;
    let events_seq = events_val
        .as_sequence()
        .ok_or("'events' must be a sequence")?;

    let mut rows = Vec::new();
    for event_val in events_seq {
        let event_map = event_val
            .as_mapping()
            .ok_or("Each event must be a mapping")?;

        let mut row = serde_json::Map::new();
        for (k, v) in event_map {
            let key_str = k.as_str().ok_or("Event keys must be strings")?.to_string();
            // Convert all values to JSON strings for filter compatibility
            let val_str = match v {
                serde_yaml::Value::String(s) => Value::String(s.clone()),
                serde_yaml::Value::Number(n) => Value::String(n.to_string()),
                serde_yaml::Value::Bool(b) => Value::String(b.to_string()),
                _ => Value::String(format!("{v:?}")),
            };
            row.insert(key_str, val_str);
        }
        rows.push(row);
    }

    Ok(rows)
}

fn parse_expectation(
    tc_map: &serde_yaml::Mapping,
) -> Result<TestExpectation, Box<dyn std::error::Error>> {
    let key = serde_yaml::Value::String("expected".into());
    let exp_val = tc_map.get(&key).ok_or("test_case must have 'expected'")?;
    let exp_map = exp_val.as_mapping().ok_or("'expected' must be a mapping")?;

    let triggered = exp_map
        .get(serde_yaml::Value::String("triggered".into()))
        .and_then(serde_yaml::Value::as_bool)
        .ok_or("'expected.triggered' must be a boolean")?;

    #[allow(clippy::cast_possible_truncation)]
    let match_count = exp_map
        .get(serde_yaml::Value::String("match_count".into()))
        .and_then(serde_yaml::Value::as_u64)
        .map(|n| n as usize);

    #[allow(clippy::cast_possible_truncation)]
    let threshold_override = exp_map
        .get(serde_yaml::Value::String("threshold_override".into()))
        .and_then(serde_yaml::Value::as_u64)
        .map(|n| n as usize);

    Ok(TestExpectation {
        triggered,
        match_count,
        threshold_override,
    })
}

/// Evaluate a single test case against a rule's filters and threshold.
///
/// Returns `Ok(())` on success, `Err(message)` on assertion failure.
pub fn evaluate_test_case(
    rule_id: &str,
    rule_name: &str,
    severity: &Severity,
    filters: &[FieldFilter],
    threshold: usize,
    test_case: &RuleTestCase,
) -> Result<(), String> {
    let qr = QueryResult::from_maps(test_case.events.clone());

    // Apply all filters (no pushdown split in tests — we test the full filter chain)
    let filtered = apply_filters(&qr, filters);
    let eval_qr = filtered.as_ref().unwrap_or(&qr);

    let effective_threshold = test_case.expected.threshold_override.unwrap_or(threshold);
    let result = threshold_evaluate(
        rule_id,
        rule_name,
        severity,
        eval_qr,
        effective_threshold,
        &[],
        &[],
    );

    let mut errors = Vec::new();

    if result.triggered != test_case.expected.triggered {
        errors.push(format!(
            "triggered: expected {}, got {} (match_count={}, threshold={})",
            test_case.expected.triggered, result.triggered, result.match_count, effective_threshold,
        ));
    }

    if let Some(expected_count) = test_case.expected.match_count
        && result.match_count != expected_count
    {
        errors.push(format!(
            "match_count: expected {}, got {}",
            expected_count, result.match_count,
        ));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "[{}] test '{}': {}",
            rule_id,
            test_case.name,
            errors.join("; "),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::rule::FilterOp;
    use super::*;

    #[test]
    fn parse_test_cases_missing_key() {
        let map = serde_yaml::Mapping::new();
        let cases = parse_test_cases(&map).unwrap();
        assert!(cases.is_empty());
    }

    #[test]
    fn parse_and_evaluate_simple() {
        let yaml = r"
test_cases:
  - name: triggers on match
    events:
      - status: Success
    expected:
      triggered: true
  - name: no trigger on empty
    events: []
    expected:
      triggered: false
";
        let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let map = val.as_mapping().unwrap();
        let cases = parse_test_cases(map).unwrap();
        assert_eq!(cases.len(), 2);

        // First case: one event, no filters, threshold 1 → triggered
        let r = evaluate_test_case("test", "Test", &Severity::High, &[], 1, &cases[0]);
        assert!(r.is_ok(), "Expected Ok, got: {r:?}");

        // Second case: no events, threshold 1 → not triggered
        let r = evaluate_test_case("test", "Test", &Severity::High, &[], 1, &cases[1]);
        assert!(r.is_ok(), "Expected Ok, got: {r:?}");
    }

    #[test]
    fn threshold_override_works() {
        let yaml = r"
test_cases:
  - name: override threshold
    events:
      - x: '1'
    expected:
      triggered: true
      threshold_override: 1
";
        let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let cases = parse_test_cases(val.as_mapping().unwrap()).unwrap();

        // Rule threshold is 100, but override is 1 → triggers
        let r = evaluate_test_case("test", "Test", &Severity::Medium, &[], 100, &cases[0]);
        assert!(r.is_ok());
    }

    #[test]
    fn numeric_yaml_values_become_strings() {
        let yaml = r"
test_cases:
  - name: numeric coercion
    events:
      - rcode_id: 3
    expected:
      triggered: true
";
        let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let cases = parse_test_cases(val.as_mapping().unwrap()).unwrap();

        // rcode_id: 3 in YAML → "3" as string → matches Equals("3") filter
        let filters = vec![FieldFilter {
            field: "rcode_id".into(),
            op: FilterOp::Equals("3".into()),
        }];
        let r = evaluate_test_case("test", "Test", &Severity::Medium, &filters, 1, &cases[0]);
        assert!(r.is_ok(), "Expected Ok, got: {r:?}");
    }
}
