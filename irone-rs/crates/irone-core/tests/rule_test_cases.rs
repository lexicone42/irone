//! Integration test: evaluate embedded test cases in rule YAML files.
//!
//! Discovers all `rules/*.yaml` files, parses `test_cases` from each,
//! loads the rule via `DetectionRunner` to obtain filters/threshold/severity,
//! and evaluates every test case. Fails with a collected summary of all failures.

use std::path::PathBuf;

use irone_core::detections::DetectionRunner;
use irone_core::detections::test_case::{evaluate_test_case, parse_test_cases};

fn rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("rules")
}

#[test]
fn all_rule_test_cases_pass() {
    let dir = rules_dir();
    assert!(dir.is_dir(), "Rules directory not found: {}", dir.display());

    // Load all rules into a runner to access filters/threshold/severity
    let mut runner = DetectionRunner::new();
    let loaded = runner.load_rules_from_directory(&dir);
    assert!(loaded > 0, "No rules loaded from {}", dir.display());

    let mut total_cases = 0;
    let mut failures = Vec::new();

    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("Failed to read rules directory")
        .flatten()
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext == "yaml")
        })
        .collect();
    entries.sort_by_key(std::fs::DirEntry::path);

    for entry in entries {
        let path = entry.path();
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));

        let yaml: serde_yaml::Value = serde_yaml::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse {}: {e}", path.display()));

        // Handle both single-rule and multi-rule YAML files
        let rule_defs: Vec<&serde_yaml::Mapping> = match &yaml {
            serde_yaml::Value::Sequence(seq) => seq
                .iter()
                .filter_map(serde_yaml::Value::as_mapping)
                .collect(),
            serde_yaml::Value::Mapping(m) => vec![m],
            _ => continue,
        };

        for rule_map in rule_defs {
            let test_cases = parse_test_cases(rule_map).unwrap_or_else(|e| {
                panic!("Failed to parse test_cases in {}: {e}", path.display())
            });

            if test_cases.is_empty() {
                continue;
            }

            // Get rule ID to look up loaded rule
            let rule_id = rule_map
                .get(serde_yaml::Value::String("id".into()))
                .and_then(serde_yaml::Value::as_str)
                .unwrap_or_else(|| panic!("Rule in {} has no id", path.display()));

            let rule = runner
                .get_rule(rule_id)
                .unwrap_or_else(|| panic!("Rule '{rule_id}' not found in runner"));

            for tc in &test_cases {
                total_cases += 1;
                if let Err(msg) = evaluate_test_case(
                    rule_id,
                    rule.name(),
                    &rule.metadata().severity,
                    rule.filters(),
                    rule.threshold(),
                    tc,
                ) {
                    failures.push(msg);
                }
            }
        }
    }

    assert!(
        total_cases > 0,
        "No test cases found in any rule YAML files. Add test_cases to at least one rule."
    );

    assert!(
        failures.is_empty(),
        "\n{} of {} rule test cases failed:\n  - {}\n",
        failures.len(),
        total_cases,
        failures.join("\n  - "),
    );

    eprintln!("All {total_cases} rule test cases passed.");
}
