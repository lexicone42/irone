//! Prompt construction for Claude-powered investigation analysis.
//!
//! Converts investigation artifacts into a structured prompt that produces
//! consistent, actionable security analysis from Claude.

use std::fmt::Write;

use crate::detections::Severity;
use crate::graph::{
    AttackNarrative, EntityAnomalyScore, GraphPattern, NodeType, SecurityGraph, TimelineEvent,
};

use super::models::InvestigationContext;

/// Build the full investigation prompt for Claude.
#[must_use]
pub fn build_investigation_prompt(ctx: &InvestigationContext) -> String {
    [
        system_preamble(),
        format_detection(&ctx.detection),
        format_graph_summary(&ctx.graph),
        format_timeline(&ctx.timeline.events),
        format_attack_paths(&ctx.attack_paths),
        format_patterns(&ctx.patterns),
        format_anomalies(&ctx.anomaly_scores),
        response_format(),
    ]
    .join("\n\n")
}

fn system_preamble() -> String {
    "You are an expert security analyst performing incident triage on a detection \
     that fired in a cloud environment. You have access to the full investigation \
     context: the original detection, an enriched entity-relationship graph, a \
     chronological timeline, extracted attack paths, structural graph patterns, \
     and statistical anomaly scores.\n\n\
     Your job is to determine:\n\
     1. **Verdict**: Is this a true positive, suspicious, likely benign, false positive, or inconclusive?\n\
     2. **Confidence**: How confident are you (0.0\u{2013}1.0)?\n\
     3. **What happened**: Reconstruct the activity narrative from the evidence.\n\
     4. **What to do**: Prioritized response actions.\n\
     5. **What to investigate next**: Questions that need answers.\n\n\
     Be direct and specific. Name entities, IPs, timestamps, and API calls. \
     Don't hedge \u{2014} commit to a verdict based on the evidence and explain your reasoning."
        .into()
}

fn format_detection(det: &crate::detections::DetectionResult) -> String {
    let severity_label = match det.severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    };

    let mut s = format!(
        "## Detection Alert\n\
         - **Rule**: {} ({})\n\
         - **Severity**: {severity_label}\n\
         - **Triggered**: {} ({} matches)\n\
         - **Time**: {}\n\
         - **Message**: {}",
        det.rule_name, det.rule_id, det.triggered, det.match_count, det.executed_at, det.message,
    );

    if !det.mitre_attack.is_empty() {
        let _ = write!(s, "\n- **MITRE ATT&CK**: {}", det.mitre_attack.join(", "));
    }
    if !det.tags.is_empty() {
        let _ = write!(s, "\n- **Tags**: {}", det.tags.join(", "));
    }

    // Include up to 5 sample matches
    if !det.matches.is_empty() {
        s.push_str("\n\n### Sample Matches\n```json\n");
        let sample: Vec<_> = det.matches.iter().take(5).collect();
        if let Ok(json) = serde_json::to_string_pretty(&sample) {
            s.push_str(&json);
        }
        s.push_str("\n```");
    }

    s
}

#[allow(clippy::too_many_lines)]
fn format_graph_summary(graph: &SecurityGraph) -> String {
    let summary = graph.summary();
    let mut s = format!(
        "## Investigation Graph\n\
         - **Nodes**: {} total\n\
         - **Edges**: {} total",
        summary.total_nodes, summary.total_edges,
    );

    for (node_type, count) in &summary.nodes_by_type {
        let _ = write!(s, "\n- **{node_type}**: {count}");
    }

    let principals: Vec<_> = graph
        .nodes
        .values()
        .filter(|n| n.node_type == NodeType::Principal)
        .collect();
    if !principals.is_empty() {
        s.push_str("\n\n### Principals");
        for p in principals.iter().take(10) {
            let user_type = p
                .properties
                .get("user_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let account = p
                .properties
                .get("account_id")
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            let _ = write!(
                s,
                "\n- `{}` (type: {user_type}, account: {account}, events: {})",
                p.label, p.event_count
            );
        }
    }

    let ips: Vec<_> = graph
        .nodes
        .values()
        .filter(|n| n.node_type == NodeType::IPAddress)
        .collect();
    if !ips.is_empty() {
        s.push_str("\n\n### IP Addresses");
        for ip in ips.iter().take(10) {
            let geo = ip
                .properties
                .get("geo_country")
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            let asn = ip
                .properties
                .get("asn")
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            let internal = ip
                .properties
                .get("is_internal")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let _ = write!(
                s,
                "\n- `{}` (country: {geo}, ASN: {asn}, internal: {internal}, events: {})",
                ip.label, ip.event_count
            );
        }
    }

    let resources: Vec<_> = graph
        .nodes
        .values()
        .filter(|n| n.node_type == NodeType::Resource)
        .collect();
    if !resources.is_empty() {
        s.push_str("\n\n### Resources");
        for r in resources.iter().take(15) {
            let _ = write!(s, "\n- `{}`", r.label);
        }
    }

    let ops: Vec<_> = graph
        .nodes
        .values()
        .filter(|n| n.node_type == NodeType::APIOperation)
        .collect();
    if !ops.is_empty() {
        s.push_str("\n\n### API Operations");
        for op in ops.iter().take(20) {
            let success = op
                .properties
                .get("success_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let failure = op
                .properties
                .get("failure_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let _ = write!(
                s,
                "\n- `{}` (success: {success}, failure: {failure}, total events: {})",
                op.label, op.event_count
            );
        }
    }

    s
}

fn format_timeline(events: &[TimelineEvent]) -> String {
    if events.is_empty() {
        return "## Timeline\nNo timeline events available.".into();
    }

    let mut s = format!("## Timeline ({} events)\n", events.len());

    for event in events.iter().take(30) {
        let tag = format!("{:?}", event.tag);
        let op = if event.operation.is_empty() {
            "-"
        } else {
            &event.operation
        };
        let _ = write!(
            s,
            "\n- **{}** [{tag}] `{}` \u{2014} {} ({op})",
            event.timestamp.format("%H:%M:%S"),
            event.entity_id,
            event.title,
        );
    }

    if events.len() > 30 {
        let _ = write!(s, "\n\n... and {} more events", events.len() - 30);
    }

    s
}

fn format_attack_paths(paths: &[AttackNarrative]) -> String {
    if paths.is_empty() {
        return "## Attack Paths\nNo attack paths extracted.".into();
    }

    let mut s = format!("## Attack Paths ({} narratives)\n", paths.len());

    for (i, narrative) in paths.iter().enumerate() {
        let phases = narrative
            .phases_observed
            .iter()
            .map(|p| format!("{p:?}"))
            .collect::<Vec<_>>()
            .join(" \u{2192} ");
        let entry = narrative.entry_point.as_deref().unwrap_or("unknown");
        let _ = write!(
            s,
            "\n### Path {} \u{2014} {}\n\
             - **Summary**: {}\n\
             - **Phases**: {phases}\n\
             - **Actors**: {}\n\
             - **Entry Point**: {entry}\n\
             - **Impact**: {}",
            i + 1,
            narrative.finding_label,
            narrative.summary,
            narrative.actors.join(", "),
            narrative.impact_assessment,
        );

        for step in &narrative.steps {
            let ts = match step.timestamp {
                Some(t) => t.format("%H:%M:%S").to_string(),
                None => "??:??:??".into(),
            };
            let actor = step.actor.as_deref().unwrap_or("?");
            let target = step.target.as_deref().unwrap_or("?");
            let _ = write!(
                s,
                "\n  {ts} | {:?} | `{actor}` \u{2192} `{}` \u{2192} `{target}`",
                step.phase, step.action,
            );
        }
    }

    s
}

fn format_patterns(patterns: &[GraphPattern]) -> String {
    if patterns.is_empty() {
        return "## Graph Patterns\nNo structural patterns detected.".into();
    }

    let mut s = format!("## Graph Patterns ({} detected)\n", patterns.len());

    for pattern in patterns {
        let _ = write!(
            s,
            "\n### {:?} (severity: {:.2})\n\
             - **Description**: {}\n\
             - **Analysis Hint**: {}\n\
             - **Involved Nodes**: {}",
            pattern.pattern_type,
            pattern.severity,
            pattern.description,
            pattern.analysis_hint,
            pattern.involved_nodes.join(", "),
        );
    }

    s
}

fn format_anomalies(scores: &[EntityAnomalyScore]) -> String {
    if scores.is_empty() {
        return "## Anomaly Scores\nNo anomaly scores computed.".into();
    }

    let mut s = format!(
        "## Anomaly Scores (MAD-based, {} entities)\n\
         Entities with z-score >= 3.5 are statistical outliers.\n",
        scores.len()
    );

    for score in scores.iter().take(10) {
        let flag = if score.z_score >= 3.5 {
            " [OUTLIER]"
        } else {
            ""
        };
        let _ = write!(
            s,
            "\n- `{}` ({}) \u{2014} events: {}, median: {:.1}, MAD: {:.1}, z-score: {:.2}{flag}",
            score.entity, score.kind, score.event_count, score.median, score.mad, score.z_score,
        );
    }

    s
}

fn response_format() -> String {
    "## Instructions\n\n\
     Analyze the investigation context above and respond with a JSON object matching this exact schema:\n\n\
     ```json\n\
     {\n\
       \"verdict\": \"true_positive\" | \"suspicious\" | \"likely_benign\" | \"false_positive\" | \"inconclusive\",\n\
       \"confidence\": 0.0-1.0,\n\
       \"mitre_techniques\": [\"T1078\", ...],\n\
       \"kill_chain_phases\": [\"Initial Access\", \"Persistence\", ...],\n\
       \"blast_radius\": \"Description of what's affected\",\n\
       \"executive_summary\": \"2-3 sentence summary for SOC manager\",\n\
       \"technical_narrative\": \"Detailed reconstruction of the activity\",\n\
       \"key_findings\": [\"Finding 1\", \"Finding 2\", ...],\n\
       \"recommended_actions\": [\n\
         {\n\
           \"priority\": 1,\n\
           \"action\": \"What to do\",\n\
           \"rationale\": \"Why\",\n\
           \"automatable\": true/false\n\
         }\n\
       ],\n\
       \"follow_up_questions\": [\"Question 1\", ...],\n\
       \"detection_improvements\": [\"Improvement 1\", ...]\n\
     }\n\
     ```\n\n\
     Be specific. Use actual entity names, IPs, timestamps, and API operations from the evidence. \
     If the graph shows AWS service-to-service traffic (e.g., Config, CloudFormation, Amplify acting \
     as principals), note this as likely benign unless the operation is inherently dangerous."
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detections::{DetectionResult, Severity};
    use crate::graph::{InvestigationTimeline, SecurityGraph};
    use std::collections::HashMap;

    fn sample_context() -> InvestigationContext {
        InvestigationContext {
            detection: DetectionResult {
                rule_id: "detect-root-console-login".into(),
                rule_name: "Root Console Login".into(),
                triggered: true,
                severity: Severity::Critical,
                match_count: 1,
                matches: vec![{
                    let mut m = serde_json::Map::new();
                    m.insert(
                        "actor".into(),
                        serde_json::json!({"user": {"name": "root", "type": "Root"}}),
                    );
                    m.insert(
                        "api".into(),
                        serde_json::json!({"operation": "ConsoleLogin"}),
                    );
                    m.insert("time".into(), serde_json::json!("2026-04-03T14:32:00Z"));
                    m.insert(
                        "src_endpoint".into(),
                        serde_json::json!({"ip": "198.51.100.1"}),
                    );
                    m
                }],
                message: "Root account console login detected".into(),
                executed_at: chrono::Utc::now(),
                execution_time_ms: 150.0,
                error: None,
                mitre_attack: vec!["T1078.004".into()],
                tags: vec!["auth".into(), "root".into()],
            },
            graph: SecurityGraph::new(),
            timeline: InvestigationTimeline::new("inv-test"),
            attack_paths: vec![],
            patterns: vec![],
            anomaly_scores: vec![],
            additional_context: HashMap::new(),
        }
    }

    #[test]
    fn prompt_includes_all_sections() {
        let ctx = sample_context();
        let prompt = build_investigation_prompt(&ctx);

        assert!(prompt.contains("## Detection Alert"));
        assert!(prompt.contains("Root Console Login"));
        assert!(prompt.contains("CRITICAL"));
        assert!(prompt.contains("T1078.004"));
        assert!(prompt.contains("## Investigation Graph"));
        assert!(prompt.contains("## Timeline"));
        assert!(prompt.contains("## Attack Paths"));
        assert!(prompt.contains("## Graph Patterns"));
        assert!(prompt.contains("## Anomaly Scores"));
        assert!(prompt.contains("## Instructions"));
        assert!(prompt.contains("true_positive"));
    }

    #[test]
    fn prompt_includes_sample_matches() {
        let ctx = sample_context();
        let prompt = build_investigation_prompt(&ctx);

        assert!(prompt.contains("Sample Matches"));
        assert!(prompt.contains("ConsoleLogin"));
        assert!(prompt.contains("198.51.100.1"));
    }

    #[test]
    fn prompt_handles_empty_context() {
        let ctx = InvestigationContext {
            detection: DetectionResult {
                rule_id: "test".into(),
                rule_name: "Test".into(),
                triggered: false,
                severity: Severity::Info,
                match_count: 0,
                matches: vec![],
                message: "No matches".into(),
                executed_at: chrono::Utc::now(),
                execution_time_ms: 10.0,
                error: None,
                mitre_attack: vec![],
                tags: vec![],
            },
            graph: SecurityGraph::new(),
            timeline: InvestigationTimeline::new("empty"),
            attack_paths: vec![],
            patterns: vec![],
            anomaly_scores: vec![],
            additional_context: HashMap::new(),
        };
        let prompt = build_investigation_prompt(&ctx);
        assert!(prompt.contains("## Detection Alert"));
        assert!(prompt.contains("No timeline events"));
        assert!(prompt.contains("No attack paths"));
        assert!(prompt.contains("No structural patterns"));
    }

    #[test]
    fn prompt_limits_entities() {
        let mut graph = SecurityGraph::new();
        for i in 0..50 {
            use crate::graph::{GraphNode, NodeType};
            graph.add_node(GraphNode {
                id: format!("Principal:user-{i}"),
                node_type: NodeType::Principal,
                label: format!("user-{i}"),
                properties: HashMap::new(),
                first_seen: Some(chrono::Utc::now()),
                last_seen: Some(chrono::Utc::now()),
                event_count: 1,
            });
        }
        let section = format_graph_summary(&graph);
        let principal_count = section.matches("user-").count();
        assert!(
            principal_count <= 10,
            "should limit principals to 10, got {principal_count}"
        );
    }
}
