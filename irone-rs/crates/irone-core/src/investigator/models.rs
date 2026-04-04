use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::detections::DetectionResult;
use crate::graph::{
    AttackNarrative, EntityAnomalyScore, GraphPattern, InvestigationTimeline, SecurityGraph,
};

/// Everything Claude needs to analyze an investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationContext {
    /// The detection that triggered this investigation.
    pub detection: DetectionResult,
    /// The enriched security graph.
    pub graph: SecurityGraph,
    /// Timeline of events.
    pub timeline: InvestigationTimeline,
    /// Attack path narratives extracted from the graph.
    #[serde(default)]
    pub attack_paths: Vec<AttackNarrative>,
    /// Structural graph patterns detected.
    #[serde(default)]
    pub patterns: Vec<GraphPattern>,
    /// Entity anomaly scores (MAD-based).
    #[serde(default)]
    pub anomaly_scores: Vec<EntityAnomalyScore>,
    /// Additional context (e.g., previous investigations for same principal).
    #[serde(default)]
    pub additional_context: HashMap<String, Value>,
}

/// Claude's overall verdict on the investigation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiVerdict {
    /// Confirmed malicious activity requiring immediate response.
    TruePositive,
    /// Suspicious activity requiring further investigation.
    Suspicious,
    /// Likely benign but unusual — document and monitor.
    LikelyBenign,
    /// Confirmed false positive — tune the detection rule.
    FalsePositive,
    /// Insufficient data to make a determination.
    Inconclusive,
}

impl std::fmt::Display for AiVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruePositive => write!(f, "true_positive"),
            Self::Suspicious => write!(f, "suspicious"),
            Self::LikelyBenign => write!(f, "likely_benign"),
            Self::FalsePositive => write!(f, "false_positive"),
            Self::Inconclusive => write!(f, "inconclusive"),
        }
    }
}

/// Threat assessment with confidence scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAssessment {
    /// Overall verdict.
    pub verdict: AiVerdict,
    /// Confidence in the verdict (0.0 = no confidence, 1.0 = certain).
    pub confidence: f64,
    /// MITRE ATT&CK techniques identified in the activity.
    pub mitre_techniques: Vec<String>,
    /// Kill chain phases observed (ordered by attack progression).
    pub kill_chain_phases: Vec<String>,
    /// Estimated blast radius (what could be affected if this is real).
    pub blast_radius: String,
}

/// A recommended response action from the AI analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedAction {
    /// Priority (1 = highest).
    pub priority: u8,
    /// What to do.
    pub action: String,
    /// Why this action is recommended.
    pub rationale: String,
    /// Whether this can be automated or requires human judgment.
    pub automatable: bool,
}

/// Complete AI analysis of an investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationAnalysis {
    /// Investigation ID this analysis belongs to.
    pub investigation_id: String,
    /// When this analysis was generated.
    pub analyzed_at: DateTime<Utc>,
    /// Threat assessment with verdict and confidence.
    pub threat_assessment: ThreatAssessment,
    /// Executive summary (2-3 sentences for SOC manager).
    pub executive_summary: String,
    /// Detailed technical narrative of what happened.
    pub technical_narrative: String,
    /// Key findings (bulleted for SOC analyst).
    pub key_findings: Vec<String>,
    /// Recommended response actions (priority-ordered).
    pub recommended_actions: Vec<RecommendedAction>,
    /// Questions the analyst should investigate further.
    pub follow_up_questions: Vec<String>,
    /// Suggested detection rule improvements.
    pub detection_improvements: Vec<String>,
    /// Raw model output (for debugging/audit).
    #[serde(default)]
    pub raw_response: String,
    /// Model used for analysis.
    #[serde(default)]
    pub model: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detections::Severity;
    use crate::graph::SecurityGraph;

    #[test]
    fn verdict_display() {
        assert_eq!(AiVerdict::TruePositive.to_string(), "true_positive");
        assert_eq!(AiVerdict::FalsePositive.to_string(), "false_positive");
        assert_eq!(AiVerdict::Inconclusive.to_string(), "inconclusive");
    }

    #[test]
    fn verdict_serde_round_trip() {
        let verdict = AiVerdict::Suspicious;
        let json = serde_json::to_string(&verdict).unwrap();
        assert_eq!(json, "\"suspicious\"");
        let back: AiVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AiVerdict::Suspicious);
    }

    #[test]
    fn investigation_analysis_serializes() {
        let analysis = InvestigationAnalysis {
            investigation_id: "inv-001".into(),
            analyzed_at: Utc::now(),
            threat_assessment: ThreatAssessment {
                verdict: AiVerdict::TruePositive,
                confidence: 0.92,
                mitre_techniques: vec!["T1078.004".into(), "T1098.001".into()],
                kill_chain_phases: vec![
                    "Initial Access".into(),
                    "Persistence".into(),
                    "Credential Access".into(),
                ],
                blast_radius: "AWS account us-west-2, 3 IAM roles, 2 S3 buckets".into(),
            },
            executive_summary: "High-confidence credential compromise detected. An external IP \
                accessed the root account and created new access keys, indicating persistence \
                establishment."
                .into(),
            technical_narrative: "At 14:32 UTC, principal root authenticated from IP 198.51.100.1 \
                (AS12345, DigitalOcean NYC). Within 4 minutes, the actor created IAM access key \
                AKIA... and modified the S3 bucket policy on prod-data-lake to allow cross-account \
                access from account 999888777666."
                .into(),
            key_findings: vec![
                "Root account login from previously unseen IP (198.51.100.1)".into(),
                "New access key created within 4 minutes of login".into(),
                "S3 bucket policy modified to allow external account access".into(),
                "No MFA used for root console login".into(),
            ],
            recommended_actions: vec![
                RecommendedAction {
                    priority: 1,
                    action: "Deactivate the newly created access key AKIA...".into(),
                    rationale: "Immediate containment — the key is likely being used for \
                        persistent access"
                        .into(),
                    automatable: true,
                },
                RecommendedAction {
                    priority: 2,
                    action: "Revert S3 bucket policy to remove cross-account access".into(),
                    rationale: "The policy change enables data exfiltration to an \
                        attacker-controlled account"
                        .into(),
                    automatable: true,
                },
                RecommendedAction {
                    priority: 3,
                    action: "Reset root account password and enable MFA".into(),
                    rationale: "Root credentials are compromised; all sessions should be \
                        invalidated"
                        .into(),
                    automatable: false,
                },
            ],
            follow_up_questions: vec![
                "Has 198.51.100.1 appeared in any other account's logs?".into(),
                "What data was in the prod-data-lake bucket?".into(),
                "Has account 999888777666 been seen in threat intel feeds?".into(),
            ],
            detection_improvements: vec![
                "Add MFA status check to root-console-login rule".into(),
                "Create correlation rule: root login + key creation within 10 minutes".into(),
            ],
            raw_response: String::new(),
            model: "claude-sonnet-4-20250514".into(),
        };

        let json = serde_json::to_value(&analysis).unwrap();
        assert_eq!(json["threat_assessment"]["verdict"], "true_positive");
        assert_eq!(json["threat_assessment"]["confidence"], 0.92);
        assert_eq!(json["key_findings"].as_array().unwrap().len(), 4);
        assert_eq!(json["recommended_actions"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn investigation_context_serializes() {
        let ctx = InvestigationContext {
            detection: DetectionResult {
                rule_id: "CT-001".into(),
                rule_name: "Test".into(),
                triggered: true,
                severity: Severity::Critical,
                match_count: 1,
                matches: vec![],
                message: "test".into(),
                executed_at: Utc::now(),
                execution_time_ms: 50.0,
                error: None,
                mitre_attack: vec![],
                tags: vec![],
            },
            graph: SecurityGraph::new(),
            timeline: InvestigationTimeline::new("test"),
            attack_paths: vec![],
            patterns: vec![],
            anomaly_scores: vec![],
            additional_context: HashMap::new(),
        };
        assert!(serde_json::to_value(&ctx).is_ok());
    }

    #[test]
    fn recommended_action_ordering() {
        let actions = vec![
            RecommendedAction {
                priority: 3,
                action: "Third".into(),
                rationale: "".into(),
                automatable: false,
            },
            RecommendedAction {
                priority: 1,
                action: "First".into(),
                rationale: "".into(),
                automatable: true,
            },
            RecommendedAction {
                priority: 2,
                action: "Second".into(),
                rationale: "".into(),
                automatable: true,
            },
        ];
        let mut sorted = actions.clone();
        sorted.sort_by_key(|a| a.priority);
        assert_eq!(sorted[0].action, "First");
        assert_eq!(sorted[2].action, "Third");
    }
}
