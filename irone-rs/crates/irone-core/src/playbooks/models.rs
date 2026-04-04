use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::detections::Severity;

/// When a playbook should fire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookTrigger {
    /// Minimum severity to activate (e.g., `High` means High + Critical).
    pub min_severity: Severity,
    /// If set, only trigger for detections with matching rule IDs.
    #[serde(default)]
    pub rule_ids: Vec<String>,
    /// If set, only trigger when detection has any of these tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// If set, only trigger when detection maps to any of these MITRE techniques.
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
}

impl PlaybookTrigger {
    /// Check whether a detection result matches this trigger.
    #[must_use]
    pub fn matches(
        &self,
        severity: &Severity,
        rule_id: &str,
        tags: &[String],
        mitre: &[String],
    ) -> bool {
        if !severity_gte(severity, &self.min_severity) {
            return false;
        }
        if !self.rule_ids.is_empty() && !self.rule_ids.iter().any(|r| r == rule_id) {
            return false;
        }
        if !self.tags.is_empty() && !self.tags.iter().any(|t| tags.contains(t)) {
            return false;
        }
        if !self.mitre_techniques.is_empty()
            && !self.mitre_techniques.iter().any(|m| mitre.contains(m))
        {
            return false;
        }
        true
    }
}

/// Compare severity levels for >= ordering.
fn severity_gte(actual: &Severity, minimum: &Severity) -> bool {
    severity_ord(actual) >= severity_ord(minimum)
}

fn severity_ord(s: &Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Types of automated response actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    /// Isolate an AWS resource (e.g., apply deny-all security group to EC2).
    IsolateResource,
    /// Revoke IAM credentials (deactivate access keys, invalidate sessions).
    RevokeCredentials,
    /// Snapshot evidence (EBS snapshot, S3 bucket versioning, pod export).
    SnapshotEvidence,
    /// Quarantine a Kubernetes pod (set to `CrashLoopBackOff` or cordon node).
    QuarantinePod,
    /// Block an IP address (NACL deny rule or WAF IP set).
    BlockIp,
    /// Send notification to a channel (Slack, `PagerDuty`, SNS).
    Notify,
    /// Create a ticket in an external system (Jira, Linear).
    CreateTicket,
    /// Run a custom Lambda function for bespoke response.
    InvokeLambda,
    /// Disable a Kubernetes service account.
    DisableServiceAccount,
    /// Scale a deployment to zero replicas.
    ScaleToZero,
}

/// Whether human approval is required before execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRequirement {
    /// Execute immediately without approval.
    Auto,
    /// Require human approval before execution.
    Manual,
    /// Auto-approve during business hours, require manual off-hours.
    BusinessHoursOnly,
}

/// A single response action within a playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub name: String,
    pub action_type: ActionType,
    pub approval: ApprovalRequirement,
    /// Action-specific parameters (e.g., security group ID, SNS topic ARN).
    #[serde(default)]
    pub parameters: HashMap<String, Value>,
    /// Maximum time to wait for approval before auto-skipping (seconds).
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    3600
}

/// A complete response playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePlaybook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub trigger: PlaybookTrigger,
    pub actions: Vec<ResponseAction>,
    #[serde(default)]
    pub enabled: bool,
}

/// Status of an individual action execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Pending,
    AwaitingApproval,
    Approved,
    Executing,
    Completed,
    Failed,
    Skipped,
    TimedOut,
}

/// Result of executing a single action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub action_name: String,
    pub action_type: ActionType,
    pub status: ActionStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub output: Option<String>,
    pub error: Option<String>,
}

/// Result of running a complete playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookResult {
    pub playbook_id: String,
    pub playbook_name: String,
    pub investigation_id: String,
    pub triggered_at: DateTime<Utc>,
    pub actions: Vec<Action>,
    pub status: PlaybookStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookStatus {
    Running,
    Completed,
    PartiallyCompleted,
    Failed,
    AwaitingApproval,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_trigger() -> PlaybookTrigger {
        PlaybookTrigger {
            min_severity: Severity::High,
            rule_ids: vec![],
            tags: vec!["privilege-escalation".into()],
            mitre_techniques: vec![],
        }
    }

    #[test]
    fn trigger_matches_severity_and_tag() {
        let trigger = sample_trigger();
        assert!(trigger.matches(
            &Severity::Critical,
            "CT-001",
            &["privilege-escalation".into(), "iam".into()],
            &[],
        ));
    }

    #[test]
    fn trigger_rejects_low_severity() {
        let trigger = sample_trigger();
        assert!(!trigger.matches(
            &Severity::Medium,
            "CT-001",
            &["privilege-escalation".into()],
            &[],
        ));
    }

    #[test]
    fn trigger_rejects_missing_tag() {
        let trigger = sample_trigger();
        assert!(!trigger.matches(
            &Severity::Critical,
            "CT-001",
            &["defense-evasion".into()],
            &[],
        ));
    }

    #[test]
    fn trigger_with_mitre_filter() {
        let trigger = PlaybookTrigger {
            min_severity: Severity::Medium,
            rule_ids: vec![],
            tags: vec![],
            mitre_techniques: vec!["T1078".into()],
        };
        assert!(trigger.matches(
            &Severity::High,
            "any",
            &[],
            &["T1078".into(), "T1110".into()],
        ));
        assert!(!trigger.matches(&Severity::High, "any", &[], &["T1110".into()],));
    }

    #[test]
    fn trigger_with_rule_id_filter() {
        let trigger = PlaybookTrigger {
            min_severity: Severity::Info,
            rule_ids: vec!["detect-eks-privileged-pod".into()],
            tags: vec![],
            mitre_techniques: vec![],
        };
        assert!(trigger.matches(&Severity::Critical, "detect-eks-privileged-pod", &[], &[],));
        assert!(!trigger.matches(&Severity::Critical, "detect-eks-kubectl-exec", &[], &[],));
    }

    #[test]
    fn trigger_empty_filters_match_any() {
        let trigger = PlaybookTrigger {
            min_severity: Severity::High,
            rule_ids: vec![],
            tags: vec![],
            mitre_techniques: vec![],
        };
        // Empty optional filters = match any (only severity matters)
        assert!(trigger.matches(&Severity::High, "anything", &[], &[]));
        assert!(!trigger.matches(&Severity::Medium, "anything", &[], &[]));
    }

    #[test]
    fn severity_ordering() {
        assert!(severity_gte(&Severity::Critical, &Severity::Info));
        assert!(severity_gte(&Severity::High, &Severity::High));
        assert!(!severity_gte(&Severity::Medium, &Severity::High));
        assert!(severity_gte(&Severity::Info, &Severity::Info));
    }

    #[test]
    fn playbook_serializes() {
        let playbook = ResponsePlaybook {
            id: "pb-001".into(),
            name: "Credential Compromise Response".into(),
            description: "Automated response for credential theft detections".into(),
            trigger: sample_trigger(),
            actions: vec![
                ResponseAction {
                    name: "Revoke compromised credentials".into(),
                    action_type: ActionType::RevokeCredentials,
                    approval: ApprovalRequirement::Auto,
                    parameters: HashMap::new(),
                    timeout_seconds: 300,
                },
                ResponseAction {
                    name: "Notify security team".into(),
                    action_type: ActionType::Notify,
                    approval: ApprovalRequirement::Auto,
                    parameters: HashMap::from([(
                        "channel".into(),
                        Value::String("#security-alerts".into()),
                    )]),
                    timeout_seconds: 60,
                },
                ResponseAction {
                    name: "Isolate affected instance".into(),
                    action_type: ActionType::IsolateResource,
                    approval: ApprovalRequirement::Manual,
                    parameters: HashMap::new(),
                    timeout_seconds: 3600,
                },
            ],
            enabled: true,
        };
        let json = serde_json::to_value(&playbook).unwrap();
        assert_eq!(json["id"], "pb-001");
        assert_eq!(json["actions"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn action_status_lifecycle() {
        let action = Action {
            action_name: "Revoke keys".into(),
            action_type: ActionType::RevokeCredentials,
            status: ActionStatus::Completed,
            started_at: Some(Utc::now()),
            completed_at: Some(Utc::now()),
            output: Some("Deactivated AKIA1234".into()),
            error: None,
        };
        let json = serde_json::to_value(&action).unwrap();
        assert_eq!(json["status"], "completed");
    }

    #[test]
    fn playbook_result_serializes() {
        let result = PlaybookResult {
            playbook_id: "pb-001".into(),
            playbook_name: "Test".into(),
            investigation_id: "inv-123".into(),
            triggered_at: Utc::now(),
            actions: vec![],
            status: PlaybookStatus::Completed,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["status"], "completed");
    }
}
