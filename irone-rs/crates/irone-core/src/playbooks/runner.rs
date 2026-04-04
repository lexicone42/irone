use chrono::Utc;

use crate::detections::DetectionResult;

use super::models::{
    Action, ActionStatus, ApprovalRequirement, PlaybookResult, PlaybookStatus, ResponsePlaybook,
};

/// Evaluates playbooks against detection results and orchestrates response actions.
pub struct PlaybookRunner {
    playbooks: Vec<ResponsePlaybook>,
}

impl PlaybookRunner {
    #[must_use]
    pub fn new() -> Self {
        Self {
            playbooks: Vec::new(),
        }
    }

    /// Register a playbook.
    pub fn register(&mut self, playbook: ResponsePlaybook) {
        self.playbooks.push(playbook);
    }

    /// Return all registered playbooks.
    #[must_use]
    pub fn list_playbooks(&self) -> &[ResponsePlaybook] {
        &self.playbooks
    }

    /// Find all playbooks that should trigger for a given detection result.
    #[must_use]
    pub fn match_playbooks(&self, detection: &DetectionResult) -> Vec<&ResponsePlaybook> {
        if !detection.triggered {
            return vec![];
        }
        self.playbooks
            .iter()
            .filter(|pb| {
                pb.enabled
                    && pb.trigger.matches(
                        &detection.severity,
                        &detection.rule_id,
                        &detection.tags,
                        &detection.mitre_attack,
                    )
            })
            .collect()
    }

    /// Evaluate a detection result and produce playbook execution plans.
    ///
    /// This is a *dry run* — it builds the action list with statuses set based
    /// on approval requirements but doesn't execute anything. The caller (Lambda
    /// or CLI) is responsible for actually executing the actions via cloud APIs.
    #[must_use]
    pub fn evaluate(
        &self,
        detection: &DetectionResult,
        investigation_id: &str,
    ) -> Vec<PlaybookResult> {
        let matched = self.match_playbooks(detection);
        let now = Utc::now();

        matched
            .into_iter()
            .map(|pb| {
                let actions: Vec<Action> = pb
                    .actions
                    .iter()
                    .map(|ra| {
                        let status = match ra.approval {
                            ApprovalRequirement::Auto => ActionStatus::Pending,
                            ApprovalRequirement::Manual => ActionStatus::AwaitingApproval,
                            ApprovalRequirement::BusinessHoursOnly => {
                                if is_business_hours() {
                                    ActionStatus::Pending
                                } else {
                                    ActionStatus::AwaitingApproval
                                }
                            }
                        };
                        Action {
                            action_name: ra.name.clone(),
                            action_type: ra.action_type.clone(),
                            status,
                            started_at: None,
                            completed_at: None,
                            output: None,
                            error: None,
                        }
                    })
                    .collect();

                let has_awaiting = actions
                    .iter()
                    .any(|a| a.status == ActionStatus::AwaitingApproval);
                let status = if has_awaiting {
                    PlaybookStatus::AwaitingApproval
                } else {
                    PlaybookStatus::Running
                };

                PlaybookResult {
                    playbook_id: pb.id.clone(),
                    playbook_name: pb.name.clone(),
                    investigation_id: investigation_id.into(),
                    triggered_at: now,
                    actions,
                    status,
                }
            })
            .collect()
    }

    /// Load playbooks from YAML files in a directory.
    pub fn load_from_directory(&mut self, dir: &std::path::Path) -> usize {
        let mut count = 0;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "yaml" || e == "yml")
                    && let Ok(contents) = std::fs::read_to_string(&path)
                {
                    match serde_yaml::from_str::<ResponsePlaybook>(&contents) {
                        Ok(pb) => {
                            self.register(pb);
                            count += 1;
                        }
                        Err(e) => {
                            tracing::warn!(path = %path.display(), error = %e, "failed to parse playbook");
                        }
                    }
                }
            }
        }
        count
    }
}

impl Default for PlaybookRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple business hours check (9am–6pm UTC, weekdays).
fn is_business_hours() -> bool {
    use chrono::{Datelike, Timelike};
    let now = Utc::now();
    let hour = now.time().hour();
    let weekday = now.weekday();
    matches!(
        weekday,
        chrono::Weekday::Mon
            | chrono::Weekday::Tue
            | chrono::Weekday::Wed
            | chrono::Weekday::Thu
            | chrono::Weekday::Fri
    ) && (9..18).contains(&hour)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detections::Severity;
    use crate::playbooks::models::{
        ActionType, ApprovalRequirement, PlaybookTrigger, ResponseAction,
    };
    use std::collections::HashMap;

    fn credential_compromise_playbook() -> ResponsePlaybook {
        ResponsePlaybook {
            id: "pb-credential-compromise".into(),
            name: "Credential Compromise Response".into(),
            description: "Automated response for credential theft".into(),
            trigger: PlaybookTrigger {
                min_severity: Severity::High,
                rule_ids: vec![],
                tags: vec!["credential-access".into(), "persistence".into()],
                mitre_techniques: vec![],
            },
            actions: vec![
                ResponseAction {
                    name: "Revoke compromised credentials".into(),
                    action_type: ActionType::RevokeCredentials,
                    approval: ApprovalRequirement::Auto,
                    parameters: HashMap::new(),
                    timeout_seconds: 300,
                },
                ResponseAction {
                    name: "Snapshot evidence".into(),
                    action_type: ActionType::SnapshotEvidence,
                    approval: ApprovalRequirement::Auto,
                    parameters: HashMap::new(),
                    timeout_seconds: 600,
                },
                ResponseAction {
                    name: "Isolate resource".into(),
                    action_type: ActionType::IsolateResource,
                    approval: ApprovalRequirement::Manual,
                    parameters: HashMap::new(),
                    timeout_seconds: 3600,
                },
            ],
            enabled: true,
        }
    }

    fn k8s_container_escape_playbook() -> ResponsePlaybook {
        ResponsePlaybook {
            id: "pb-k8s-container-escape".into(),
            name: "K8s Container Escape Response".into(),
            description: "Automated response for container breakout".into(),
            trigger: PlaybookTrigger {
                min_severity: Severity::Critical,
                rule_ids: vec!["detect-eks-privileged-pod".into()],
                tags: vec![],
                mitre_techniques: vec!["T1611".into()],
            },
            actions: vec![
                ResponseAction {
                    name: "Quarantine pod".into(),
                    action_type: ActionType::QuarantinePod,
                    approval: ApprovalRequirement::Auto,
                    parameters: HashMap::new(),
                    timeout_seconds: 120,
                },
                ResponseAction {
                    name: "Disable service account".into(),
                    action_type: ActionType::DisableServiceAccount,
                    approval: ApprovalRequirement::Auto,
                    parameters: HashMap::new(),
                    timeout_seconds: 300,
                },
                ResponseAction {
                    name: "Scale deployment to zero".into(),
                    action_type: ActionType::ScaleToZero,
                    approval: ApprovalRequirement::Manual,
                    parameters: HashMap::new(),
                    timeout_seconds: 1800,
                },
            ],
            enabled: true,
        }
    }

    fn sample_detection(
        rule_id: &str,
        severity: Severity,
        tags: Vec<String>,
        mitre: Vec<String>,
    ) -> DetectionResult {
        DetectionResult {
            rule_id: rule_id.into(),
            rule_name: "Test Rule".into(),
            triggered: true,
            severity,
            match_count: 5,
            matches: vec![],
            message: "Test detection".into(),
            executed_at: Utc::now(),
            execution_time_ms: 100.0,
            error: None,
            mitre_attack: mitre,
            tags,
        }
    }

    #[test]
    fn runner_matches_playbook_by_tag() {
        let mut runner = PlaybookRunner::new();
        runner.register(credential_compromise_playbook());

        let detection = sample_detection(
            "detect-eks-secret-access",
            Severity::High,
            vec!["credential-access".into(), "kubernetes".into()],
            vec!["T1552.007".into()],
        );
        let matched = runner.match_playbooks(&detection);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].id, "pb-credential-compromise");
    }

    #[test]
    fn runner_skips_untriggered_detection() {
        let mut runner = PlaybookRunner::new();
        runner.register(credential_compromise_playbook());

        let mut detection = sample_detection(
            "detect-eks-secret-access",
            Severity::High,
            vec!["credential-access".into()],
            vec![],
        );
        detection.triggered = false;
        let matched = runner.match_playbooks(&detection);
        assert!(matched.is_empty());
    }

    #[test]
    fn runner_matches_by_rule_id_and_mitre() {
        let mut runner = PlaybookRunner::new();
        runner.register(k8s_container_escape_playbook());

        let detection = sample_detection(
            "detect-eks-privileged-pod",
            Severity::Critical,
            vec!["privilege-escalation".into()],
            vec!["T1611".into()],
        );
        let matched = runner.match_playbooks(&detection);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].id, "pb-k8s-container-escape");
    }

    #[test]
    fn runner_rejects_wrong_rule_id() {
        let mut runner = PlaybookRunner::new();
        runner.register(k8s_container_escape_playbook());

        let detection = sample_detection(
            "detect-eks-kubectl-exec",
            Severity::Critical,
            vec![],
            vec!["T1611".into()],
        );
        // Wrong rule_id — playbook requires detect-eks-privileged-pod
        let matched = runner.match_playbooks(&detection);
        assert!(matched.is_empty());
    }

    #[test]
    fn evaluate_produces_action_plan() {
        let mut runner = PlaybookRunner::new();
        runner.register(credential_compromise_playbook());

        let detection = sample_detection(
            "detect-access-key-created",
            Severity::High,
            vec!["persistence".into()],
            vec!["T1098.001".into()],
        );
        let results = runner.evaluate(&detection, "inv-456");
        assert_eq!(results.len(), 1);

        let result = &results[0];
        assert_eq!(result.investigation_id, "inv-456");
        assert_eq!(result.actions.len(), 3);

        // First two actions are auto-approved → Pending
        assert_eq!(result.actions[0].status, ActionStatus::Pending);
        assert_eq!(result.actions[0].action_type, ActionType::RevokeCredentials);
        assert_eq!(result.actions[1].status, ActionStatus::Pending);
        assert_eq!(result.actions[1].action_type, ActionType::SnapshotEvidence);

        // Third action requires manual approval
        assert_eq!(result.actions[2].status, ActionStatus::AwaitingApproval);
        assert_eq!(result.actions[2].action_type, ActionType::IsolateResource);

        // Overall status should be AwaitingApproval since one action needs it
        assert_eq!(result.status, PlaybookStatus::AwaitingApproval);
    }

    #[test]
    fn multiple_playbooks_can_match() {
        let mut runner = PlaybookRunner::new();
        runner.register(credential_compromise_playbook());
        runner.register(k8s_container_escape_playbook());

        // This detection matches the credential playbook but not k8s (wrong rule_id)
        let detection = sample_detection(
            "detect-eks-secret-access",
            Severity::Critical,
            vec!["credential-access".into()],
            vec!["T1611".into()],
        );
        let matched = runner.match_playbooks(&detection);
        // Only credential playbook matches (k8s requires specific rule_id)
        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn disabled_playbook_not_matched() {
        let mut runner = PlaybookRunner::new();
        let mut pb = credential_compromise_playbook();
        pb.enabled = false;
        runner.register(pb);

        let detection = sample_detection(
            "any",
            Severity::Critical,
            vec!["credential-access".into()],
            vec![],
        );
        assert!(runner.match_playbooks(&detection).is_empty());
    }

    #[test]
    fn evaluate_empty_for_no_match() {
        let runner = PlaybookRunner::new();
        let detection = sample_detection("any", Severity::Info, vec![], vec![]);
        let results = runner.evaluate(&detection, "inv-789");
        assert!(results.is_empty());
    }

    #[test]
    fn playbook_runner_default() {
        let runner = PlaybookRunner::default();
        assert!(runner.list_playbooks().is_empty());
    }
}
