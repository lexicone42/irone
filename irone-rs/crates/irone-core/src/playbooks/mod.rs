//! SOAR Playbook Engine
//!
//! Declarative playbooks that map detection triggers to automated response
//! actions. Each playbook defines trigger conditions (severity, rule tags,
//! MITRE techniques) and a sequence of response actions with approval gates.

mod models;
mod runner;

pub use models::{
    Action, ActionStatus, ActionType, ApprovalRequirement, PlaybookResult, PlaybookTrigger,
    ResponseAction, ResponsePlaybook,
};
pub use runner::PlaybookRunner;
