//! AI-powered investigation analysis using Claude.
//!
//! Takes investigation artifacts (graph, timeline, patterns, anomalies, attack
//! paths) and produces structured analysis: threat assessment, confidence level,
//! recommended response actions, and investigation narrative.

mod client;
mod models;
mod prompt;

pub use client::ClaudeInvestigator;
pub use models::{
    AiVerdict, InvestigationAnalysis, InvestigationContext, RecommendedAction, ThreatAssessment,
};
pub use prompt::build_investigation_prompt;
