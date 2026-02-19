mod rule;
mod runner;

pub use rule::{
    DetectionMetadata, DetectionQuery, DetectionResult, DetectionRule, DualTargetDetectionRule,
    FieldFilter, FilterOp, OCSFDetectionRule, QueryTarget, SQLDetectionRule, Severity,
    apply_filters,
};
pub use runner::DetectionRunner;
