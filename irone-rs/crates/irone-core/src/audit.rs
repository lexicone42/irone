//! OCSF-compatible audit logging.
//!
//! Emits structured JSON audit events via `tracing` that conform to the
//! OCSF v1.x schema. These events are written to `CloudWatch` Logs and can
//! be ingested back into Security Lake for self-monitoring.
//!
//! # OCSF Mapping
//!
//! | irone action | OCSF class | activity_id |
//! |---|---|---|
//! | API access | 6003 (API Activity) | 1 (Create), 2 (Read), 3 (Update), 4 (Delete) |
//! | Investigation lifecycle | 3004 (Entity Management) | 1 (Create), 3 (Update), 4 (Delete) |
//! | Detection run | 2004 (Detection Finding) | 1 (Create) |
//! | Authentication | 3002 (Authentication) | 1 (Logon), 2 (Logoff) |

use chrono::Utc;
use serde::Serialize;
use serde_json::Value;

/// OCSF activity IDs.
#[derive(Debug, Clone, Copy, Serialize)]
#[repr(u8)]
pub enum ActivityId {
    Create = 1,
    Read = 2,
    Update = 3,
    Delete = 4,
}

/// OCSF status IDs.
#[derive(Debug, Clone, Copy, Serialize)]
#[repr(u8)]
pub enum StatusId {
    Success = 1,
    Failure = 2,
}

/// OCSF severity IDs (matches the existing `Severity` enum but as numeric).
#[derive(Debug, Clone, Copy, Serialize)]
#[repr(u8)]
pub enum SeverityId {
    Informational = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

/// An OCSF-compatible audit event.
///
/// Structured to match OCSF v1.x base event fields. Serialized as JSON
/// and emitted via `tracing::info!` so it flows to `CloudWatch` Logs.
#[derive(Debug, Serialize)]
pub struct AuditEvent {
    /// OCSF schema version.
    pub metadata: AuditMetadata,
    /// OCSF event class UID (e.g., 6003 for API Activity).
    pub class_uid: u32,
    /// Activity within the class (Create/Read/Update/Delete).
    pub activity_id: u8,
    /// Human-readable activity name.
    pub activity_name: String,
    /// RFC 3339 timestamp.
    pub time: String,
    /// Outcome status.
    pub status_id: u8,
    pub status: String,
    /// Severity of the action.
    pub severity_id: u8,
    /// Who performed the action.
    pub actor: AuditActor,
    /// What was acted upon.
    pub resource: AuditResource,
    /// Human-readable description.
    pub message: String,
    /// Additional context.
    #[serde(skip_serializing_if = "Value::is_null")]
    pub unmapped: Value,
}

#[derive(Debug, Serialize)]
pub struct AuditMetadata {
    pub product: AuditProduct,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct AuditProduct {
    pub name: &'static str,
    pub vendor_name: &'static str,
}

#[derive(Debug, Serialize)]
pub struct AuditActor {
    /// User identity (email, service-token, or "system").
    pub user: String,
    /// Source IP if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuditResource {
    /// Resource type (e.g., "investigation", "detection", "source").
    #[serde(rename = "type")]
    pub resource_type: String,
    /// Resource identifier.
    pub uid: String,
    /// Human-readable name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl AuditEvent {
    fn new(
        class_uid: u32,
        activity: ActivityId,
        activity_name: impl Into<String>,
        actor: &str,
        resource_type: impl Into<String>,
        resource_uid: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            metadata: AuditMetadata {
                product: AuditProduct {
                    name: "irone",
                    vendor_name: "lexicone",
                },
                version: "1.1.0",
            },
            class_uid,
            activity_id: activity as u8,
            activity_name: activity_name.into(),
            time: Utc::now().to_rfc3339(),
            status_id: StatusId::Success as u8,
            status: "Success".into(),
            severity_id: SeverityId::Informational as u8,
            actor: AuditActor {
                user: actor.into(),
                src_ip: None,
            },
            resource: AuditResource {
                resource_type: resource_type.into(),
                uid: resource_uid.into(),
                name: None,
            },
            message: message.into(),
            unmapped: Value::Null,
        }
    }

    /// Mark this event as a failure.
    #[must_use]
    pub fn with_failure(mut self, error: &str) -> Self {
        self.status_id = StatusId::Failure as u8;
        self.status = format!("Failure: {error}");
        self
    }

    /// Set source IP.
    #[must_use]
    pub fn with_src_ip(mut self, ip: impl Into<String>) -> Self {
        self.actor.src_ip = Some(ip.into());
        self
    }

    /// Set resource name.
    #[must_use]
    pub fn with_resource_name(mut self, name: impl Into<String>) -> Self {
        self.resource.name = Some(name.into());
        self
    }

    /// Set severity.
    #[must_use]
    pub fn with_severity(mut self, severity: SeverityId) -> Self {
        self.severity_id = severity as u8;
        self
    }

    /// Add extra context fields.
    #[must_use]
    pub fn with_unmapped(mut self, data: Value) -> Self {
        self.unmapped = data;
        self
    }

    /// Emit the audit event as a structured JSON log line.
    pub fn emit(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            tracing::info!(
                target: "audit",
                ocsf_event = %json,
                class_uid = self.class_uid,
                activity_id = self.activity_id,
                actor = %self.actor.user,
                resource_type = %self.resource.resource_type,
                resource_uid = %self.resource.uid,
                "audit"
            );
        }
    }
}

// -- Convenience constructors for common audit events --

/// Log an investigation creation.
pub fn investigation_created(actor: &str, investigation_id: &str, name: &str) {
    AuditEvent::new(
        3004, // Entity Management
        ActivityId::Create,
        "Create",
        actor,
        "investigation",
        investigation_id,
        format!("Investigation created: {name}"),
    )
    .with_resource_name(name)
    .emit();
}

/// Log an investigation deletion.
pub fn investigation_deleted(actor: &str, investigation_id: &str) {
    AuditEvent::new(
        3004,
        ActivityId::Delete,
        "Delete",
        actor,
        "investigation",
        investigation_id,
        format!("Investigation deleted: {investigation_id}"),
    )
    .emit();
}

/// Log an investigation enrichment.
pub fn investigation_enriched(
    actor: &str,
    investigation_id: &str,
    node_count: usize,
    edge_count: usize,
) {
    AuditEvent::new(
        3004,
        ActivityId::Update,
        "Update",
        actor,
        "investigation",
        investigation_id,
        format!("Investigation enriched: {node_count} nodes, {edge_count} edges"),
    )
    .with_unmapped(serde_json::json!({
        "node_count": node_count,
        "edge_count": edge_count,
    }))
    .emit();
}

/// Log a detection run.
pub fn detection_run(actor: &str, rules_checked: usize, triggered: usize) {
    AuditEvent::new(
        2004, // Detection Finding
        ActivityId::Create,
        "Create",
        actor,
        "detection_run",
        Utc::now().to_rfc3339(),
        format!("Detection run: {rules_checked} rules, {triggered} triggered"),
    )
    .with_severity(if triggered > 0 {
        SeverityId::Medium
    } else {
        SeverityId::Informational
    })
    .with_unmapped(serde_json::json!({
        "rules_checked": rules_checked,
        "triggered": triggered,
    }))
    .emit();
}

/// Log an API access event.
pub fn api_access(actor: &str, method: &str, path: &str, status: u16) {
    let activity = match method {
        "POST" => ActivityId::Create,
        "PUT" | "PATCH" => ActivityId::Update,
        "DELETE" => ActivityId::Delete,
        _ => ActivityId::Read,
    };

    let mut event = AuditEvent::new(
        6003, // API Activity
        activity,
        method,
        actor,
        "api_endpoint",
        path,
        format!("{method} {path} -> {status}"),
    );

    if status >= 400 {
        event = event.with_failure(&format!("HTTP {status}"));
        if status >= 500 {
            event = event.with_severity(SeverityId::High);
        } else {
            event = event.with_severity(SeverityId::Low);
        }
    }

    event.emit();
}

/// Log a timeline event tagging action.
pub fn timeline_event_tagged(actor: &str, investigation_id: &str, event_id: &str, tag: &str) {
    AuditEvent::new(
        3004,
        ActivityId::Update,
        "Update",
        actor,
        "timeline_event",
        event_id,
        format!("Timeline event tagged as '{tag}' in investigation {investigation_id}"),
    )
    .with_unmapped(serde_json::json!({
        "investigation_id": investigation_id,
        "tag": tag,
    }))
    .emit();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_serializes_to_ocsf() {
        let event = AuditEvent::new(
            6003,
            ActivityId::Read,
            "Read",
            "test@example.com",
            "investigation",
            "inv-123",
            "Test audit event",
        )
        .with_src_ip("10.0.0.1")
        .with_resource_name("Test Investigation");

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 6003);
        assert_eq!(json["activity_id"], 2);
        assert_eq!(json["activity_name"], "Read");
        assert_eq!(json["status_id"], 1);
        assert_eq!(json["actor"]["user"], "test@example.com");
        assert_eq!(json["actor"]["src_ip"], "10.0.0.1");
        assert_eq!(json["resource"]["type"], "investigation");
        assert_eq!(json["resource"]["uid"], "inv-123");
        assert_eq!(json["resource"]["name"], "Test Investigation");
        assert_eq!(json["metadata"]["product"]["name"], "irone");
        assert_eq!(json["metadata"]["version"], "1.1.0");
    }

    #[test]
    fn audit_event_failure() {
        let event = AuditEvent::new(
            6003,
            ActivityId::Create,
            "Create",
            "system",
            "detection_run",
            "run-1",
            "Detection failed",
        )
        .with_failure("permission denied");

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["status_id"], 2);
        assert!(
            json["status"]
                .as_str()
                .unwrap()
                .contains("permission denied")
        );
    }

    #[test]
    fn audit_event_skips_null_unmapped() {
        let event = AuditEvent::new(
            3004,
            ActivityId::Delete,
            "Delete",
            "admin",
            "investigation",
            "inv-456",
            "Deleted",
        );

        let json = serde_json::to_value(&event).unwrap();
        assert!(!json.as_object().unwrap().contains_key("unmapped"));
    }

    #[test]
    fn audit_event_includes_unmapped_when_set() {
        let event = AuditEvent::new(
            2004,
            ActivityId::Create,
            "Create",
            "alerting",
            "detection_run",
            "run-1",
            "Detection run",
        )
        .with_unmapped(serde_json::json!({"rules_checked": 37}));

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["unmapped"]["rules_checked"], 37);
    }

    #[test]
    fn severity_levels() {
        let event = AuditEvent::new(
            6003,
            ActivityId::Read,
            "Read",
            "user",
            "api",
            "/health",
            "Health check",
        )
        .with_severity(SeverityId::Critical);

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["severity_id"], 5);
    }
}
