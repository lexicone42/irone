use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::result::QueryResult;

/// OCSF event class IDs commonly found in Security Lake.
///
/// Values follow the OCSF v1.x schema numbering:
/// - 1xxx: System Activity
/// - 2xxx: Findings
/// - 3xxx: Identity & Access Management
/// - 4xxx: Network Activity
/// - 6xxx: Application Activity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum OCSFEventClass {
    // System Activity (1xxx)
    FileActivity = 1001,
    KernelExtension = 1002,
    KernelActivity = 1003,
    MemoryActivity = 1004,
    ModuleActivity = 1005,
    ScheduledJobActivity = 1006,
    ProcessActivity = 1007,

    // Findings (2xxx)
    SecurityFinding = 2001,
    VulnerabilityFinding = 2002,
    ComplianceFinding = 2003,
    DetectionFinding = 2004,
    IncidentFinding = 2005,

    // Identity & Access Management (3xxx)
    AccountChange = 3001,
    Authentication = 3002,
    AuthorizeSession = 3003,
    EntityManagement = 3004,
    UserAccessManagement = 3005,
    GroupManagement = 3006,

    // Network Activity (4xxx)
    NetworkActivity = 4001,
    HttpActivity = 4002,
    DnsActivity = 4003,
    DhcpActivity = 4004,
    RdpActivity = 4005,
    SmbActivity = 4006,
    SshActivity = 4007,
    FtpActivity = 4008,
    EmailActivity = 4009,
    NetworkFileActivity = 4010,
    EmailFileActivity = 4011,
    EmailUrlActivity = 4012,
    NtpActivity = 4013,
    TunnelActivity = 4014,

    // Application Activity (6xxx)
    WebResourceAccessActivity = 6001,
    ApplicationLifecycle = 6002,
    ApiActivity = 6003,
    WebResourceActivity = 6004,
    DatastoreActivity = 6005,
    FileHostingActivity = 6006,
    ScanActivity = 6007,
}

impl OCSFEventClass {
    /// Get the numeric class UID.
    #[must_use]
    pub const fn class_uid(self) -> u32 {
        self as u32
    }

    /// Get a human-readable name for the event class.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::FileActivity => "File Activity",
            Self::KernelExtension => "Kernel Extension",
            Self::KernelActivity => "Kernel Activity",
            Self::MemoryActivity => "Memory Activity",
            Self::ModuleActivity => "Module Activity",
            Self::ScheduledJobActivity => "Scheduled Job Activity",
            Self::ProcessActivity => "Process Activity",
            Self::SecurityFinding => "Security Finding",
            Self::VulnerabilityFinding => "Vulnerability Finding",
            Self::ComplianceFinding => "Compliance Finding",
            Self::DetectionFinding => "Detection Finding",
            Self::IncidentFinding => "Incident Finding",
            Self::AccountChange => "Account Change",
            Self::Authentication => "Authentication",
            Self::AuthorizeSession => "Authorize Session",
            Self::EntityManagement => "Entity Management",
            Self::UserAccessManagement => "User Access Management",
            Self::GroupManagement => "Group Management",
            Self::NetworkActivity => "Network Activity",
            Self::HttpActivity => "HTTP Activity",
            Self::DnsActivity => "DNS Activity",
            Self::DhcpActivity => "DHCP Activity",
            Self::RdpActivity => "RDP Activity",
            Self::SmbActivity => "SMB Activity",
            Self::SshActivity => "SSH Activity",
            Self::FtpActivity => "FTP Activity",
            Self::EmailActivity => "Email Activity",
            Self::NetworkFileActivity => "Network File Activity",
            Self::EmailFileActivity => "Email File Activity",
            Self::EmailUrlActivity => "Email URL Activity",
            Self::NtpActivity => "NTP Activity",
            Self::TunnelActivity => "Tunnel Activity",
            Self::WebResourceAccessActivity => "Web Resource Access Activity",
            Self::ApplicationLifecycle => "Application Lifecycle",
            Self::ApiActivity => "API Activity",
            Self::WebResourceActivity => "Web Resource Activity",
            Self::DatastoreActivity => "Datastore Activity",
            Self::FileHostingActivity => "File Hosting Activity",
            Self::ScanActivity => "Scan Activity",
        }
    }
}

impl std::fmt::Display for OCSFEventClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Error type for Security Lake query operations.
#[derive(Debug, thiserror::Error)]
pub enum SecurityLakeError {
    #[error("query failed: {0}")]
    QueryFailed(String),
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Trait for Security Lake OCSF-aware query operations.
///
/// Defined in `iris-core` for dependency inversion: `GraphBuilder` and
/// `SecurityLakeEnricher` depend on this trait, while `iris-aws` provides
/// the concrete implementation.
#[allow(async_fn_in_trait)]
pub trait SecurityLakeQueries: Send + Sync {
    /// Query events by OCSF event class ID within a time window.
    async fn query_by_event_class(
        &self,
        event_class: OCSFEventClass,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
        additional_filters: Option<&str>,
    ) -> Result<QueryResult, SecurityLakeError>;

    /// Query authentication events (class 3002).
    async fn query_authentication_events(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        status: Option<&str>,
        limit: usize,
    ) -> Result<QueryResult, SecurityLakeError>;

    /// Query API activity events (class 6003).
    async fn query_api_activity(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        service: Option<&str>,
        operation: Option<&str>,
        limit: usize,
    ) -> Result<QueryResult, SecurityLakeError>;

    /// Query network activity events (class 4001).
    async fn query_network_activity(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        src_ip: Option<&str>,
        dst_ip: Option<&str>,
        dst_port: Option<u16>,
        limit: usize,
    ) -> Result<QueryResult, SecurityLakeError>;

    /// Query security findings (class 2001).
    async fn query_security_findings(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        severity: Option<&str>,
        limit: usize,
    ) -> Result<QueryResult, SecurityLakeError>;

    /// Get a summary of events by class over a time window.
    async fn get_event_summary(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<QueryResult, SecurityLakeError>;
}

/// Format a `DateTime<Utc>` to the Athena TIMESTAMP literal format.
///
/// Athena expects: `YYYY-MM-DD HH:MM:SS.ffffff` (no T, no timezone).
#[must_use]
pub fn format_athena_timestamp(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
}

/// Extract a value from OCSF event data using a dot-notation path.
///
/// Tries the flat key first (e.g. `"actor.user.name"` as a literal key),
/// then navigates nested JSON objects. Returns a cloned value since nested
/// traversal may cross ownership boundaries.
#[must_use]
pub fn get_nested_value(data: &serde_json::Map<String, Value>, path: &str) -> Option<Value> {
    // Try direct flat key
    if let Some(val) = data.get(path)
        && !val.is_null()
    {
        return Some(val.clone());
    }

    // Navigate nested structure
    let parts: Vec<&str> = path.split('.').collect();
    let mut current: &Value = data.get(parts[0])?;
    for part in &parts[1..] {
        match current {
            Value::Object(map) => {
                current = map.get(*part)?;
            }
            _ => return None,
        }
    }
    if current.is_null() {
        None
    } else {
        Some(current.clone())
    }
}

/// Extract a string value from OCSF event data, trying multiple paths.
#[must_use]
pub fn get_nested_str(data: &serde_json::Map<String, Value>, paths: &[&str]) -> Option<String> {
    for path in paths {
        if let Some(val) = get_nested_value(data, path)
            && let Some(s) = val.as_str()
            && !s.is_empty()
        {
            return Some(s.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ocsf_class_uid_values() {
        assert_eq!(OCSFEventClass::Authentication.class_uid(), 3002);
        assert_eq!(OCSFEventClass::ApiActivity.class_uid(), 6003);
        assert_eq!(OCSFEventClass::NetworkActivity.class_uid(), 4001);
        assert_eq!(OCSFEventClass::SecurityFinding.class_uid(), 2001);
        assert_eq!(OCSFEventClass::FileActivity.class_uid(), 1001);
    }

    #[test]
    fn ocsf_serde_roundtrip() {
        let cls = OCSFEventClass::Authentication;
        let json = serde_json::to_string(&cls).unwrap();
        let back: OCSFEventClass = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cls);
    }

    #[test]
    fn ocsf_display() {
        assert_eq!(OCSFEventClass::Authentication.to_string(), "Authentication");
        assert_eq!(OCSFEventClass::ApiActivity.to_string(), "API Activity");
        assert_eq!(
            OCSFEventClass::NetworkActivity.to_string(),
            "Network Activity"
        );
    }

    #[test]
    fn format_athena_timestamp_format() {
        let dt = chrono::DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let formatted = format_athena_timestamp(&dt);
        assert_eq!(formatted, "2024-01-15 10:30:00.000000");
    }

    #[test]
    fn get_nested_value_flat_key() {
        let mut data = serde_json::Map::new();
        data.insert("actor.user.name".to_string(), json!("alice"));
        let val = get_nested_value(&data, "actor.user.name");
        assert_eq!(val, Some(json!("alice")));
    }

    #[test]
    fn get_nested_value_deep_path() {
        let data: serde_json::Map<String, Value> =
            serde_json::from_str(r#"{"actor": {"user": {"name": "bob"}}}"#).unwrap();
        let val = get_nested_value(&data, "actor.user.name");
        assert_eq!(val, Some(json!("bob")));
    }

    #[test]
    fn get_nested_value_missing() {
        let data = serde_json::Map::new();
        assert!(get_nested_value(&data, "missing.path").is_none());
    }

    #[test]
    fn get_nested_str_tries_multiple_paths() {
        let mut data = serde_json::Map::new();
        data.insert("user_name".to_string(), json!("charlie"));
        let result = get_nested_str(&data, &["actor.user.name", "user_name"]);
        assert_eq!(result, Some("charlie".to_string()));
    }
}
