use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::result::QueryResult;
use super::sql_utils::sanitize_string;

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

    /// Parse a `snake_case` YAML string into an `OCSFEventClass`.
    ///
    /// Accepts the canonical `snake_case` names used in detection rule YAML files.
    #[must_use]
    pub fn from_yaml_str(s: &str) -> Option<Self> {
        match s {
            "file_activity" => Some(Self::FileActivity),
            "kernel_extension" => Some(Self::KernelExtension),
            "kernel_activity" => Some(Self::KernelActivity),
            "memory_activity" => Some(Self::MemoryActivity),
            "module_activity" => Some(Self::ModuleActivity),
            "scheduled_job_activity" => Some(Self::ScheduledJobActivity),
            "process_activity" => Some(Self::ProcessActivity),
            "security_finding" => Some(Self::SecurityFinding),
            "vulnerability_finding" => Some(Self::VulnerabilityFinding),
            "compliance_finding" => Some(Self::ComplianceFinding),
            "detection_finding" => Some(Self::DetectionFinding),
            "incident_finding" => Some(Self::IncidentFinding),
            "account_change" => Some(Self::AccountChange),
            "authentication" => Some(Self::Authentication),
            "authorize_session" => Some(Self::AuthorizeSession),
            "entity_management" => Some(Self::EntityManagement),
            "user_access_management" => Some(Self::UserAccessManagement),
            "group_management" => Some(Self::GroupManagement),
            "network_activity" => Some(Self::NetworkActivity),
            "http_activity" => Some(Self::HttpActivity),
            "dns_activity" => Some(Self::DnsActivity),
            "dhcp_activity" => Some(Self::DhcpActivity),
            "rdp_activity" => Some(Self::RdpActivity),
            "smb_activity" => Some(Self::SmbActivity),
            "ssh_activity" => Some(Self::SshActivity),
            "ftp_activity" => Some(Self::FtpActivity),
            "email_activity" => Some(Self::EmailActivity),
            "network_file_activity" => Some(Self::NetworkFileActivity),
            "email_file_activity" => Some(Self::EmailFileActivity),
            "email_url_activity" => Some(Self::EmailUrlActivity),
            "ntp_activity" => Some(Self::NtpActivity),
            "tunnel_activity" => Some(Self::TunnelActivity),
            "web_resource_access_activity" => Some(Self::WebResourceAccessActivity),
            "application_lifecycle" => Some(Self::ApplicationLifecycle),
            "api_activity" => Some(Self::ApiActivity),
            "web_resource_activity" => Some(Self::WebResourceActivity),
            "datastore_activity" => Some(Self::DatastoreActivity),
            "file_hosting_activity" => Some(Self::FileHostingActivity),
            "scan_activity" => Some(Self::ScanActivity),
            _ => None,
        }
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

/// Typed predicate for filtering OCSF event rows.
///
/// Replaces raw SQL filter strings with structured predicates that can be
/// converted to SQL (for Athena) or Arrow-level filters (for Iceberg).
/// Dot-notation paths match the existing `get_nested_value` convention
/// (e.g. `"actor.user.name"`, `"src_endpoint.ip"`).
#[derive(Debug, Clone)]
pub enum ColumnFilter {
    /// Exact string match on a (possibly nested) OCSF column.
    StringEquals { path: String, value: String },
    /// String membership test on a (possibly nested) OCSF column.
    StringIn { path: String, values: Vec<String> },
    /// Disjunction of filters.
    Or(Vec<ColumnFilter>),
    /// Conjunction of filters.
    And(Vec<ColumnFilter>),
    /// Raw SQL expression — used for Athena-specific features like `any_match()`.
    /// Iceberg ignores this variant gracefully.
    RawSql(String),
    /// Match rows where a List<Struct> column contains an element with a string
    /// field equal to the given value. Athena: `any_match(list, x -> x.field = value)`.
    /// Iceberg: Arrow-level list traversal.
    ListContains {
        list_path: String,
        field: String,
        value: String,
    },
    /// Match rows where a List<Struct> column contains an element with a string
    /// field matching any of the given values.
    /// Athena: `any_match(list, x -> x.field IN (values))`.
    ListContainsAny {
        list_path: String,
        field: String,
        values: Vec<String>,
    },
}

impl ColumnFilter {
    /// Convert a dot-notation OCSF path to a quoted SQL column reference.
    ///
    /// `"actor.user.name"` → `"actor"."user"."name"`
    fn quote_ocsf_path(path: &str) -> String {
        path.split('.')
            .map(|part| format!("\"{part}\""))
            .collect::<Vec<_>>()
            .join(".")
    }

    /// Convert this filter to a SQL WHERE clause fragment.
    ///
    /// Values are sanitized via `sanitize_string` for defense-in-depth.
    #[must_use]
    pub fn to_sql(&self) -> String {
        match self {
            Self::StringEquals { path, value } => {
                let col = Self::quote_ocsf_path(path);
                let safe = sanitize_string(value);
                format!("{col} = '{safe}'")
            }
            Self::StringIn { path, values } => {
                let col = Self::quote_ocsf_path(path);
                let in_list = values
                    .iter()
                    .map(|v| format!("'{}'", sanitize_string(v)))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{col} IN ({in_list})")
            }
            Self::Or(filters) => {
                if filters.is_empty() {
                    return "FALSE".to_string();
                }
                let parts: Vec<String> = filters.iter().map(Self::to_sql).collect();
                format!("({})", parts.join(" OR "))
            }
            Self::And(filters) => {
                if filters.is_empty() {
                    return "TRUE".to_string();
                }
                let parts: Vec<String> = filters.iter().map(Self::to_sql).collect();
                format!("({})", parts.join(" AND "))
            }
            Self::RawSql(sql) => sql.clone(),
            Self::ListContains {
                list_path,
                field,
                value,
            } => {
                let col = Self::quote_ocsf_path(list_path);
                let safe = sanitize_string(value);
                format!("any_match({col}, x -> x.\"{field}\" = '{safe}')")
            }
            Self::ListContainsAny {
                list_path,
                field,
                values,
            } => {
                let col = Self::quote_ocsf_path(list_path);
                let in_list = values
                    .iter()
                    .map(|v| format!("'{}'", sanitize_string(v)))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("any_match({col}, x -> x.\"{field}\" IN ({in_list}))")
            }
        }
    }
}

/// Trait for Security Lake OCSF-aware query operations.
///
/// Defined in `irone-core` for dependency inversion: `GraphBuilder` and
/// `SecurityLakeEnricher` depend on this trait, while `irone-aws` provides
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
        filters: Option<&[ColumnFilter]>,
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

/// Extract an array of JSON objects from OCSF event data using a dot-notation path.
///
/// Like [`get_nested_value`] but expects the target to be a JSON array,
/// and returns only the elements that are JSON objects (non-object elements
/// are silently skipped).
#[must_use]
pub fn get_nested_array(
    data: &serde_json::Map<String, Value>,
    path: &str,
) -> Option<Vec<serde_json::Map<String, Value>>> {
    let val = get_nested_value(data, path)?;
    let arr = val.as_array()?;
    let objects: Vec<serde_json::Map<String, Value>> =
        arr.iter().filter_map(|v| v.as_object().cloned()).collect();
    if objects.is_empty() {
        None
    } else {
        Some(objects)
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
    fn from_yaml_str_known_classes() {
        assert_eq!(
            OCSFEventClass::from_yaml_str("api_activity"),
            Some(OCSFEventClass::ApiActivity)
        );
        assert_eq!(
            OCSFEventClass::from_yaml_str("authentication"),
            Some(OCSFEventClass::Authentication)
        );
        assert_eq!(
            OCSFEventClass::from_yaml_str("security_finding"),
            Some(OCSFEventClass::SecurityFinding)
        );
        assert_eq!(
            OCSFEventClass::from_yaml_str("network_activity"),
            Some(OCSFEventClass::NetworkActivity)
        );
    }

    #[test]
    fn from_yaml_str_unknown_returns_none() {
        assert!(OCSFEventClass::from_yaml_str("not_a_class").is_none());
        assert!(OCSFEventClass::from_yaml_str("").is_none());
    }

    #[test]
    fn get_nested_str_tries_multiple_paths() {
        let mut data = serde_json::Map::new();
        data.insert("user_name".to_string(), json!("charlie"));
        let result = get_nested_str(&data, &["actor.user.name", "user_name"]);
        assert_eq!(result, Some("charlie".to_string()));
    }

    #[test]
    fn get_nested_array_extracts_objects() {
        let data: serde_json::Map<String, Value> = serde_json::from_str(
            r#"{"resources": [{"uid": "arn:aws:s3:::bucket1", "type": "AWS::S3::Bucket"}, {"uid": "arn:aws:s3:::bucket2", "type": "AWS::S3::Bucket"}]}"#,
        )
        .unwrap();
        let result = get_nested_array(&data, "resources").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].get("uid").unwrap(), "arn:aws:s3:::bucket1");
    }

    #[test]
    fn get_nested_array_skips_non_objects() {
        let data: serde_json::Map<String, Value> =
            serde_json::from_str(r#"{"tags": ["tag1", "tag2"]}"#).unwrap();
        assert!(get_nested_array(&data, "tags").is_none());
    }

    #[test]
    fn get_nested_array_missing_path() {
        let data = serde_json::Map::new();
        assert!(get_nested_array(&data, "resources").is_none());
    }

    #[test]
    fn get_nested_array_empty_array() {
        let data: serde_json::Map<String, Value> =
            serde_json::from_str(r#"{"resources": []}"#).unwrap();
        assert!(get_nested_array(&data, "resources").is_none());
    }

    // --- ColumnFilter::to_sql ---

    #[test]
    fn column_filter_string_equals_sql() {
        let f = ColumnFilter::StringEquals {
            path: "actor.user.name".into(),
            value: "alice".into(),
        };
        assert_eq!(f.to_sql(), r#""actor"."user"."name" = 'alice'"#);
    }

    #[test]
    fn column_filter_string_in_sql() {
        let f = ColumnFilter::StringIn {
            path: "src_endpoint.ip".into(),
            values: vec!["10.0.0.1".into(), "10.0.0.2".into()],
        };
        assert_eq!(
            f.to_sql(),
            r#""src_endpoint"."ip" IN ('10.0.0.1', '10.0.0.2')"#
        );
    }

    #[test]
    fn column_filter_or_sql() {
        let f = ColumnFilter::Or(vec![
            ColumnFilter::StringEquals {
                path: "src_endpoint.ip".into(),
                value: "10.0.0.1".into(),
            },
            ColumnFilter::StringEquals {
                path: "dst_endpoint.ip".into(),
                value: "10.0.0.1".into(),
            },
        ]);
        assert_eq!(
            f.to_sql(),
            r#"("src_endpoint"."ip" = '10.0.0.1' OR "dst_endpoint"."ip" = '10.0.0.1')"#
        );
    }

    #[test]
    fn column_filter_sanitizes_values() {
        let f = ColumnFilter::StringEquals {
            path: "actor.user.name".into(),
            value: "O'Brien; DROP TABLE--".into(),
        };
        let sql = f.to_sql();
        assert!(sql.contains("O''Brien"));
        assert!(!sql.contains("--"));
    }

    #[test]
    fn column_filter_list_contains_sql() {
        let f = ColumnFilter::ListContains {
            list_path: "resources".into(),
            field: "uid".into(),
            value: "arn:aws:s3:::my-bucket".into(),
        };
        assert_eq!(
            f.to_sql(),
            r#"any_match("resources", x -> x."uid" = 'arn:aws:s3:::my-bucket')"#
        );
    }

    #[test]
    fn column_filter_list_contains_any_sql() {
        let f = ColumnFilter::ListContainsAny {
            list_path: "resources".into(),
            field: "uid".into(),
            values: vec!["arn:aws:s3:::bucket1".into(), "arn:aws:s3:::bucket2".into()],
        };
        assert_eq!(
            f.to_sql(),
            r#"any_match("resources", x -> x."uid" IN ('arn:aws:s3:::bucket1', 'arn:aws:s3:::bucket2'))"#
        );
    }

    #[test]
    fn column_filter_list_contains_sanitizes() {
        let f = ColumnFilter::ListContains {
            list_path: "resources".into(),
            field: "uid".into(),
            value: "arn'; DROP TABLE--".into(),
        };
        let sql = f.to_sql();
        assert!(sql.contains("arn''"));
        assert!(!sql.contains("--"));
    }
}
