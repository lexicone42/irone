use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Types of data sources supported.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSourceType {
    SecurityLake,
    SecurityLakeDirect,
    Athena,
    S3,
    CloudwatchLogs,
    Duckdb,
    Custom,
}

impl std::fmt::Display for DataSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SecurityLake => write!(f, "security_lake"),
            Self::SecurityLakeDirect => write!(f, "security_lake_direct"),
            Self::Athena => write!(f, "athena"),
            Self::S3 => write!(f, "s3"),
            Self::CloudwatchLogs => write!(f, "cloudwatch_logs"),
            Self::Duckdb => write!(f, "duckdb"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// A data source definition in the catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSource {
    /// Unique name for this data source.
    pub name: String,
    /// Type of data source.
    #[serde(rename = "type")]
    pub source_type: DataSourceType,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,

    // Connection settings
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub table: Option<String>,
    #[serde(default)]
    pub s3_location: Option<String>,
    #[serde(default = "default_region")]
    pub region: String,

    // Schema info
    #[serde(default)]
    pub schema_fields: HashMap<String, String>,

    // Custom connector settings
    #[serde(default)]
    pub connector_class: Option<String>,
    #[serde(default)]
    pub connector_config: HashMap<String, Value>,

    // Health check settings
    #[serde(default)]
    pub health_check_query: Option<String>,
    #[serde(default = "default_freshness_minutes")]
    pub expected_freshness_minutes: u32,

    // Tags for organization
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_region() -> String {
    "us-west-2".into()
}

fn default_freshness_minutes() -> u32 {
    60
}

/// Configuration for the data catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogConfig {
    #[serde(default)]
    pub sources: Vec<DataSource>,
    #[serde(default = "default_region")]
    pub default_region: String,
}

impl Default for CatalogConfig {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            default_region: default_region(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_source_type_display() {
        assert_eq!(DataSourceType::SecurityLake.to_string(), "security_lake");
        assert_eq!(
            DataSourceType::CloudwatchLogs.to_string(),
            "cloudwatch_logs"
        );
    }

    #[test]
    fn data_source_type_serde_roundtrip() {
        let json = serde_json::to_string(&DataSourceType::SecurityLake).unwrap();
        assert_eq!(json, "\"security_lake\"");
        let back: DataSourceType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, DataSourceType::SecurityLake);
    }

    #[test]
    fn data_source_minimal_fields() {
        let src = DataSource {
            name: "test".into(),
            source_type: DataSourceType::Athena,
            description: String::new(),
            database: Some("mydb".into()),
            table: Some("mytable".into()),
            s3_location: None,
            region: "us-west-2".into(),
            schema_fields: HashMap::new(),
            connector_class: None,
            connector_config: HashMap::new(),
            health_check_query: None,
            expected_freshness_minutes: 60,
            tags: vec!["test".into()],
        };
        assert_eq!(src.name, "test");
        assert_eq!(src.source_type, DataSourceType::Athena);
    }

    #[test]
    fn data_source_serde_roundtrip() {
        let src = DataSource {
            name: "cloudtrail".into(),
            source_type: DataSourceType::SecurityLake,
            description: "CloudTrail via Security Lake".into(),
            database: Some("amazon_security_lake_glue_db_us_west_2".into()),
            table: Some("amazon_security_lake_table_us_west_2_cloud_trail_mgmt_2_0".into()),
            s3_location: None,
            region: "us-west-2".into(),
            schema_fields: HashMap::new(),
            connector_class: None,
            connector_config: HashMap::new(),
            health_check_query: None,
            expected_freshness_minutes: 60,
            tags: vec!["security-lake".into(), "ocsf".into()],
        };
        let json = serde_json::to_string_pretty(&src).unwrap();
        let back: DataSource = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "cloudtrail");
        assert_eq!(back.source_type, DataSourceType::SecurityLake);
        assert_eq!(back.tags.len(), 2);
    }

    #[test]
    fn catalog_config_yaml_roundtrip() {
        let yaml_str = r"
sources:
  - name: test-source
    type: athena
    database: mydb
    table: mytable
    tags:
      - test
default_region: us-east-1
";
        let cfg: CatalogConfig = serde_yaml::from_str(yaml_str).unwrap();
        assert_eq!(cfg.sources.len(), 1);
        assert_eq!(cfg.sources[0].name, "test-source");
        assert_eq!(cfg.default_region, "us-east-1");
    }

    #[test]
    fn catalog_config_defaults() {
        let cfg = CatalogConfig::default();
        assert!(cfg.sources.is_empty());
        assert_eq!(cfg.default_region, "us-west-2");
    }
}
