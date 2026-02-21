use std::collections::HashMap;
use std::path::Path;

use tracing::info;

use super::models::{CatalogConfig, DataSource, DataSourceType};

/// Registry of available data sources.
///
/// Provides CRUD operations, filtering, and YAML persistence for the
/// data source catalog.
#[derive(Debug, Clone, Default)]
pub struct DataCatalog {
    sources: HashMap<String, DataSource>,
}

impl DataCatalog {
    /// Create an empty catalog.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a data source.
    pub fn add_source(&mut self, source: DataSource) {
        info!(name = %source.name, source_type = %source.source_type, "Registered data source");
        self.sources.insert(source.name.clone(), source);
    }

    /// Get a data source by name.
    #[must_use]
    pub fn get_source(&self, name: &str) -> Option<&DataSource> {
        self.sources.get(name)
    }

    /// List all registered sources.
    #[must_use]
    pub fn list_sources(&self) -> Vec<&DataSource> {
        self.sources.values().collect()
    }

    /// Filter sources by tag.
    #[must_use]
    pub fn filter_by_tag(&self, tag: &str) -> Vec<&DataSource> {
        self.sources
            .values()
            .filter(|s| s.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Filter sources by type.
    #[must_use]
    pub fn filter_by_type(&self, source_type: &DataSourceType) -> Vec<&DataSource> {
        self.sources
            .values()
            .filter(|s| &s.source_type == source_type)
            .collect()
    }

    /// Remove a data source. Returns `true` if it existed.
    pub fn remove_source(&mut self, name: &str) -> bool {
        self.sources.remove(name).is_some()
    }

    /// Number of registered sources.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Whether the catalog is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Load sources from a YAML file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from_yaml(&mut self, path: &Path) -> Result<usize, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: CatalogConfig = serde_yaml::from_str(&content)?;

        let count = config.sources.len();
        for source in config.sources {
            self.add_source(source);
        }

        info!(path = %path.display(), count, "Loaded data sources from YAML");
        Ok(count)
    }

    /// Save current sources to a YAML file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn save_to_yaml(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let config = CatalogConfig {
            sources: self.sources.values().cloned().collect(),
            ..CatalogConfig::default()
        };
        let yaml = serde_yaml::to_string(&config)?;
        std::fs::write(path, yaml)?;
        info!(path = %path.display(), count = self.sources.len(), "Saved data sources to YAML");
        Ok(())
    }

    /// Load well-known Security Lake sources for a given database.
    ///
    /// Registers the 5 standard Security Lake tables without needing
    /// a catalog file.
    pub fn register_security_lake_sources(&mut self, database: &str, region: &str) {
        let tables = [
            (
                "cloudtrail",
                "amazon_security_lake_table_{region}_cloud_trail_mgmt_2_0",
                "CloudTrail management events",
            ),
            (
                "vpc-flow",
                "amazon_security_lake_table_{region}_vpc_flow_2_0",
                "VPC Flow Logs",
            ),
            (
                "route53",
                "amazon_security_lake_table_{region}_route53_2_0",
                "Route 53 DNS resolver logs",
            ),
            (
                "security-hub",
                "amazon_security_lake_table_{region}_sh_findings_2_0",
                "Security Hub findings",
            ),
            (
                "lambda-execution",
                "amazon_security_lake_table_{region}_lambda_execution_2_0",
                "Lambda execution logs",
            ),
        ];

        let region_suffix = region.replace('-', "_");

        for (name, table_template, description) in tables {
            let table = table_template.replace("{region}", &region_suffix);
            let source = DataSource {
                name: name.to_string(),
                source_type: DataSourceType::SecurityLake,
                description: description.to_string(),
                database: Some(database.to_string()),
                table: Some(table),
                s3_location: None,
                region: region.to_string(),
                schema_fields: HashMap::new(),
                connector_class: None,
                connector_config: HashMap::new(),
                health_check_query: None,
                expected_freshness_minutes: 60,
                tags: vec!["security-lake".into(), "ocsf".into()],
            };
            self.add_source(source);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_source(name: &str) -> DataSource {
        DataSource {
            name: name.to_string(),
            source_type: DataSourceType::Athena,
            description: format!("Test source {name}"),
            database: Some("testdb".into()),
            table: Some("testtable".into()),
            s3_location: None,
            region: "us-west-2".into(),
            schema_fields: HashMap::new(),
            connector_class: None,
            connector_config: HashMap::new(),
            health_check_query: None,
            expected_freshness_minutes: 60,
            tags: vec!["test".into()],
        }
    }

    #[test]
    fn crud_operations() {
        let mut catalog = DataCatalog::new();
        assert!(catalog.is_empty());

        catalog.add_source(sample_source("src-1"));
        catalog.add_source(sample_source("src-2"));
        assert_eq!(catalog.len(), 2);

        assert!(catalog.get_source("src-1").is_some());
        assert!(catalog.get_source("missing").is_none());

        assert!(catalog.remove_source("src-1"));
        assert_eq!(catalog.len(), 1);
        assert!(!catalog.remove_source("src-1")); // already removed
    }

    #[test]
    fn filter_by_tag() {
        let mut catalog = DataCatalog::new();

        let mut s1 = sample_source("src-1");
        s1.tags = vec!["ocsf".into(), "security-lake".into()];
        catalog.add_source(s1);

        let mut s2 = sample_source("src-2");
        s2.tags = vec!["custom".into()];
        catalog.add_source(s2);

        let ocsf = catalog.filter_by_tag("ocsf");
        assert_eq!(ocsf.len(), 1);
        assert_eq!(ocsf[0].name, "src-1");

        let custom = catalog.filter_by_tag("custom");
        assert_eq!(custom.len(), 1);

        let none = catalog.filter_by_tag("nonexistent");
        assert!(none.is_empty());
    }

    #[test]
    fn yaml_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.yaml");

        let mut catalog = DataCatalog::new();
        catalog.add_source(sample_source("roundtrip-src"));

        catalog.save_to_yaml(&path).unwrap();

        let mut loaded = DataCatalog::new();
        let count = loaded.load_from_yaml(&path).unwrap();
        assert_eq!(count, 1);
        assert!(loaded.get_source("roundtrip-src").is_some());
    }

    #[test]
    fn register_security_lake_sources() {
        let mut catalog = DataCatalog::new();
        catalog.register_security_lake_sources("my_sl_db", "us-west-2");
        assert_eq!(catalog.len(), 5);

        let ct = catalog.get_source("cloudtrail").unwrap();
        assert_eq!(ct.source_type, DataSourceType::SecurityLake);
        assert_eq!(ct.database.as_deref(), Some("my_sl_db"));
        assert!(ct.table.as_deref().unwrap().contains("us_west_2"));
    }
}
