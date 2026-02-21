use serde::Deserialize;

/// Application configuration loaded from `SECDASH_*` environment variables.
///
/// Mirrors the Python `WebConfig(BaseSettings)` with `env_prefix = "SECDASH_"`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)]
pub struct AppConfig {
    // AWS
    pub region: String,
    pub account_id: String,
    pub security_lake_db: String,
    pub athena_output: String,
    pub use_direct_query: bool,

    // DuckDB
    pub duckdb_path: String,
    pub investigations_db_path: String,

    // Health cache (DynamoDB table name)
    pub health_cache_table: String,

    // Paths
    pub rules_dir: String,
    pub catalog_path: String,

    // Server
    pub debug: bool,
    pub host: String,
    pub port: u16,

    // Runtime
    pub is_lambda: bool,
    pub report_bucket: String,

    // Auth (Cognito)
    pub auth_enabled: bool,
    pub cognito_user_pool_id: String,
    pub cognito_client_id: String,
    pub cognito_client_secret: String,
    pub cognito_domain: String,
    pub cognito_region: String,
    pub cognito_redirect_uri: String,

    // Session
    pub session_secret_key: String,
    pub session_backend: String,
    pub session_max_age: u64,

    // Cedar authorization
    pub cedar_enabled: bool,

    // Service token for headless API access (bypasses session auth)
    pub service_token: String,

    // Frontend
    pub frontend_url: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            region: "us-west-2".into(),
            account_id: String::new(),
            security_lake_db: String::new(),
            athena_output: String::new(),
            use_direct_query: true,

            duckdb_path: ":memory:".into(),
            investigations_db_path: String::new(),

            health_cache_table: String::new(),

            rules_dir: String::new(),
            catalog_path: String::new(),

            debug: false,
            host: "0.0.0.0".into(),
            port: 8000,

            is_lambda: false,
            report_bucket: String::new(),

            auth_enabled: false,
            cognito_user_pool_id: String::new(),
            cognito_client_id: String::new(),
            cognito_client_secret: String::new(),
            cognito_domain: String::new(),
            cognito_region: "us-west-2".into(),
            cognito_redirect_uri: String::new(),

            session_secret_key: "change-me-in-production".into(),
            session_backend: "memory".into(),
            session_max_age: 30 * 24 * 3600,

            cedar_enabled: true,

            service_token: String::new(),

            frontend_url: String::new(),
        }
    }
}

impl AppConfig {
    /// Load configuration from `SECDASH_*` environment variables.
    ///
    /// # Errors
    /// Returns an error if any env var has an invalid value for its target type.
    pub fn from_env() -> Result<Self, envy::Error> {
        envy::prefixed("SECDASH_").from_env::<Self>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.region, "us-west-2");
        assert_eq!(cfg.port, 8000);
        assert!(!cfg.auth_enabled);
        assert!(cfg.cedar_enabled);
        assert_eq!(cfg.duckdb_path, ":memory:");
        assert_eq!(cfg.session_backend, "memory");
        assert_eq!(cfg.session_max_age, 30 * 24 * 3600);
    }

    #[test]
    fn from_env_with_no_vars_uses_defaults() {
        // envy returns defaults for missing vars when #[serde(default)] is set
        let cfg = AppConfig::from_env().unwrap();
        assert_eq!(cfg.region, "us-west-2");
    }
}
