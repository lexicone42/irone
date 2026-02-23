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

    // Investigation pipeline (Step Functions)
    pub investigation_state_machine_arn: String,
    pub investigations_table: String,

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

            investigation_state_machine_arn: String::new(),
            investigations_table: String::new(),

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

    /// Validate that required config fields are set for Lambda deployment.
    ///
    /// Called at startup to fail fast instead of failing later with cryptic errors.
    /// Only validates fields that are required when `is_lambda` is true.
    pub fn validate_for_lambda(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.security_lake_db.is_empty() {
            errors.push("SECDASH_SECURITY_LAKE_DB is required".into());
        }
        if self.report_bucket.is_empty() {
            errors.push("SECDASH_REPORT_BUCKET is required".into());
        }
        if self.session_secret_key == "change-me-in-production" {
            errors.push("SECDASH_SESSION_SECRET_KEY is using the default value".into());
        }
        if self.auth_enabled && self.cognito_user_pool_id.is_empty() {
            errors.push("SECDASH_COGNITO_USER_POOL_ID is required when auth is enabled".into());
        }
        if self.auth_enabled && self.cognito_client_id.is_empty() {
            errors.push("SECDASH_COGNITO_CLIENT_ID is required when auth is enabled".into());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
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

    #[test]
    fn validate_for_lambda_catches_defaults() {
        let cfg = AppConfig::default();
        let result = cfg.validate_for_lambda();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("SECURITY_LAKE_DB")));
        assert!(errors.iter().any(|e| e.contains("REPORT_BUCKET")));
        assert!(errors.iter().any(|e| e.contains("SESSION_SECRET_KEY")));
    }

    #[test]
    fn validate_for_lambda_passes_with_required_fields() {
        let cfg = AppConfig {
            security_lake_db: "my_db".into(),
            report_bucket: "my-bucket".into(),
            session_secret_key: "a-real-secret-key".into(),
            ..AppConfig::default()
        };
        assert!(cfg.validate_for_lambda().is_ok());
    }

    #[test]
    fn validate_for_lambda_catches_auth_without_cognito() {
        let cfg = AppConfig {
            security_lake_db: "my_db".into(),
            report_bucket: "my-bucket".into(),
            session_secret_key: "real-key".into(),
            auth_enabled: true,
            ..AppConfig::default()
        };
        let errors = cfg.validate_for_lambda().unwrap_err();
        assert!(errors.iter().any(|e| e.contains("COGNITO_USER_POOL_ID")));
        assert!(errors.iter().any(|e| e.contains("COGNITO_CLIENT_ID")));
    }
}
