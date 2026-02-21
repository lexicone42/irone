use irone_core::config::AppConfig;

/// Web-specific configuration.
///
/// Delegates to [`AppConfig`] which reads `SECDASH_*` env vars via `envy`.
/// This alias exists so irone-web code uses a web-specific name while
/// the actual fields live in irone-core (single source of truth).
pub type WebConfig = AppConfig;

/// Load web configuration from environment.
///
/// # Errors
///
/// Returns an error if any `SECDASH_*` env var has an invalid value for its target type.
pub fn load_config() -> Result<WebConfig, envy::Error> {
    WebConfig::from_env()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let cfg = WebConfig::default();
        assert_eq!(cfg.region, "us-west-2");
        assert!(!cfg.auth_enabled);
        assert!(!cfg.is_lambda);
        assert_eq!(cfg.port, 8000);
    }

    #[test]
    fn load_config_with_defaults() {
        let cfg = load_config().unwrap();
        assert_eq!(cfg.region, "us-west-2");
    }

    #[test]
    fn investigations_db_path_empty_by_default() {
        let cfg = WebConfig::default();
        assert!(cfg.investigations_db_path.is_empty());
    }
}
