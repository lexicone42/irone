//! AWS Secrets Manager integration.
//!
//! Fetches secrets at Lambda startup, falling back to environment variables
//! for local development.

use std::collections::HashMap;

/// Fetch a secret string from Secrets Manager.
///
/// Returns `None` if the secret doesn't exist or can't be read.
pub async fn get_secret(sdk_config: &aws_config::SdkConfig, secret_id: &str) -> Option<String> {
    let client = aws_sdk_secretsmanager::Client::new(sdk_config);
    match client.get_secret_value().secret_id(secret_id).send().await {
        Ok(output) => output.secret_string().map(String::from),
        Err(e) => {
            tracing::warn!(secret_id, error = %e, "failed to fetch secret from Secrets Manager");
            None
        }
    }
}

/// Fetch a JSON secret and parse it into key-value pairs.
///
/// Many secrets are stored as JSON objects like `{"key": "value"}`.
pub async fn get_secret_json(
    sdk_config: &aws_config::SdkConfig,
    secret_id: &str,
) -> Option<HashMap<String, String>> {
    let raw = get_secret(sdk_config, secret_id).await?;
    match serde_json::from_str::<HashMap<String, String>>(&raw) {
        Ok(map) => Some(map),
        Err(e) => {
            tracing::warn!(secret_id, error = %e, "secret is not a valid JSON object");
            None
        }
    }
}

/// Resolve a config value: try Secrets Manager first, fall back to env var.
///
/// This allows a smooth migration path: set `SECDASH_SERVICE_TOKEN_SECRET_ARN`
/// to point to the secret, and the code will fetch it from Secrets Manager.
/// If the ARN env var is not set, it falls back to reading the value directly
/// from `SECDASH_SERVICE_TOKEN`.
pub async fn resolve_secret(
    sdk_config: &aws_config::SdkConfig,
    secret_arn_env: &str,
    fallback_env: &str,
) -> String {
    // Check if a Secrets Manager ARN is configured
    if let Ok(secret_arn) = std::env::var(secret_arn_env)
        && !secret_arn.is_empty()
    {
        if let Some(value) = get_secret(sdk_config, &secret_arn).await {
            tracing::info!(secret_arn_env, "loaded secret from Secrets Manager");
            return value;
        }
        tracing::warn!(
            secret_arn_env,
            "Secrets Manager fetch failed, falling back to env var"
        );
    }

    // Fall back to direct env var
    std::env::var(fallback_env).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_json_secret() {
        let json = r#"{"service_token": "abc123", "session_secret": "xyz789"}"#;
        let map: HashMap<String, String> = serde_json::from_str(json).unwrap();
        assert_eq!(map["service_token"], "abc123");
        assert_eq!(map["session_secret"], "xyz789");
    }

    #[test]
    fn parse_invalid_json_returns_none() {
        let result = serde_json::from_str::<HashMap<String, String>>("not json");
        assert!(result.is_err());
    }
}
