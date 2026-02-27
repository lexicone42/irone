//! AWS secret resolution (SSM Parameter Store + Secrets Manager).
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

/// Fetch a single SSM Parameter Store value (decrypting `SecureString` params).
///
/// Returns `None` if the parameter doesn't exist or can't be read.
pub async fn get_ssm_param(client: &aws_sdk_ssm::Client, name: &str) -> Option<String> {
    match client
        .get_parameter()
        .name(name)
        .with_decryption(true)
        .send()
        .await
    {
        Ok(output) => output.parameter().and_then(|p| p.value().map(String::from)),
        Err(e) => {
            tracing::warn!(param = name, error = %e, "failed to fetch SSM parameter");
            None
        }
    }
}

/// Resolve a config value: try SSM Parameter Store first, fall back to env var.
///
/// `param_name_env` is an env var whose *value* is an SSM parameter name
/// (e.g. `SECDASH_SERVICE_TOKEN_SSM` → `/secdash/service-token`).
/// If it's not set or the SSM fetch fails, falls back to reading the value
/// directly from `fallback_env`.
pub async fn resolve_ssm_param(
    ssm_client: &aws_sdk_ssm::Client,
    param_name_env: &str,
    fallback_env: &str,
) -> String {
    if let Ok(param_name) = std::env::var(param_name_env)
        && !param_name.is_empty()
    {
        if let Some(value) = get_ssm_param(ssm_client, &param_name).await {
            tracing::info!(param_name_env, "loaded secret from SSM Parameter Store");
            return value;
        }
        tracing::warn!(
            param_name_env,
            "SSM Parameter Store fetch failed, falling back to env var"
        );
    }

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

    #[tokio::test]
    async fn resolve_ssm_param_falls_back_to_env_var() {
        // No SSM param env var set → should fall back to the direct env var
        let unique_key = "SECDASH_TEST_FALLBACK_82a3f";
        let unique_ssm = "SECDASH_TEST_SSM_MISSING_82a3f";
        // SAFETY: test-only, unique keys won't collide with other threads
        unsafe {
            std::env::set_var(unique_key, "fallback_value");
            std::env::remove_var(unique_ssm);
        }

        // Build a dummy SSM client — won't be called since the SSM env var is unset
        let config = aws_config::from_env()
            .region(aws_config::Region::new("us-west-2"))
            .no_credentials()
            .load()
            .await;
        let ssm_client = aws_sdk_ssm::Client::new(&config);

        let result = resolve_ssm_param(&ssm_client, unique_ssm, unique_key).await;
        assert_eq!(result, "fallback_value");

        unsafe { std::env::remove_var(unique_key) };
    }

    #[tokio::test]
    async fn resolve_ssm_param_returns_empty_when_no_env_vars() {
        let unique_key = "SECDASH_TEST_NONE_93b4e";
        let unique_ssm = "SECDASH_TEST_SSM_NONE_93b4e";
        // SAFETY: test-only, unique keys won't collide with other threads
        unsafe {
            std::env::remove_var(unique_key);
            std::env::remove_var(unique_ssm);
        }

        let config = aws_config::from_env()
            .region(aws_config::Region::new("us-west-2"))
            .no_credentials()
            .load()
            .await;
        let ssm_client = aws_sdk_ssm::Client::new(&config);

        let result = resolve_ssm_param(&ssm_client, unique_ssm, unique_key).await;
        assert_eq!(result, "");
    }
}
