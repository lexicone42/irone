//! AWS secret resolution (SSM Parameter Store).
//!
//! Fetches secrets at Lambda startup, falling back to environment variables
//! for local development.

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
