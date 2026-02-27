use irone_auth::bridge::build_auth;
use irone_web::app::build_router;
use irone_web::config::load_config;
use irone_web::state::create_app_state;

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    tracing_subscriber::fmt().json().with_target(false).init();

    let mut config = load_config().expect("failed to load config");
    tracing::info!(region = %config.region, lambda = config.is_lambda, auth = config.auth_enabled, "starting irone-web");

    // Validate config for Lambda deployment
    if config.is_lambda
        && let Err(warnings) = config.validate_for_lambda()
    {
        for w in &warnings {
            tracing::warn!(issue = %w, "config validation warning");
        }
    }

    // Resolve secrets from SSM Parameter Store (falls back to env vars)
    if config.is_lambda {
        let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let ssm_client = aws_sdk_ssm::Client::new(&sdk_config);

        let service_token = irone_aws::secrets::resolve_ssm_param(
            &ssm_client,
            "SECDASH_SERVICE_TOKEN_SSM",
            "SECDASH_SERVICE_TOKEN",
        )
        .await;
        if !service_token.is_empty() {
            config.service_token = service_token;
        }

        let session_secret = irone_aws::secrets::resolve_ssm_param(
            &ssm_client,
            "SECDASH_SESSION_SECRET_SSM",
            "SECDASH_SESSION_SECRET_KEY",
        )
        .await;
        if !session_secret.is_empty() {
            config.session_secret_key = session_secret;
        }

        let client_secret = irone_aws::secrets::resolve_ssm_param(
            &ssm_client,
            "SECDASH_COGNITO_CLIENT_SECRET_SSM",
            "SECDASH_COGNITO_CLIENT_SECRET",
        )
        .await;
        if !client_secret.is_empty() {
            config.cognito_client_secret = client_secret;
        }
    }

    // Init service token for headless API access
    if config.is_lambda && config.service_token.is_empty() {
        tracing::warn!("service token is empty — headless API access will be unavailable");
    }
    irone_auth::middleware::set_service_token(config.service_token.clone());

    // Init auth (l42 token handler) if enabled
    let auth = build_auth(&config).await;

    let state = create_app_state(config).await;
    let app = build_router(state, auth);

    lambda_http::run(app).await
}
