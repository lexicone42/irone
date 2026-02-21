use irone_auth::bridge::build_auth;
use irone_web::app::build_router;
use irone_web::config::load_config;
use irone_web::state::create_app_state;

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    tracing_subscriber::fmt().json().with_target(false).init();

    let config = load_config().expect("failed to load config");
    tracing::info!(region = %config.region, lambda = config.is_lambda, auth = config.auth_enabled, "starting irone-web");

    // Init auth (l42 token handler) if enabled
    let auth = build_auth(&config).await;

    let state = create_app_state(config).await;
    let app = build_router(state, auth);

    lambda_http::run(app).await
}
