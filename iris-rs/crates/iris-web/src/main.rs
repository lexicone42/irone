use iris_web::app::build_router;
use iris_web::config::load_config;
use iris_web::state::create_app_state;

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    tracing_subscriber::fmt().json().with_target(false).init();

    let config = load_config().expect("failed to load config");
    tracing::info!(region = %config.region, lambda = config.is_lambda, "starting iris-web");

    let state = create_app_state(config).await;
    let app = build_router(state);

    lambda_http::run(app).await
}
