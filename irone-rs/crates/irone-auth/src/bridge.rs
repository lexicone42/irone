//! Bridge between irone `AppConfig` and `l42-token-handler`.
//!
//! Converts SECDASH_* config into the l42 token handler's `Config`,
//! initializes Cedar policies, session backends, and returns auth state +
//! route builder for integration into the irone-web router.

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::middleware::from_fn;
use axum::response::Redirect;

use irone_core::config::AppConfig;
use l42_token_handler::AppState as AuthState;
use l42_token_handler::cedar::engine::CedarState;
use l42_token_handler::cognito::jwt::JwksCache;
use l42_token_handler::config::Config as L42Config;
use l42_token_handler::routes;
use l42_token_handler::session::AnyBackend;
use l42_token_handler::session::memory::InMemoryBackend;
use l42_token_handler::session::middleware::SessionLayer;

/// Convert irone `AppConfig` (loaded from `SECDASH_*` env vars) into the l42
/// token handler's `Config`.
fn to_l42_config(app: &AppConfig) -> L42Config {
    L42Config {
        cognito_client_id: app.cognito_client_id.clone(),
        cognito_client_secret: app.cognito_client_secret.clone(),
        cognito_user_pool_id: app.cognito_user_pool_id.clone(),
        cognito_domain: app.cognito_domain.clone(),
        cognito_region: app.cognito_region.clone(),
        session_secret: app.session_secret_key.clone(),
        frontend_url: if app.frontend_url.is_empty() {
            // Strip the path to get the origin (scheme + authority).
            // "https://irone.lexicone.com/auth/callback" → "https://irone.lexicone.com"
            let uri = &app.cognito_redirect_uri;
            uri.find("://")
                .and_then(|i| uri[i + 3..].find('/').map(|j| uri[..i + 3 + j].to_string()))
                .unwrap_or_else(|| uri.clone())
        } else {
            app.frontend_url.clone()
        },
        port: app.port,
        session_backend: app.session_backend.clone(),
        dynamodb_table: "secdash_sessions".into(),
        dynamodb_endpoint: String::new(),
        session_https_only: app.is_lambda,
        cookie_domain: None,
        auth_path_prefix: "/auth".into(),
        // Passkey fields
        callback_use_origin: false,
        callback_allowed_origins: Vec::new(),
        aaguid_allowlist: Vec::new(),
        require_device_bound: false,
        service_token: None,
    }
}

/// Auth components ready for integration into the irone-web router.
pub struct AuthComponents {
    /// The auth state (l42 token handler state).
    pub state: Arc<AuthState>,
    /// Auth routes (with CSRF layer on POST endpoints, but WITHOUT session middleware).
    /// Session middleware must be applied at the app level so it also covers API routes.
    pub routes: Router,
}

/// Build auth components from irone config.
///
/// Returns `None` if `auth_enabled` is false.
pub async fn build_auth(config: &AppConfig) -> Option<AuthComponents> {
    if !config.auth_enabled {
        tracing::info!("auth disabled — skipping token handler init");
        return None;
    }

    let l42_config = to_l42_config(config);
    let http_client = reqwest::Client::new();
    let jwks_cache = Arc::new(JwksCache::new(http_client.clone()));

    let cedar = init_cedar();

    // Session backend
    let session_backend = if l42_config.session_backend == "dynamodb" {
        let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let dynamo_client = aws_sdk_dynamodb::Client::new(&sdk_config);
        tracing::info!(
            table = %l42_config.dynamodb_table,
            "auth: using DynamoDB session backend"
        );
        AnyBackend::DynamoDb(l42_token_handler::session::dynamodb::DynamoDbBackend::new(
            dynamo_client,
            l42_config.dynamodb_table.clone(),
        ))
    } else {
        tracing::info!("auth: using in-memory session backend");
        AnyBackend::Memory(InMemoryBackend::new())
    };

    let session_layer = Arc::new(SessionLayer {
        backend: Arc::new(session_backend),
        secret: l42_config.session_secret.clone(),
        https_only: l42_config.session_https_only,
        cookie_domain: l42_config.cookie_domain.clone(),
        service_token: l42_config.service_token.clone(),
    });

    let state = Arc::new(AuthState {
        config: l42_config,
        http_client,
        jwks_cache,
        cedar,
        session_layer,
    });

    // Build auth routes using l42 handlers directly.
    // CSRF-protected routes (state-changing POST endpoints):
    let csrf_routes = Router::new()
        .route(
            "/session",
            axum::routing::post(routes::session::create_session),
        )
        .route(
            "/refresh",
            axum::routing::post(routes::refresh::refresh_tokens),
        )
        .route(
            "/authorize",
            axum::routing::post(routes::authorize::authorize),
        )
        .route(
            "/validate-credential",
            axum::routing::post(routes::validate_credential::validate_credential),
        )
        .layer(from_fn(l42_token_handler::middleware::csrf::require_csrf));

    // Open auth routes (no CSRF):
    let open_routes = Router::new()
        .route("/login", axum::routing::get(cognito_login))
        .route(
            "/logout",
            axum::routing::get(cognito_logout).post(routes::logout::logout),
        )
        .route("/token", axum::routing::get(routes::token::get_token))
        .route(
            "/callback",
            axum::routing::get(routes::callback::oauth_callback),
        )
        .route("/me", axum::routing::get(routes::me::me));

    let auth_routes = Router::new().merge(csrf_routes).merge(open_routes);

    // Nest under /auth and bind state (produces Router<()>).
    // Session middleware is NOT applied here — caller must apply it at the app level.
    let routes = Router::new()
        .nest("/auth", auth_routes)
        .with_state(Arc::clone(&state));

    tracing::info!(
        "auth: token handler initialized (Cedar={})",
        state.cedar.is_some()
    );

    Some(AuthComponents { state, routes })
}

/// `GET /auth/login` — redirect to Cognito Hosted UI.
#[allow(clippy::unused_async)]
async fn cognito_login(State(state): State<Arc<AuthState>>) -> Redirect {
    let cfg = &state.config;
    let callback = format!("{}/auth/callback", cfg.frontend_url);
    let callback_encoded = urlencoding::encode(&callback);
    let url = format!(
        "https://{}/oauth2/authorize?client_id={}&response_type=code&scope=openid+email+profile&redirect_uri={}",
        cfg.cognito_domain, cfg.cognito_client_id, callback_encoded
    );
    Redirect::temporary(&url)
}

/// `GET /auth/logout` — destroy session and redirect to Cognito logout.
async fn cognito_logout(
    State(state): State<Arc<AuthState>>,
    request: axum::http::Request<axum::body::Body>,
) -> Redirect {
    // Mark session as destroyed (session middleware will clear cookie on response)
    if let Some(handle) = request
        .extensions()
        .get::<l42_token_handler::session::middleware::SessionHandle>()
    {
        *handle.destroyed.lock().await = true;
    }

    let cfg = &state.config;
    let logout_uri = format!("{}/auth/login", cfg.frontend_url);
    let logout_uri_encoded = urlencoding::encode(&logout_uri);
    let url = format!(
        "https://{}/logout?client_id={}&logout_uri={}",
        cfg.cognito_domain, cfg.cognito_client_id, logout_uri_encoded
    );
    Redirect::temporary(&url)
}

/// Initialize Cedar policy engine from bundled policies.
fn init_cedar() -> Option<CedarState> {
    let candidates = [
        std::env::var("CARGO_MANIFEST_DIR")
            .map(|d| PathBuf::from(d).join("cedar"))
            .ok(),
        Some(PathBuf::from("cedar")),
        Some(PathBuf::from("/opt/cedar")),
        std::env::var("CARGO_MANIFEST_DIR")
            .map(|d| PathBuf::from(d).join("../../../l42cognitopasskey/rust/cedar"))
            .ok(),
    ];

    for candidate in candidates.into_iter().flatten() {
        let schema = candidate.join("schema.cedarschema.json");
        let policies = candidate.join("policies");
        if schema.exists() && policies.exists() {
            match CedarState::init(&schema, &policies) {
                Ok(state) => {
                    tracing::info!(path = %candidate.display(), "Cedar engine initialized");
                    return Some(state);
                }
                Err(e) => {
                    tracing::warn!(
                        path = %candidate.display(),
                        err = %e,
                        "Cedar init failed at this path, trying next"
                    );
                }
            }
        }
    }

    tracing::warn!("Cedar policies not found — running without authorization");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_conversion_maps_fields() {
        let app = AppConfig {
            cognito_client_id: "client-123".into(),
            cognito_client_secret: "secret-456".into(),
            cognito_user_pool_id: "us-west-2_abc".into(),
            cognito_domain: "auth.example.com".into(),
            cognito_region: "us-east-1".into(),
            session_secret_key: "my-secret".into(),
            frontend_url: "https://app.example.com".into(),
            is_lambda: true,
            ..AppConfig::default()
        };

        let l42 = to_l42_config(&app);
        assert_eq!(l42.cognito_client_id, "client-123");
        assert_eq!(l42.cognito_client_secret, "secret-456");
        assert_eq!(l42.cognito_user_pool_id, "us-west-2_abc");
        assert_eq!(l42.cognito_domain, "auth.example.com");
        assert_eq!(l42.cognito_region, "us-east-1");
        assert_eq!(l42.session_secret, "my-secret");
        assert_eq!(l42.frontend_url, "https://app.example.com");
        assert!(l42.session_https_only);
    }

    #[test]
    fn config_conversion_derives_frontend_from_redirect_uri() {
        let app = AppConfig {
            cognito_redirect_uri: "https://irone.lexicone.com/auth/callback".into(),
            ..AppConfig::default()
        };

        let l42 = to_l42_config(&app);
        // Must strip the entire path, not just the last segment
        assert_eq!(l42.frontend_url, "https://irone.lexicone.com");
    }

    #[tokio::test]
    async fn auth_disabled_returns_none() {
        let config = AppConfig {
            auth_enabled: false,
            ..AppConfig::default()
        };
        assert!(build_auth(&config).await.is_none());
    }
}
