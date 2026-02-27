# Rust Patterns in irone

A guide to the Rust idioms and architecture used in this codebase. Written for contributors who know programming but are new to Rust — it explains *why* things are structured this way, not just *what* they do.

## Table of Contents

- [Workspace Layout](#workspace-layout)
- [Config via Environment Variables](#config-via-environment-variables)
- [Traits as Interfaces](#traits-as-interfaces)
- [Enums as Closed Vocabularies](#enums-as-closed-vocabularies)
- [Error Handling](#error-handling)
- [Async and Tokio](#async-and-tokio)
- [Lambda Startup](#lambda-startup)
- [Secrets Resolution](#secrets-resolution)
- [Serde for Serialization](#serde-for-serialization)
- [Testing Patterns](#testing-patterns)

---

## Workspace Layout

Rust projects use **workspaces** to organize code into multiple **crates** (libraries/binaries) that share a single `Cargo.lock` and build cache. Think of it like a monorepo with shared dependency versions.

```
irone-rs/
├── Cargo.toml              # Workspace root — lists members, shared deps
├── crates/
│   ├── irone-core/         # Pure logic, no AWS calls — types, rules, graph
│   ├── irone-aws/          # AWS SDK integrations (Iceberg, DynamoDB, SSM)
│   ├── irone-auth/         # Authentication bridge to l42-token-handler
│   ├── irone-persistence/  # On-disk storage (redb key-value store)
│   ├── irone-web/          # HTTP layer (axum routes, Lambda handler)
│   ├── irone-worker/       # Background enrichment worker
│   ├── irone-alerting/     # Scheduled detection + alerting
│   └── irone-health-checker/ # Scheduled health checks
└── rules/                  # YAML detection rules (not a Rust crate)
```

**Why split this way?** Each crate compiles independently and has its own dependency list. `irone-core` has zero AWS dependencies — it can be tested without any AWS credentials or network access. `irone-aws` adds the AWS SDK deps. `irone-web` adds the HTTP framework (axum). This means:

- Unit tests in `irone-core` run instantly (no network I/O)
- Changing a route handler recompiles only `irone-web`, not the entire codebase
- Dependencies are explicit — you can see exactly what each layer needs

The workspace `Cargo.toml` defines shared dependency versions so all crates use the same version of, say, `serde` or `aws-sdk-s3`:

```toml
# Workspace root Cargo.toml
[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
aws-sdk-s3 = "1"

# Individual crate Cargo.toml
[dependencies]
serde = { workspace = true }   # inherits version from workspace
```

---

## Config via Environment Variables

All configuration is read from `SECDASH_*` environment variables using the `envy` crate, which deserializes env vars into a Rust struct automatically:

```rust
// irone-core/src/config.rs
#[derive(Deserialize)]
pub struct AppConfig {
    pub security_lake_db: String,          // from SECDASH_SECURITY_LAKE_DB
    pub cognito_client_id: String,         // from SECDASH_COGNITO_CLIENT_ID
    pub use_direct_query: bool,            // from SECDASH_USE_DIRECT_QUERY ("true"/"false")
    pub auth_enabled: bool,                // from SECDASH_AUTH_ENABLED
    // ... ~25 fields total
}
```

`envy` maps struct field names to `SECDASH_` prefixed env vars: `security_lake_db` → `SECDASH_SECURITY_LAKE_DB`. The Rust compiler knows the types, so `"true"` is parsed to `bool`, `"1024"` to a number, and missing required fields produce a clear error at startup rather than a runtime crash later.

**Compared to Python/JS**: No `.env` file parsing, no `os.getenv("FOO") or "default"` scattered through the code. One struct, one place, validated at startup.

---

## Traits as Interfaces

Rust uses **traits** where other languages use interfaces or abstract classes. A trait defines a contract — "any type that implements this trait must provide these methods."

irone has three key traits:

### `DataConnector` — query abstraction

```rust
// irone-core/src/connectors/base.rs
pub trait DataConnector: Send + Sync {
    async fn execute_query(&self, query: &str) -> Result<QueryResult, ConnectorError>;
    async fn list_tables(&self) -> Result<Vec<String>, ConnectorError>;
    // ...
}
```

Both `AthenaConnector` and `IcebergConnector` implement this trait. The detection runner doesn't know or care which one it's using — it just calls `connector.execute_query()`. Swapping from Athena to Iceberg required zero changes to the detection logic.

### `SecurityLakeQueries` — OCSF-specific operations

```rust
pub trait SecurityLakeQueries: Send + Sync {
    async fn query_by_event_class(&self, class: OCSFEventClass, ...) -> Result<...>;
    async fn count_by_event_class(&self, class: OCSFEventClass, ...) -> Result<u64>;
}
```

This is a higher-level abstraction — instead of writing SQL, callers say "give me API Activity events from the last 24 hours." The implementation handles the SQL/Iceberg details.

### `NotificationChannel` — alert delivery

```rust
pub trait NotificationChannel: Send + Sync {
    async fn send_alert(&self, alert: &Alert) -> Result<()>;
}
```

Currently implemented by `SnsNotifier`. Adding Slack or PagerDuty would mean implementing this trait for a new type — no changes to the alerting logic.

**The `: Send + Sync` part**: This tells the Rust compiler "this trait can be used safely across threads." Since Lambda handlers process requests concurrently (via tokio), all shared objects must be thread-safe. Rust enforces this at compile time — if you accidentally share mutable state without a lock, the code won't compile. This is one of Rust's core safety guarantees.

---

## Enums as Closed Vocabularies

Rust enums are more powerful than enums in most languages — each variant can carry data. This is heavily used throughout irone.

### Simple enums — a fixed set of options

```rust
pub enum Severity {
    Info,
    Low,
    Medium,  // #[default]
    High,
    Critical,
}
```

The compiler ensures every `match` on a `Severity` handles all 5 cases. If you add a new variant, every `match` in the codebase that doesn't handle it becomes a compile error. No forgotten switch cases.

### Data-carrying enums — different shapes for different cases

```rust
pub enum DetectionQuery {
    Sql(String),                         // raw SQL string
    Ocsf {                               // structured OCSF query
        event_class: OCSFEventClass,
        limit: u32,
    },
}

pub enum FilterOp {
    Equals(String),
    NotEquals(String),
    Contains(String),
    In(Vec<String>),                     // list of allowed values
    Regex(Regex),                        // compiled regex
}
```

Each variant carries exactly the data it needs. An `Equals` filter has one string. An `In` filter has a list. A `Regex` filter has a pre-compiled regex object. The compiler won't let you access the regex from an `Equals` filter — it's structurally impossible, not just "undefined behavior."

**Compared to Python/JS**: In dynamic languages, you'd use a dict like `{"type": "equals", "value": "foo"}` and hope nobody passes `{"type": "equals"}` without a `value`. In Rust, that's a compile error.

### Error enums

```rust
pub enum ConnectorError {
    Transient { message: String, source: Option<Box<dyn Error>> },
    Permanent { message: String, source: Option<Box<dyn Error>> },
    Timeout { message: String },
}
```

Different error variants carry different context. A `Timeout` doesn't have a source error — it *is* the error. A `Transient` might wrap an underlying AWS SDK error. The caller can match on the variant to decide whether to retry.

---

## Error Handling

Rust doesn't have exceptions. Instead, functions return `Result<T, E>` — either an `Ok(value)` or an `Err(error)`. The compiler forces you to handle both cases.

### `thiserror` — structured error types in libraries

Used in `irone-core` and `irone-aws` for errors that callers need to match on:

```rust
#[derive(thiserror::Error)]
pub enum ConnectorError {
    #[error("transient: {message}")]
    Transient { message: String },
    #[error("permanent: {message}")]
    Permanent { message: String },
}
```

The `#[error("...")]` attribute generates the `Display` implementation (human-readable message). Callers can pattern-match to decide how to handle each case.

### `WebError` — HTTP error conversion

The web layer has its own error type that converts to HTTP responses:

```rust
pub enum WebError {
    NotFound(String),     // → 404
    BadRequest(String),   // → 400
    Internal(String),     // → 500
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            Self::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
```

And `From` implementations convert lower-level errors automatically:

```rust
impl From<ConnectorError> for WebError {
    fn from(e: ConnectorError) -> Self {
        Self::Internal(e.to_string())
    }
}
```

So a route handler can use `?` to propagate errors:

```rust
async fn list_sources(State(state): State<AppState>) -> Result<Json<Vec<Source>>, WebError> {
    let sources = state.connector.list_tables().await?;  // ConnectorError → WebError automatically
    Ok(Json(sources))
}
```

The `?` operator is Rust's way of saying "if this is an error, return it; if it's ok, unwrap the value." It replaces try/catch with a single character.

---

## Async and Tokio

irone is an async application — it can handle many requests concurrently without OS threads. This matters for Lambda, where cold start time and memory are critical.

**`async fn` and `.await`** work like `async/await` in JavaScript or Python:

```rust
async fn query_security_lake(client: &Client, db: &str) -> Result<Vec<Event>> {
    let result = client.get_parameter()  // returns a Future (like a Promise)
        .name("/secdash/service-token")
        .send()
        .await?;                         // suspends until the AWS call completes
    // ...
}
```

**Tokio** is the async runtime — it schedules these futures across a thread pool. The `#[tokio::main]` attribute on `main()` starts the runtime:

```rust
#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    // Inside here, .await works
    let config = aws_config::load_defaults(...).await;
    lambda_http::run(app).await
}
```

**Why this matters for Lambda**: A single Lambda invocation can make multiple AWS API calls concurrently (e.g., health-checking 6 data sources in parallel) without spawning threads. The binary is ~10MB with a 220ms cold start. A comparable Python Lambda with `boto3` would be ~50MB with a multi-second cold start.

---

## Lambda Startup

The Lambda entry point (`irone-web/src/main.rs`) follows a specific pattern:

```rust
#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    // 1. Init logging (JSON format for CloudWatch)
    tracing_subscriber::fmt().json().init();

    // 2. Load config from env vars
    let mut config = load_config()?;

    // 3. Resolve secrets from SSM Parameter Store
    if config.is_lambda {
        let ssm_client = aws_sdk_ssm::Client::new(&sdk_config);
        config.service_token = resolve_ssm_param(&ssm_client, "SECDASH_SERVICE_TOKEN_SSM", "SECDASH_SERVICE_TOKEN").await;
        // ...
    }

    // 4. Build auth layer (Cognito + Cedar)
    let auth = build_auth(&config).await;

    // 5. Build app state (connectors, stores)
    let state = create_app_state(config).await;

    // 6. Build router (routes + middleware)
    let app = build_router(state, auth);

    // 7. Run the Lambda handler
    lambda_http::run(app).await
}
```

Everything before step 7 runs **once per cold start** (~220ms). Step 7 runs the axum router as a Lambda handler — each API Gateway request becomes an axum request, and the response is returned to API Gateway. Warm invocations skip steps 1-6 entirely (1-2ms).

This is fundamentally different from Python/Node Lambda handlers where the handler function runs on every invocation. In Rust, the setup is amortized across thousands of warm invocations.

---

## Secrets Resolution

Secrets follow a "try SSM, fall back to env var" pattern (see `irone-aws/src/secrets.rs`):

```rust
pub async fn resolve_ssm_param(
    ssm_client: &aws_sdk_ssm::Client,
    param_name_env: &str,   // e.g., "SECDASH_SERVICE_TOKEN_SSM"
    fallback_env: &str,     // e.g., "SECDASH_SERVICE_TOKEN"
) -> String {
    // 1. Check if an SSM parameter name is configured
    if let Ok(param_name) = std::env::var(param_name_env) && !param_name.is_empty() {
        // 2. Fetch from SSM (decrypts SecureString automatically)
        if let Some(value) = get_ssm_param(ssm_client, &param_name).await {
            return value;
        }
    }
    // 3. Fall back to direct env var (for local dev)
    std::env::var(fallback_env).unwrap_or_default()
}
```

**Why this pattern?** In Lambda, the `SECDASH_SERVICE_TOKEN_SSM` env var contains `/secdash/service-token` (an SSM parameter *name*), and the code fetches the actual secret at runtime. In local development, you just set `SECDASH_SERVICE_TOKEN=mysecret` directly. Same code path, different config.

The `if let Ok(...) = ... && !...` syntax is a Rust "let chain" — it combines pattern matching with a boolean condition in a single `if`.

---

## Serde for Serialization

Almost every struct in irone derives `Serialize` and/or `Deserialize` via the `serde` crate:

```rust
#[derive(Serialize, Deserialize)]
pub struct DetectionMetadata {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    #[serde(default)]              // defaults to empty vec if missing from JSON/YAML
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]  // omit from JSON if None
    pub mitre_attack: Option<Vec<String>>,
}
```

This single derive gives you:
- JSON serialization (for API responses)
- YAML deserialization (for detection rules)
- Env var deserialization (via `envy`, for config)

**Compared to Python/JS**: No manual `to_dict()` / `from_dict()` methods. No schema validation libraries. The Rust type system *is* the schema — if a field is `Severity`, it must be a valid severity value. If it's `Vec<String>`, it must be an array of strings. Invalid data fails at deserialization time with a clear error message.

---

## Testing Patterns

### Unit tests live next to the code

Rust convention puts tests in the same file as the code they test, inside a `#[cfg(test)]` module:

```rust
// In secrets.rs, after the main code:
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_ssm_param_falls_back_to_env_var() {
        unsafe { std::env::set_var("MY_KEY", "fallback_value") };
        let ssm_client = /* dummy client */;
        let result = resolve_ssm_param(&ssm_client, "MISSING_SSM", "MY_KEY").await;
        assert_eq!(result, "fallback_value");
    }
}
```

The `#[cfg(test)]` means this code is only compiled when running tests — it's excluded from the production binary. `use super::*` imports everything from the parent module, including private functions.

### Property-based testing with proptest

Detection rule logic uses **property-based testing** (like Hypothesis in Python):

```rust
proptest! {
    #[test]
    fn threshold_zero_always_triggers(count in 0u64..1000) {
        let result = evaluate_threshold(0, count);
        prop_assert!(result.triggered);  // threshold=0 triggers on ANY count
    }
}
```

Instead of testing specific examples, proptest generates hundreds of random inputs and checks that an *invariant* (property) always holds. This caught real bugs — like the `threshold=0` edge case documented in SECURITY.md.

### Integration tests that skip AWS

Tests in `irone-core` never touch AWS. Tests in `irone-aws` that need AWS use dummy clients with `no_credentials()`:

```rust
let config = aws_config::from_env()
    .region(Region::new("us-west-2"))
    .no_credentials()
    .load()
    .await;
let ssm_client = aws_sdk_ssm::Client::new(&config);
```

This builds a real SDK client that would fail if it tried to call AWS — but for tests that only exercise the "env var not set → fall back" path, the client is never called.

---

## Key Takeaways for New Contributors

1. **Read the types** — Rust structs and enums are the documentation. A function signature like `async fn run_detection(rule: &YamlDetectionRule, connector: &dyn SecurityLakeQueries) -> Result<DetectionResult, ConnectorError>` tells you everything about what it needs and what it returns.

2. **`?` means "return early on error"** — when you see `let x = foo().await?;`, that's equivalent to `try { x = await foo() } catch(e) { return Err(e) }`.

3. **`Option<T>` means "might be absent"** — Rust has no null. `Option::Some(value)` means it's present, `Option::None` means it's absent. The compiler forces you to handle both cases.

4. **Ownership is the hard part** — if the compiler says "borrow of moved value" or "cannot borrow as mutable," it's telling you two parts of the code are trying to use the same data in conflicting ways. This is what prevents data races and use-after-free bugs.

5. **`cargo test --workspace`** runs everything — 447 tests across 8 crates. If it passes, you haven't broken anything. The pre-push hook runs this automatically.
