# iris — Security Data Lake Analytics

[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-6B48FF?style=flat&logo=claude)](https://claude.com/claude-code)

A Rust-based security analytics platform for AWS Security Lake. Run detection rules against OCSF data, build investigation graphs, and deploy as lightweight AWS Lambda functions.

## Architecture

```
iris/
├── iris-rs/                  # Rust workspace (6 crates)
│   ├── iris-core/            # Config, connectors, catalog, detections, graph, reports
│   ├── iris-aws/             # SecurityLakeConnector (Athena), DynamoDB health cache, SNS
│   ├── iris-persistence/     # redb-backed investigation store
│   ├── iris-auth/            # Cognito OAuth + Cedar authorization (via l42-token-handler)
│   ├── iris-web/             # Axum web layer — 19 JSON API endpoints, Lambda handler
│   └── iris-health-checker/  # Scheduled EventBridge Lambda for parallel health checks
├── frontend/                 # Static Alpine.js frontend → S3 + CloudFront
├── detections/               # YAML detection rules (loaded by iris-core)
└── scripts/                  # Deploy scripts (Rust Lambda, frontend)
```

## Features

- **AWS Security Lake**: Query OCSF-formatted data via Athena
- **Detection Rules**: SQL-based rules in YAML, loaded at startup, parallel execution
- **Investigation Graphs**: Build security graphs from detection results with OCSF entity extraction
- **Health Monitoring**: DynamoDB-cached source health checks, EventBridge scheduled
- **Cedar Authorization**: RBAC with 5 groups and 20 fine-grained actions
- **Lambda Deployment**: ~10MB zips, 220ms cold start, 1-2ms warm

## Quick Start

### Prerequisites

- **Rust** (stable toolchain)
- **AWS credentials** configured
- **cargo-lambda** (for Lambda builds): `cargo install cargo-lambda`

### Build & Test

```bash
cd iris-rs
cargo test --workspace    # 236 tests
cargo build --release     # Build all crates
```

### Deploy

```bash
# Deploy Rust Lambda (web API)
./scripts/deploy_rust_lambda.sh iris-web

# Deploy Rust Lambda (health checker)
./scripts/deploy_rust_lambda.sh iris-health-checker

# Deploy frontend to S3 + CloudFront
./scripts/deploy_frontend.sh iris-frontend-415aeeaed7a5 EHQTNGR6VJ0YM
```

### Detection Rules

Rules are defined in YAML (`detections/`):

```yaml
- id: detect-root-login
  name: Root Account Login Detected
  severity: high
  threshold: 1
  query: |
    SELECT time_dt, actor.user.name, src_endpoint.ip
    FROM "{database}"."{table}"
    WHERE time_dt >= TIMESTAMP '{start_time}'
      AND time_dt < TIMESTAMP '{end_time}'
      AND actor.user.type = 'Root'
```

### Configuration

All config via environment variables with `SECDASH_` prefix:

| Variable | Description |
|----------|-------------|
| `SECDASH_SECURITY_LAKE_DB` | Glue database for Security Lake |
| `SECDASH_ATHENA_WORKGROUP` | Athena workgroup name |
| `SECDASH_ATHENA_OUTPUT` | S3 path for Athena results |
| `SECDASH_HEALTH_CACHE_TABLE` | DynamoDB table for health cache |
| `SECDASH_COGNITO_*` | Cognito OAuth configuration |

## Development

### Pre-commit Hooks

Uses [prek](https://github.com/catppuccin/prek):

- `cargo fmt --check` — format check on every commit
- `cargo clippy -- -D warnings` — lint on every commit
- `cargo deny check` — license/advisory check on every commit
- `cargo test --workspace` — full test suite on pre-push

### API Endpoints

19 JSON API endpoints under `/api/`:

- `GET /api/sources/health` — cached health for all sources
- `POST /api/sources/refresh` — trigger live health check
- `GET /api/dashboard` — dashboard summary
- `POST /api/detections/{rule_id}/run` — execute a detection rule
- `POST /api/investigations/from-detection` — full pipeline: detect → graph → timeline
- `GET /api/investigations/{id}/report` — investigation report
- `DELETE /api/investigations/{id}` — delete investigation

## Security

See [SECURITY.md](SECURITY.md) for security design decisions and responsible disclosure.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
