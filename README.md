# irone — Security Data Lake Analytics

[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-6B48FF?style=flat&logo=claude)](https://claude.com/claude-code)

A Rust-based security analytics platform for AWS Security Lake. Run OCSF-native detection rules against live data, build investigation graphs, and deploy as lightweight AWS Lambda functions.

The name "irone" comes from the aromatic compound found in iris flowers — and contains "iron", a nod to Rust.

## Architecture

```
irone/
├── irone-rs/                  # Rust workspace (6 crates, 276 tests)
│   ├── irone-core/            # Config, connectors, catalog, detections, graph, reports
│   ├── irone-aws/             # SecurityLakeConnector (Athena + Iceberg), DynamoDB, SNS
│   ├── irone-persistence/     # redb-backed investigation store
│   ├── irone-auth/            # Cognito OAuth + Cedar authorization (via l42-token-handler)
│   ├── irone-web/             # Axum web layer — 21 JSON API endpoints, Lambda handler
│   ├── irone-health-checker/  # Scheduled EventBridge Lambda for parallel health checks
│   └── rules/                 # 9 OCSF detection rules (YAML)
├── frontend/                 # Static Alpine.js frontend → S3 + CloudFront
├── infra/                    # TypeScript CDK (4 stacks)
└── scripts/                  # Deploy scripts (Rust Lambda, frontend, CDK)
```

## Features

- **AWS Security Lake**: Query OCSF-formatted data via Athena or direct Iceberg reads (sub-second)
- **OCSF Detection Rules**: Structured event class queries with declarative field filters, plus raw SQL support
- **Investigation Graphs**: Build security graphs from detection results with OCSF entity extraction
- **Health Monitoring**: DynamoDB-cached source health checks, EventBridge scheduled (every 15 min)
- **Cedar Authorization**: RBAC with 5 groups (admin, detection-engineer, soc-analyst, incident-responder, read-only) and 20 fine-grained actions
- **Lambda Deployment**: ~15MB web zip, ~12MB health zip, 220ms cold start, 1-2ms warm

## Quick Start

### Prerequisites

- **Rust** (stable toolchain)
- **AWS credentials** configured
- **cargo-lambda** (for Lambda builds): `cargo install cargo-lambda`

### Build & Test

```bash
cd irone-rs
cargo test --workspace    # 276 tests
cargo build --release     # Build all crates
```

### Deploy

```bash
# Deploy Rust Lambda (web API)
./scripts/deploy_rust_lambda.sh web

# Deploy Rust Lambda (health checker)
./scripts/deploy_rust_lambda.sh health

# Deploy both
./scripts/deploy_rust_lambda.sh

# Deploy frontend to S3 + CloudFront
./scripts/deploy_frontend.sh iris-frontend-415aeeaed7a5 EHQTNGR6VJ0YM

# Deploy CDK infrastructure
./scripts/deploy_cdk.sh
```

### Detection Rules

Rules are OCSF-native YAML in `irone-rs/rules/`. Each rule targets an OCSF event class and applies declarative filters:

```yaml
id: detect-api-permission-enumeration
name: API Permission Enumeration by IAM User
description: >
  Detects a high volume of failed API calls from IAM users,
  which may indicate an attacker probing for accessible permissions.
severity: high
event_class: api_activity
limit: 5000
threshold: 20
tags:
  - reconnaissance
  - permission-enumeration
mitre_attack:
  - T1580
  - T1526
data_sources:
  - cloudtrail
filters:
  - field: status
    equals: Failure
  - field: actor.user.type
    equals: IAMUser
```

**9 bundled rules** covering: IAM privilege escalation, root console login, Security Hub critical findings, Cognito auth failure spikes, Lambda invocation spikes, console login detection, GitHub OIDC role assumption, API permission enumeration, and Lambda execution failures.

Filter operators: `equals`, `not_equals`, `contains`, `in`, `regex`.

### Configuration

All config via environment variables with `SECDASH_` prefix:

| Variable | Description |
|----------|-------------|
| `SECDASH_SECURITY_LAKE_DB` | Glue database for Security Lake |
| `SECDASH_ATHENA_WORKGROUP` | Athena workgroup name |
| `SECDASH_ATHENA_OUTPUT` | S3 path for Athena results |
| `SECDASH_USE_DIRECT_QUERY` | Enable direct Iceberg reads (bypasses Athena) |
| `SECDASH_RULES_DIR` | Directory for YAML detection rules |
| `SECDASH_HEALTH_CACHE_TABLE` | DynamoDB table for health cache |
| `SECDASH_REPORT_BUCKET` | S3 bucket for report storage |
| `SECDASH_COGNITO_*` | Cognito OAuth configuration |

## Development

### Pre-commit Hooks

Uses [prek](https://github.com/catppuccin/prek):

- `cargo fmt --check` — format check on every commit
- `cargo clippy -- -D warnings` — lint on every commit
- `cargo deny check` — license/advisory check on every commit
- `cargo test --workspace` — full test suite on pre-push

### API Endpoints

21 JSON API endpoints under `/api/`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/auth/config` | GET | Auth configuration for frontend |
| `/api/dashboard` | GET | Dashboard summary |
| `/api/sources` | GET | List all data sources |
| `/api/sources/health` | GET | Cached health for all sources |
| `/api/sources/{name}/health` | GET | Health for a single source |
| `/api/sources/{name}/health/history` | GET | Health history for a source |
| `/api/sources/refresh` | POST | Trigger live health check |
| `/api/rules` | GET | List all detection rules |
| `/api/rules/{rule_id}` | GET | Get a single rule |
| `/api/detections/{rule_id}/run` | POST | Execute a detection rule |
| `/api/query` | POST | Run an ad-hoc OCSF query |
| `/api/investigations` | GET | List investigations |
| `/api/investigations` | POST | Create investigation |
| `/api/investigations/from-detection` | POST | Detect → graph → timeline pipeline |
| `/api/investigations/{id}` | GET | Get investigation |
| `/api/investigations/{id}` | DELETE | Delete investigation |
| `/api/investigations/{id}/graph` | GET | Get investigation graph |
| `/api/investigations/{id}/report` | GET | Get investigation report |
| `/api/investigations/{id}/enrich` | POST | Enrich investigation with context |
| `/api/investigations/{id}/timeline/tag` | POST | Tag a timeline event |

Auth routes (`/auth/*`) are provided by `l42-token-handler` (Cognito OAuth login/logout/callback).

## Security

See [SECURITY.md](SECURITY.md) for security design decisions and responsible disclosure.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
