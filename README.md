<p align="center">
  <img src="assets/logo.png" alt="irone logo" width="400">
</p>

<h1 align="center">irone — Security Data Lake Analytics</h1>

<p align="center">
  <a href="https://claude.com/claude-code"><img src="https://img.shields.io/badge/Built%20with-Claude%20Code-6B48FF?style=flat&logo=claude" alt="Built with Claude Code"></a>
</p>

A Rust-based security analytics platform for AWS Security Lake. Run OCSF-native detection rules against live data, build investigation graphs, and deploy as lightweight AWS Lambda functions.

The name "irone" comes from the aromatic compound found in iris flowers — and contains "iron", a nod to Rust.

## Architecture

```
irone/
├── irone-rs/                  # Rust workspace (8 crates, 447 tests)
│   ├── irone-core/            # Config, connectors, catalog, detections, graph, reports
│   ├── irone-aws/             # Iceberg + Athena connectors, DynamoDB, SNS, SSM secrets
│   ├── irone-persistence/     # redb-backed investigation + detection store
│   ├── irone-auth/            # Cognito OAuth + Cedar authorization (via l42-token-handler)
│   ├── irone-web/             # Axum web layer — 26 API endpoints, Lambda handler
│   ├── irone-worker/          # Investigation enrichment worker (Step Functions)
│   ├── irone-alerting/        # Scheduled detection + freshness alerting Lambda
│   ├── irone-health-checker/  # Scheduled EventBridge Lambda for parallel health checks
│   └── rules/                 # 45 OCSF detection rules (YAML)
├── frontend/                 # Static Alpine.js frontend → S3 + CloudFront
├── infra/                    # TypeScript CDK (5 stacks)
├── scripts/                  # Deploy + migration scripts
└── docs/                     # Cost estimates, Rust patterns guide
```

## Features

- **AWS Security Lake**: Query OCSF-formatted data via direct Iceberg reads (sub-second) or Athena fallback
- **OCSF Detection Rules**: 45 bundled rules with declarative field filters, MITRE ATT&CK mapping, and kill-chain phase classification
- **Investigation Graphs**: Build security graphs from detection results with OCSF entity extraction, attack path analysis, and anomaly detection
- **Automated Alerting**: Hourly detection scans + 15-minute freshness checks via scheduled Lambda
- **Health Monitoring**: DynamoDB-cached source health checks with history tracking
- **Cedar Authorization**: RBAC with 5 groups (admin, detection-engineer, soc-analyst, incident-responder, read-only) and 20 fine-grained actions
- **Passkey Authentication**: WebAuthn/FIDO2 passkey login via Cognito + l42-cognito-passkey
- **Lambda Deployment**: ~10MB web zip, ~7MB health zip, 220ms cold start, 1-2ms warm

## Quick Start

### Prerequisites

- **Rust** (stable toolchain, edition 2024)
- **AWS credentials** configured
- **cargo-lambda** (for Lambda builds): `cargo install cargo-lambda`

### Build & Test

```bash
cd irone-rs
cargo test --workspace    # 447 tests
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

**45 bundled rules** covering: IAM privilege escalation, root console login, Security Hub critical findings, Cognito auth failure spikes, Lambda invocation spikes, console login detection, GitHub OIDC role assumption, API permission enumeration, S3 public access, IMDS credential theft, VPC flow anomalies, and more.

Filter operators: `equals`, `not_equals`, `contains`, `in`, `regex`.

### Configuration

All config via environment variables with `SECDASH_` prefix:

| Variable | Description |
|----------|-------------|
| `SECDASH_SECURITY_LAKE_DB` | Glue database for Security Lake |
| `SECDASH_USE_DIRECT_QUERY` | Enable direct Iceberg reads (bypasses Athena) |
| `SECDASH_RULES_DIR` | Directory for YAML detection rules |
| `SECDASH_HEALTH_CACHE_TABLE` | DynamoDB table for health cache |
| `SECDASH_REPORT_BUCKET` | S3 bucket for report storage |
| `SECDASH_SESSION_BACKEND` | Session backend (`dynamodb` or `memory`) |
| `SECDASH_COGNITO_*` | Cognito OAuth configuration |
| `SECDASH_*_SSM` | SSM Parameter Store names for secrets (see [SECURITY.md](SECURITY.md)) |

## Development

### Pre-commit Hooks

Uses [prek](https://github.com/catppuccin/prek):

- `cargo fmt --check` — format check on every commit
- `cargo clippy -- -D warnings` — lint on every commit
- `cargo deny check` — license/advisory check on every commit
- `cargo test --workspace` — full test suite on pre-push

### Rust Patterns

See [docs/rust-patterns.md](docs/rust-patterns.md) for a guide to the Rust patterns and architecture used in this codebase — useful for contributors coming from other languages.

### API Endpoints

26 JSON API endpoints under `/api/`:

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
| `/api/detections/history` | GET | Detection run history |
| `/api/detections/{rule_id}/run` | POST | Execute a detection rule |
| `/api/query` | POST | Run an ad-hoc OCSF query |
| `/api/investigations` | GET | List investigations |
| `/api/investigations` | POST | Create investigation |
| `/api/investigations/from-detection` | POST | Detect → graph → timeline pipeline |
| `/api/investigations/seed` | POST | Seed investigation from raw data |
| `/api/investigations/{id}` | GET | Get investigation |
| `/api/investigations/{id}` | DELETE | Delete investigation |
| `/api/investigations/{id}/graph` | GET | Get investigation graph |
| `/api/investigations/{id}/report` | GET | Get investigation report |
| `/api/investigations/{id}/timeline` | GET | Get investigation timeline |
| `/api/investigations/{id}/attack-paths` | GET | Get attack path analysis |
| `/api/investigations/{id}/anomalies` | GET | Get anomaly scores |
| `/api/investigations/{id}/enrich` | POST | Enrich investigation with context |
| `/api/investigations/{id}/timeline/tag` | POST | Tag a timeline event |

Auth routes (`/auth/*`) are provided by `l42-token-handler` (Cognito OAuth login/logout/callback, passkey management).

## Security

See [SECURITY.md](SECURITY.md) for security design decisions and responsible disclosure.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
