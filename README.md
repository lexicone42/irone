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
├── irone-rs/                  # Rust workspace (8 crates, 515+ tests)
│   ├── irone-core/            # Config, connectors, catalog, detections, graph, reports,
│   │                          #   playbooks (SOAR engine), investigator (Claude AI analysis)
│   ├── irone-aws/             # Iceberg + Athena connectors, DynamoDB, SNS, SSM secrets
│   ├── irone-persistence/     # redb-backed investigation + detection store
│   ├── irone-auth/            # Cognito OAuth + Cedar authorization (via l42-token-handler)
│   ├── irone-web/             # Axum web layer — 26 API endpoints, Lambda handler
│   ├── irone-worker/          # Investigation enrichment worker (Step Functions)
│   ├── irone-alerting/        # Scheduled detection + freshness alerting Lambda
│   ├── irone-health-checker/  # Scheduled EventBridge Lambda for parallel health checks
│   ├── rules/                 # 53 OCSF detection rules (YAML) — AWS, EKS, GCP
│   └── playbooks/             # 3 SOAR response playbooks (YAML)
├── frontend/                 # Static Alpine.js frontend → S3 + CloudFront
├── infra/                    # TypeScript CDK (5 stacks)
├── scenarios/                # Mock incident scenarios for interview prep
├── scripts/                  # Deploy + migration scripts
└── docs/                     # Cost estimates, Rust patterns guide
```

## Features

- **AWS Security Lake**: Query OCSF-formatted data via direct Iceberg reads (sub-second) or Athena fallback
- **53 OCSF Detection Rules**: AWS CloudTrail, EKS audit logs, and GCP audit logs with declarative field filters, MITRE ATT&CK mapping (42 techniques across 11 tactics), and kill-chain phase classification
- **Investigation Graphs**: Build security graphs from detection results with OCSF entity extraction, attack path analysis, graph pattern detection (PrivilegeFanout, ResourceConvergence, MultiSourceAuth, ServiceBridge), and MAD-based anomaly scoring
- **SOAR Playbook Engine**: Declarative response playbooks with trigger matching, approval gates (auto/manual/business-hours), and 10 action types including K8s-specific containment
- **Claude AI Investigator**: Feed investigation artifacts (graph, timeline, patterns, anomalies) to Claude for structured analysis — verdict, confidence, recommended actions, detection improvements
- **Zero-Materialization Scan Path**: Column projection + Arrow-native filtering + lazy evaluation — 381x faster than full JSON materialization on 10K-row OCSF datasets
- **Parallel Detection Runner**: 53 rules execute concurrently via `futures::join_all`
- **Automated Alerting**: Hourly detection scans + 15-minute freshness checks via scheduled Lambda
- **Health Monitoring**: DynamoDB-cached source health checks with history tracking
- **Cedar Authorization**: RBAC with 5 groups (admin, detection-engineer, soc-analyst, incident-responder, read-only) and 20 fine-grained actions
- **Passkey Authentication**: WebAuthn/FIDO2 passkey login via Cognito + l42-cognito-passkey
- **Supply Chain Verification**: `cargo vet` with Google + Mozilla audit imports, `cargo deny` for advisories/licenses
- **Lambda Deployment**: ~16MB web zip, ~13MB worker zip, 220ms cold start, 1-2ms warm

## Quick Start

### Prerequisites

- **Rust** (stable toolchain, edition 2024)
- **AWS credentials** configured
- **cargo-lambda** (for Lambda builds): `cargo install cargo-lambda`

### Build & Test

```bash
cd irone-rs
cargo test --workspace    # 515+ tests
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

**53 bundled rules** across three platforms:
- **AWS** (40 rules): IAM privilege escalation, root console login, CloudTrail tampering, cross-account role assumption, S3 data collection, IMDS credential theft, Lambda layer injection, and more
- **EKS/Kubernetes** (8 rules): privileged pod creation, kubectl exec, RBAC escalation, secret access, DaemonSet/CronJob persistence, service account token theft, NodePort exposure
- **GCP** (5 rules): audit logging tampering, service account key creation, IAM policy changes, bucket exposure, compute enumeration

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

Native shell hook at `.githooks/pre-commit`:

- `cargo fmt --check` — format check on every commit
- `cargo clippy -- -D warnings` — lint on every commit
- `cargo deny check` — license/advisory/ban check on every commit (real failures block commits)

Supply chain: `cargo vet` with Google + Mozilla audit imports (60 crates audited, 501 exempted).

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
| `/api/investigations/{id}/patterns` | GET | Get graph structural patterns |
| `/api/investigations/{id}/enrich` | POST | Enrich investigation with context |
| `/api/investigations/{id}/timeline/tag` | POST | Tag a timeline event |

Auth routes (`/auth/*`) are provided by `l42-token-handler` (Cognito OAuth login/logout/callback, passkey management).

## Security

See [SECURITY.md](SECURITY.md) for security design decisions and responsible disclosure.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
