# Security

## Security Design

irone is designed for use as an internal security analytics tool. The primary threat model assumes trusted operators deploying in controlled AWS environments with proper IAM boundaries.

### Query Construction

All Security Lake queries are constructed safely in Rust:

- **Athena queries** (`irone-aws`): Parameterized SQL templates with identifier validation — database/table names enforced via `^[a-zA-Z_][a-zA-Z0-9_]*$` regex, timestamps formatted via `chrono` (no string interpolation)
- **Iceberg queries** (`irone-aws`): Direct Parquet reads via `iceberg-rust` + `arrow-rs` — no SQL construction at all; predicates are Arrow filter expressions
- **Destructive keyword blocklist**: Ad-hoc queries reject DROP, DELETE, INSERT, UPDATE, TRUNCATE, ALTER, CREATE

### Detection Rule Isolation

Detection rules are loaded exclusively from YAML files at startup:

- **YAML-only parsing** via `serde_yaml` — no arbitrary code execution
- **Schema validation** via Rust type system — `DetectionRule` struct enforces required fields, valid `FilterOp` variants, and `OCSFEventClass` enum values
- **No dynamic rule loading** — rules are bundled into the Lambda zip at deploy time from `irone-rs/rules/`
- **Filter operators** are a closed enum: `Equals`, `NotEquals`, `Contains`, `In`, `Regex` — no arbitrary expressions
- **30-second query timeout** — `tokio::time::timeout` prevents hung connectors from blocking indefinitely

### Authentication & Authorization

- **Cognito OAuth**: Dual-client pattern — confidential server-side client (with `client_secret`) for OAuth code exchange, plus a public client for browser-side password and WebAuthn/passkey authentication
- **Passkey support**: WebAuthn/FIDO2 passkeys via `l42-cognito-passkey` integration. Passkey registration and management on the settings page
- **Cedar RBAC**: 5 groups (admin, detection-engineer, soc-analyst, incident-responder, read-only) with 20 fine-grained actions in the `Secdash::` namespace. Policy evaluation runs on every API request via axum middleware
- **Session storage**: DynamoDB `secdash_sessions` table with server-side session state, HttpOnly cookies
- **AWS APIs**: Standard AWS SDK for Rust credential chain (no hardcoded credentials)

### Secrets Management

Secrets are stored in AWS SSM Parameter Store as `SecureString` parameters (encrypted with the default `aws/ssm` KMS key):

| Secret | SSM Parameter | Lambda Env Var |
|--------|---------------|----------------|
| Cognito client secret | `/secdash/cognito-client-secret` | `SECDASH_COGNITO_CLIENT_SECRET_SSM` |
| Session encryption key | `/secdash/session-secret-key` | `SECDASH_SESSION_SECRET_SSM` |
| Service API token | `/secdash/service-token` | `SECDASH_SERVICE_TOKEN_SSM` |

Lambda env vars contain only the SSM parameter *name* (a pointer), not the secret value. At startup, the Lambda calls `ssm:GetParameter` with `WithDecryption=true` to fetch and decrypt. If the SSM parameter is unavailable, it falls back to reading the direct env var (e.g., `SECDASH_SERVICE_TOKEN`) for local development.

IAM is scoped: `ssm:GetParameter` on `arn:aws:ssm:REGION:ACCOUNT:parameter/secdash/*`, plus `kms:Decrypt` conditioned on `kms:ViaService: ssm.REGION.amazonaws.com` (prevents using the KMS key outside SSM).

### Network Architecture

- **CloudFront** → S3 (static frontend) + API Gateway v2 (Lambda)
- **API Gateway**: HTTP API with Lambda proxy integration, no public endpoints bypass auth
- **Host header stripping**: `ALL_VIEWER_EXCEPT_HOST_HEADER` cache policy — Lambda sees API Gateway hostname, `SECDASH_COGNITO_REDIRECT_URI` set explicitly

## Known Sharp Edges

These are design decisions with security trade-offs that operators should understand:

### Threshold=0 Always Triggers

A detection rule with `threshold: 0` triggers on any query result, even zero matches. This is by design (documented in proptest invariants) but may surprise operators. Set threshold >= 1 for meaningful detection.

### NotEquals Filter on Missing Fields

`NotEquals` filter passes when the target field is missing from an OCSF event (missing != "value" is true). This means a `not_equals: "Root"` filter won't exclude events that lack the field entirely. Use `equals` for allowlisting instead.

### String-Only Filter Coercion

All filter comparisons coerce OCSF values to strings via `serde_json::Value::to_string()`. Numeric fields like `status_id` must be quoted in rule YAML: `equals: "1"`, not `equals: 1`.

### Enrichment Query Amplification

`POST /api/investigations/{id}/enrich` runs N users x M event classes + N IPs x M event classes unfiltered Iceberg scans. For investigations with many entities, this can generate ~60 queries scanning hundreds of Parquet files. API Gateway's 29-second timeout will cut off large enrichments. Enrichment is currently disabled on the `from-detection` pipeline for this reason.

## Reporting Security Issues

If you discover a security vulnerability, please report it via GitHub private vulnerability reporting at:

https://github.com/lexicone42/irone/security/advisories/new

Do not open a public issue for security vulnerabilities.
