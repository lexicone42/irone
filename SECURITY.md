# Security

## Security Design

secdashboards is designed for use as an internal security analytics tool. The primary threat model assumes trusted operators deploying in controlled AWS environments with proper IAM boundaries.

### SQL Injection Protection

All Security Lake and Athena queries use parameterized construction via `connectors/sql_utils.py`:

- **`sanitize_string()`** — escapes quotes, removes null bytes and SQL comment sequences
- **`validate_identifier()`** — enforces `^[a-zA-Z_][a-zA-Z0-9_]*$` for SQL identifiers
- **`quote_identifier()` / `quote_table()`** — ANSI double-quoting for identifiers
- **`validate_ipv4()` / `validate_arn()`** — format validation for common AWS types
- **Destructive keyword blocklist** — rejects queries containing DROP, DELETE, INSERT, UPDATE, TRUNCATE, ALTER, CREATE

### Detection Rule Isolation

Detection rules are loaded from YAML by default. The `S3RuleStore` enforces:

- YAML-only parsing (no arbitrary code execution)
- Pydantic schema validation on rule structure
- SQL keyword blocklist on rule queries
- Rule ID format validation (`^[a-zA-Z0-9_-]+$`)

### Authentication

- **Neptune**: IAM authentication via SigV4-signed requests (default: `use_iam_auth=True`)
- **Health Dashboard**: OIDC/Cognito authentication via ALB integration
- **AWS APIs**: Standard boto3 credential chain (no hardcoded credentials)

## Known Sharp Edges

These are design decisions with security trade-offs that operators should understand:

### Python Rule Loading (Critical — Default Off)

Setting `SECDASH_ALLOW_PYTHON_RULES=1` enables loading arbitrary Python code as detection rules. This is **disabled by default** and logs a warning when enabled. Only enable in trusted development environments.

```bash
# DO NOT set in production
export SECDASH_ALLOW_PYTHON_RULES=1  # Allows arbitrary code execution
```

### SQL Construction in Base Connector

`DataConnector.query_time_range()` in `connectors/base.py` accepts `columns`, `time_column`, and `additional_filters` as string parameters without sanitization. These are safe when called from internal code but should not accept untrusted user input directly. The specialized connectors (`SecurityLakeConnector`, `AthenaConnector`) apply proper sanitization.

### Webhook URL Handling

`SlackNotifier` and `URLAnalyzer` accept URLs without validation. In the intended deployment model, URLs come from operator configuration (environment variables, constructor arguments), not from end users. If exposing URL parameters to untrusted input, add URL validation first.

### Lambda Deployment Parameters

`LambdaBuilder.deploy_lambda()` does not bounds-check `memory_mb` or `timeout_seconds`. Invalid values will be rejected by the AWS API at deploy time, but early validation would provide better error messages.

## Reporting Security Issues

If you discover a security vulnerability, please report it via GitHub private vulnerability reporting at:

https://github.com/lexicone42/secdashboards/security/advisories/new

Do not open a public issue for security vulnerabilities.
