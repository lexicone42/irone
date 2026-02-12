# Security Dashboards - Current State

**Last Updated**: 2026-02-11

## Project Overview

A security operations platform for connecting to AWS Security Lake, creating detection rules, deploying them to Lambda for automated security monitoring, and testing detections with adversary emulation. Includes investigation graph visualization with Neptune, AI-assisted analysis via Bedrock, and professional report generation.

**Primary UI**: FastAPI + HTMX web application. Server-rendered HTML with HTMX for dynamic updates, DuckDB for local/Lambda SQL, deployable to Lambda via Mangum.

**Authentication**: Cognito passkey/OAuth + Cedar RBAC authorization. 5 groups (admin, detection-engineer, soc-analyst, incident-responder, read-only), 20 Cedar actions. Off by default (`auth_enabled=False`).

**Architecture**: Supports hybrid hot/cold tier with CloudWatch Logs Insights for real-time queries (0-7 days) and Security Lake for long-term storage (7+ days), with unified dual-target detection rules.

## Project Structure

```
secdashboards/
├── src/secdashboards/
│   ├── catalog/           # Data catalog and source management
│   │   ├── models.py      # DataSource, CatalogConfig pydantic models
│   │   └── registry.py    # DataCatalog class for managing sources
│   ├── connectors/        # Data source connectors
│   │   ├── base.py        # DataConnector base class, HealthCheckResult
│   │   ├── athena.py      # AthenaConnector for generic Athena queries
│   │   ├── duckdb.py      # DuckDBConnector for local/Lambda SQL (NEW)
│   │   └── security_lake.py  # SecurityLakeConnector with OCSF support
│   ├── detections/        # Detection rules framework
│   │   ├── rule.py        # DetectionRule, SQLDetectionRule, DetectionResult
│   │   ├── runner.py      # DetectionRunner for executing rules
│   │   └── rule_store.py  # S3RuleStore for secure YAML-only rule storage
│   ├── graph/             # Investigation graph module
│   │   ├── models.py      # Node/edge entity models (Pydantic)
│   │   ├── builder.py     # Graph construction from detections
│   │   ├── connector.py   # Neptune database connector
│   │   ├── enrichment.py  # Security Lake enrichment queries
│   │   ├── visualization.py  # pyvis graph visualization
│   │   ├── timeline.py    # Timeline visualization with Plotly
│   │   └── queries.py     # Gremlin/openCypher query templates
│   ├── web/               # FastAPI + HTMX web application (NEW)
│   │   ├── app.py         # create_app() factory, router registration, auth wiring
│   │   ├── config.py      # WebConfig(BaseSettings) with SECDASH_ env prefix + auth fields
│   │   ├── state.py       # AppState dataclass, create_app_state() factory
│   │   ├── lambda_handler.py  # Mangum ASGI→Lambda adapter
│   │   ├── report_generator.py  # HTML report rendering (Report models → HTML)
│   │   ├── auth/                  # Authentication & authorization (NEW — PR #13)
│   │   │   ├── __init__.py        # Exports: require_auth, get_current_user
│   │   │   ├── cognito.py         # JWKS verification, token exchange, refresh
│   │   │   ├── cedar_engine.py    # Cedar authorization (Secdash:: namespace)
│   │   │   ├── dependencies.py    # FastAPI deps: require_auth, require_csrf
│   │   │   ├── middleware.py      # Global auth enforcement (redirect/401)
│   │   │   ├── session/           # Server-side session management
│   │   │   │   ├── backend.py     # SessionBackend protocol + InMemoryBackend
│   │   │   │   ├── middleware.py  # ASGI session middleware (signed cookies)
│   │   │   │   └── dynamodb.py   # DynamoDB session backend (production)
│   │   │   └── routes/            # 8 auth endpoints (/auth/*)
│   │   │       ├── login.py      # GET /auth/login → Cognito redirect
│   │   │       ├── token.py      # GET /auth/token
│   │   │       ├── session_ep.py  # POST /auth/session
│   │   │       ├── callback.py   # GET /auth/callback (OAuth)
│   │   │       ├── refresh.py    # POST /auth/refresh
│   │   │       ├── logout.py     # POST /auth/logout
│   │   │       ├── me.py         # GET /auth/me
│   │   │       └── authorize.py  # POST /auth/authorize (Cedar)
│   │   ├── cedar/                 # Cedar policy files (NEW — PR #13)
│   │   │   ├── schema.cedarschema.json  # Secdash entity types + 20 actions
│   │   │   └── policies/         # 5 RBAC group policies
│   │   ├── routers/
│   │   │   ├── dashboard.py      # GET / — overview with source/rule counts
│   │   │   ├── monitoring.py     # /monitoring/ — health checks
│   │   │   ├── security_lake.py  # /security-lake/ — connectivity testing
│   │   │   ├── detections.py     # /detections/ — rule CRUD, testing, AI generation
│   │   │   ├── investigations.py # /investigations/ — graph investigations
│   │   │   ├── deploy.py         # /deploy/ — Lambda build dashboard
│   │   │   └── api.py            # /api/ — JSON API for programmatic access
│   │   ├── templates/
│   │   │   ├── base.html         # Base layout with nav, HTMX, CSRF header, terminal CSS
│   │   │   ├── components/       # Reusable HTMX fragments (+ user info/logout)
│   │   │   ├── pages/            # Full-page templates per router
│   │   │   └── reports/          # Self-contained HTML report templates
│   │   └── static/
│   │       ├── css/terminal.css  # Dark terminal aesthetic
│   │       └── js/app.js         # HTMX config + toast notifications
│   ├── reports/           # Report generation
│   │   ├── latex_renderer.py  # LaTeX/PDF report generation
│   │   ├── exporters.py   # S3 export and PDF compilation
│   │   ├── converters.py  # Graph to report data conversion
│   │   └── templates/     # Jinja2 LaTeX templates
│   ├── health/            # Health monitoring
│   │   ├── monitor.py     # HealthMonitor for checking data sources
│   │   ├── alerting_handler.py # Lambda handler for alerting stack
│   │   └── url_analyzer.py # URLAnalyzer for external URL health
│   ├── deploy/            # Lambda deployment
│   │   ├── lambda_builder.py  # LambdaBuilder for deployment packages
│   │   └── scheduler.py   # DetectionScheduler for EventBridge rules
│   ├── adversary/         # Red team and adversary emulation
│   │   ├── events.py      # OCSF-compliant synthetic event generators
│   │   ├── network.py     # Network packet generation for testing
│   │   ├── scenarios.py   # MITRE ATT&CK attack scenarios
│   │   ├── runner.py      # Adversary test runner
│   │   ├── lambda_handler.py # Lambda for network-based testing
│   │   └── deploy.py      # Lambda deployment utilities
│   ├── notifications/     # Alert delivery
│   │   ├── base.py        # SecurityAlert model, NotificationChannel ABC
│   │   ├── sns.py         # SNSNotifier for AWS SNS topics
│   │   ├── slack.py       # SlackNotifier for Slack webhooks
│   │   └── manager.py     # NotificationManager multi-channel routing
│   ├── ai/                # AI/Bedrock integration
│   │   ├── assistant.py   # BedrockAssistant for AI analysis
│   │   ├── models.py      # Model configs and pricing
│   │   ├── prompts.py     # Security-focused prompts
│   │   └── tools.py       # Agent tools skeleton
│   ├── security/          # Security infrastructure
│   │   └── auth.py        # OIDCAuthenticator for ALB/Cognito auth
│   └── cli.py             # CLI: serve, deploy, etc.
├── scripts/
│   └── example_investigation.py  # Demo investigation workflow
├── detections/
│   ├── sample_rules.yaml         # 6 CloudTrail detection rules
│   ├── vpc_flow_rules.yaml       # 4 VPC Flow detection rules
│   ├── dns_rules.yaml            # 4 Route53 DNS detection rules
│   └── security_hub_rules.yaml   # 4 Security Hub detection rules
├── infrastructure/
│   ├── neptune.yaml           # Neptune Serverless CloudFormation stack
│   └── cdk/                   # AWS CDK stacks
│       ├── stacks/
│       │   ├── alerting.py          # AlertingStack (SNS, Lambda, EventBridge)
│       │   ├── detection_rules.py   # DetectionRulesStack (Lambda per rule, shared Layer)
│       │   ├── health_dashboard.py  # HealthDashboardStack (API Gateway, Cognito)
│       │   ├── fastapi_stack.py     # FastAPIStack (Lambda + API GW v2 + DynamoDB sessions)
│       │   └── shared_auth.py       # SharedAuthStack (Cognito User Pool + web client)
│       └── tests/
│           ├── test_health_dashboard_stack.py  # 12 tests
│           ├── test_alerting_stack.py          # 7 tests
│           └── test_detection_rules_stack.py   # 10 tests
├── docs/                    # mkdocs-material API documentation
├── tests/                   # 697 tests total (+ 29 CDK tests separate)
├── catalog.example.yaml     # Example catalog configuration
├── mkdocs.yml               # Documentation site config
├── pyproject.toml           # Project configuration (uv, ruff, ty)
└── README.md                # Documentation
```

## Recent Changes (2026-02-11)

### PR #14 — Deploy Lambda with Lazy Imports (`feature/deploy-lambda-lazy-imports`)

Deployed `secdash-shared-auth` and `secdash-web` CDK stacks to AWS. Converted all heavy optional dependencies to lazy imports for fast Lambda cold starts. Full auth flow verified end-to-end in browser.

**Deployed infrastructure:**
| Resource | Details |
|----------|---------|
| User Pool | `us-west-2_EgkXXauzP` (5 RBAC groups, OAuth web client) |
| Web Client ID | `5hh278qt9lcmm5q4nls1nq110h` |
| Cognito Domain | `secdash-auth-651804262336.auth.us-west-2.amazoncognito.com` |
| API Gateway | `https://udy3l282oh.execute-api.us-west-2.amazonaws.com` |
| Lambda | `secdash-web-FastAPIHandlerC4831E27-KlK3BmblmlcV` (Python 3.13, 512MB) |
| Session Table | `secdash_sessions` (DynamoDB, TTL-enabled) |
| Report Bucket | `secdash-web-reportbucket577f0fcd-f0gcyawogvqr` |
| Test User | `bryan.egan@gmail.com` (admin group) |

**Lazy imports (13 files):**
- Package `__init__.py`: `__getattr__` pattern — avoids eager loading of polars, pyvis, pyarrow, plotly at import time
- All connector, detection, graph, adversary, and health modules: `TYPE_CHECKING` + runtime `import polars as pl` inside methods
- Lambda package reduced from 662MB to 160MB via slim requirements (excludes polars, pyarrow, pandas, numpy, plotly)

**CDK changes:**
- `shared_auth.py`: Disabled passkey (needs custom domain for WebAuthn RP ID), added `passkey_relying_party_domain` param, added `additional_callback_urls`/`additional_logout_urls`
- `fastapi_stack.py`: Added `lambda_package_dir` param, fixed handler to `secdashboards.web.lambda_handler.handler`
- `app.py`: Wired `user_pool_client_secret` via CDK cross-stack reference, added `API_GATEWAY_URL` and `LAMBDA_PACKAGE_DIR` env vars

**Lambda packaging**: Built with `uv pip install --target /tmp/secdash-lambda -r requirements-slim.txt` + source copy. No Docker needed.

**Auth flow verified**: Browser → middleware redirect → Cognito hosted UI → OAuth callback → session → dashboard loads with nav, stats (38 detection rules), and registered sources.

### PR #13 — Cognito Passkey Auth + Cedar Authorization (`feature/cognito-cedar-auth`)

Ported authentication system from `l42-cognito-passkey` into secdashboards with Secdash-specific Cedar RBAC policies. Auth is disabled by default (`auth_enabled=False`) so all existing tests pass unchanged.

**New modules (22 files):**
- `auth/cognito.py`: JWKS verification, token exchange, refresh via Cognito
- `auth/cedar_engine.py`: Cedar authorization with `Secdash::` namespace, custom group mapping
- `auth/dependencies.py`: FastAPI deps — `require_auth`, `require_csrf`, `get_current_user`
- `auth/middleware.py`: Global auth enforcement (exempt: `/auth/*`, `/api/health`, `/static/*`)
- `auth/session/`: Server-side sessions — `InMemoryBackend`, `DynamoDBSessionBackend`, ASGI middleware
- `auth/routes/`: 8 endpoints — login, token, session, callback, refresh, logout, me, authorize
- `cedar/`: Schema (20 actions) + 5 policy files (admin, detection-engineer, soc-analyst, incident-responder, read-only)

**Cedar RBAC groups and actions (20 total):**
| Group | Key permissions |
|-------|----------------|
| admin | All 20 actions |
| detection-engineer | view:*, create/test detections, query:data, ai:generate_rule |
| soc-analyst | view:*, create/view investigations, ai:analyze |
| incident-responder | view dashboards/detections/investigations, create/enrich/export investigations |
| read-only | view:dashboard, view:monitoring |

**Modified files (9):**
- `pyproject.toml`: Added pyjwt, cedarpy, itsdangerous, aioboto3 + cryptography dev dep
- `config.py`: 12 auth fields (cognito_*, session_*, auth_enabled, cedar_enabled)
- `app.py`: Conditional auth middleware, Cedar init in lifespan, `_build_session_backend()`
- `templates/base.html`: CSRF header (`X-L42-CSRF`) for all HTMX requests
- `templates/components/nav.html`: User info display + logout link
- CDK: DynamoDB session table, auth env vars, SharedAuthStack web UserPoolClient

**New tests (88 tests across 14 files):**
- `tests/conftest.py`: Shared fixtures (RSA keys, JWT factory, auth app/client)
- 13 `test_auth_*.py` files: session middleware, all endpoints, Cedar engine, CSRF, DynamoDB, integration

**Net**: 47 files changed, +3,095 lines

**Test count**: 609 → 697 (+88 new auth tests)

### PR #12 — Remove Marimo/Docker/App Runner (`feature/remove-marimo-docker`)

Removed all Marimo notebook, Docker, and App Runner artifacts from the codebase. The FastAPI + HTMX migration (PRs #6–#11) fully replaced these components.

**Deleted (9 files):**
- 6 Marimo notebooks (`notebooks/*.py`)
- `Dockerfile.marimo`
- `infrastructure/marimo-apprunner.yaml`
- `infrastructure/cdk/stacks/marimo_auth.py`

**Modified (14 files):**
- `cli.py`: Removed deprecated `notebook()` command
- `visualization.py`: Removed `display_in_marimo()` method and unused `Any` import
- `pyproject.toml`: Removed `[dependency-groups.notebook]` (marimo), notebook ruff per-file-ignores, visualization.py from ty excludes
- CDK: Removed `MarimoAuthStack`, `app_runner_domain` parameter from HealthDashboardStack, App Runner CloudFront behaviors
- `.gitignore`: Removed `notebooks/__marimo__/` entry
- `infrastructure/alb-oidc-auth.yaml`: Updated descriptions (Marimo → Security Dashboards)
- `infrastructure/cdk/stacks/shared_auth.py`: Updated docstring (Marimo → FastAPI)
- Documentation (README.md, docs/index.md, quickstart.md, CURRENT_STATE.md): Updated for FastAPI-first architecture

**Lockfile**: 12 packages removed (marimo, openai, docutils, psutil, etc.)

**Net**: 23 files changed, +32 / −4,779 lines

### FastAPI Migration (PRs #6–#11)

Replaced Marimo notebook UI with FastAPI + HTMX web application. 6 PRs, all merged to `main`.

- **PR #6** — DuckDB Connector: `DuckDBConnector` ABC, `:memory:`/file/S3, 21 tests
- **PR #7** — FastAPI Core: `WebConfig`, `AppState`, `create_app()`, `secdash serve`, Mangum handler, 10 tests
- **PR #8** — Templates + Simple Routers: terminal CSS, nav, dashboard/monitoring/security-lake routers, 14 tests
- **PR #9** — Complex Routers: detections/investigations/deploy/API routers, HTMX patterns, 50 tests
- **PR #10** — Reports + CDK: HTML report generator, FastAPIStack CDK, 16 tests
- **PR #11** — Cleanup: deprecated notebook command, moved marimo to optional deps

**Test count**: 498 → 609 (+111 new tests)

### Type Hints & Any Audit
- Tightened ty rules: `possibly-missing-attribute` from "warn" to "error", added `division-by-zero = "warn"`
- Replaced 8 `Any` annotations with concrete types (GraphNode, GraphEdge, NeptuneConnector, etc.)

### Detection Lifecycle Tests
- 14 new tests in `test_detections.py` covering register/get/list/delete/overwrite/run/export

## Previous Changes (2026-02-10)

### PR #5: Detection Runner Wiring, CDK Tests, Detection Rules, Neptune Tests
- **DetectionRunner in alerting Lambda**: Wired `DetectionRunner` + `S3RuleStore` into `alerting_handler.py`
- **CDK assertion tests**: 17 new tests for AlertingStack (7) and DetectionRulesStack (10)
- **Detection rules expansion**: 12 new rules across VPC Flow (4), DNS/Route53 (4), Security Hub (4)
- **Deployment notebook**: Rewrote for CDK workflow (removed SAM references)
- **Neptune mock tests**: 39 tests covering CRUD, graph ops, health checks, result conversion
- **CI pipeline**: Added GitHub Actions (lint, test, docs) — **disabled for now** (ruff version mismatch)

### PR #4: Mkdocs, Timeline Wiring, Neptune Workflows
- **mkdocs-material**: API documentation with mkdocstrings auto-generated from docstrings
- **Timeline in reports**: Wired timeline events into LaTeX report generation
- **Neptune in notebook**: Wired save/load graph to Neptune into investigation notebook

### PR #3: CDK Consolidation & Notifications Wiring
- **Removed SAM templates**: Deleted `template.yaml`, `health-dashboard.yaml`, `deploy-dashboard.sh`
- **New DetectionRulesStack**: CDK stack for deploying detection Lambdas with shared notifications layer
- **Updated AlertingStack**: Extracted inline Lambda code into `alerting_handler.py`
- **Lambda handler templates**: Now use `NotificationManager` (SNS + Slack)
- **Notifications Lambda Layer**: `LambdaBuilder.build_notifications_layer()`

### PR #2: Input Validation
- URL validation for SlackNotifier and URLAnalyzer (HTTPS enforcement)
- Bounds validation for LambdaBuilder.deploy_lambda() parameters

### PR #1: Documentation, Security, Property-Based Tests
- SECURITY.md with vulnerability reporting guidelines
- Property-based tests for SQL sanitization and alert serialization
- py.typed marker for PEP 561

## Configuration

- **Package Manager**: uv
- **Linter**: ruff (line-length=100)
- **Type Checker**: ty (Astral) — in pre-commit via prek, `possibly-missing-attribute = "error"`
- **Pre-commit**: prek (Rust-based)
- **Default Region**: us-west-2
- **Python Version**: 3.13
- **Web Framework**: FastAPI + HTMX (Jinja2 templates)
- **Local SQL Engine**: DuckDB (in-memory for tests, file-backed or `/tmp/` for Lambda)

## Dependencies

Key dependencies in pyproject.toml:
- fastapi>=0.115.0 - Web framework
- uvicorn[standard]>=0.32.0 - Local dev server
- mangum>=0.19.0 - ASGI→Lambda adapter
- duckdb>=1.1.0 - Local/Lambda SQL engine
- python-multipart>=0.0.22 - Form data parsing for FastAPI
- pyjwt[crypto]>=2.10.0 - JWT verification (Cognito JWKS) (NEW)
- cedarpy>=4.8.0 - Cedar authorization engine (NEW)
- itsdangerous>=2.2.0 - Session cookie signing (NEW)
- aioboto3>=13.0.0 - Async DynamoDB for session backend (NEW)
- boto3>=1.35.0 - AWS SDK
- polars>=1.0.0 - Data processing
- pydantic>=2.10.0 - Data validation
- pyvis>=0.3.2 - Graph visualization
- plotly>=5.24.0 - Timeline visualization
- gremlinpython>=3.7.0 - Neptune client
- networkx>=3.2 - Graph analysis
- jinja2>=3.1.0 - Template rendering

## Test Status

### Unit Tests (697 total - all passing)
```bash
uv run pytest tests/ -v
```

Test breakdown:
- Catalog: 8
- DuckDB Connector: 21
- Detection: 23
- Adversary: 36
- Graph: 50
- AI/Bedrock: 26
- Reports: 58
- Report Generator (HTML): 16
- Rule Store: 32
- SQL Utils: 32
- Timeline: 24
- Notifications: 28
- Deployment: 33
- Alerting Handler: 8
- Neptune Connector: 39
- Web App: 10
- Web Routers (simple): 14
- Web Routers (detections): 13
- Web Routers (investigations): 15
- Web Routers (API): 13
- Web Routers (deploy): 9
- Auth Session Middleware: 9 (NEW)
- Auth Session Endpoint: 6 (NEW)
- Auth Token: 4 (NEW)
- Auth Callback: 5 (NEW)
- Auth Refresh: 5 (NEW)
- Auth Logout: 2 (NEW)
- Auth Me: 2 (NEW)
- Auth Authorize: 7 (NEW)
- Auth Cedar Engine: 15 (NEW)
- Auth CSRF: 3 (NEW)
- Auth DynamoDB Session: 6 (NEW)
- Auth Middleware: 5 (NEW)
- Auth Integration (E2E): 4 (NEW)
- Auth Conftest fixtures: 15 (NEW)
- Deploy E2E + others: 99
- Property-based: 2

### CDK Tests (29 total - all passing, requires `uv sync --group cdk`)
```bash
cd infrastructure/cdk && uv run pytest tests/ -v
```

### Integration Tests (20 total - skipped without AWS)
```bash
RUN_INTEGRATION_TESTS=1 uv run pytest tests/test_security_lake_integration.py -v
RUN_NEPTUNE_TESTS=1 uv run pytest tests/test_neptune_integration.py -v
```

### Type Checking
```bash
uv run ty check src/
# Also runs automatically in pre-commit via prek
```

## Web Application Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/auth/login` | GET | Redirect to Cognito hosted UI (NEW) |
| `/auth/callback` | GET | OAuth2 callback from Cognito (NEW) |
| `/auth/token` | GET | Return tokens from session (NEW) |
| `/auth/session` | POST | Store tokens (direct/passkey login) (NEW) |
| `/auth/refresh` | POST | Refresh tokens via Cognito (NEW) |
| `/auth/logout` | POST | Destroy session (NEW) |
| `/auth/me` | GET | Current user info (email, groups) (NEW) |
| `/auth/authorize` | POST | Cedar policy check (NEW) |
| `/` | GET | Dashboard overview (source/rule counts, region) |
| `/monitoring/` | GET | Health monitoring page |
| `/monitoring/check` | POST | Run health checks (HTMX fragment) |
| `/monitoring/catalog` | GET | Data catalog display |
| `/security-lake/` | GET | Security Lake connectivity page |
| `/security-lake/test` | POST | Test connections (HTMX fragment) |
| `/detections/` | GET/POST | Rule list / create rule |
| `/detections/new` | GET | Rule editor form |
| `/detections/{id}/test` | POST | Test rule against DuckDB/Athena |
| `/detections/query-explorer` | GET | Ad-hoc SQL query page |
| `/detections/query-explorer/run` | POST | Execute SQL query |
| `/detections/ai-generate` | POST | AI rule generation via Bedrock |
| `/investigations/` | GET/POST | List / start investigation |
| `/investigations/{id}` | GET | Investigation detail with graph |
| `/investigations/{id}/graph.html` | GET | Pyvis graph HTML (iframe) |
| `/investigations/{id}/enrich` | POST | Enrich by user/IP |
| `/investigations/{id}/ai-analyze` | POST | AI analysis via Bedrock |
| `/investigations/{id}/export` | POST | Export to JSON/S3 |
| `/deploy/` | GET | Lambda build dashboard |
| `/deploy/build` | POST | Build Lambda package |
| `/api/health` | GET | Liveness check (JSON) |
| `/api/sources` | GET | List data sources (JSON) |
| `/api/rules` | GET | List detection rules (JSON) |
| `/api/rules/{id}` | GET | Rule detail (JSON) |
| `/api/query` | POST | Execute SQL query (JSON) |
| `/api/operations/{id}` | GET | Poll operation status (JSON) |

## Detection Rules (18 total)

| File | Count | Data Source | OCSF Class |
|------|-------|-------------|------------|
| `sample_rules.yaml` | 6 | CloudTrail | 3002 (Auth) |
| `vpc_flow_rules.yaml` | 4 | VPC Flow | 4001 (Network) |
| `dns_rules.yaml` | 4 | Route53 | 4003 (DNS) |
| `security_hub_rules.yaml` | 4 | Security Hub | 2001 (Findings) |

## Infrastructure Status

| Component | Template | Status |
|-----------|----------|--------|
| CDK FastAPIStack | `cdk/stacks/fastapi_stack.py` | **Deployed** (`secdash-web`) |
| CDK SharedAuthStack | `cdk/stacks/shared_auth.py` | **Deployed** (`secdash-shared-auth`) |
| CDK AlertingStack | `cdk/stacks/alerting.py` | Ready (tested, not deployed) |
| CDK DetectionRulesStack | `cdk/stacks/detection_rules.py` | Ready (tested, not deployed) |
| CDK HealthDashboardStack | `cdk/stacks/health_dashboard.py` | Ready (tested, not deployed) |
| Neptune Serverless | `neptune.yaml` | CloudFormation template ready |

## Investigation Graph Module

### Node Types
| Type | Color | Description |
|------|-------|-------------|
| Principal | Red | Users, roles, AWS identities |
| IP Address | Teal | Source/destination IPs |
| Resource | Blue | AWS resources (S3, EC2, etc.) |
| API Operation | Green | AWS API calls |
| Security Finding | Bright Red | Triggered detections |
| Event | Gray | Individual security events |

### Timeline Event Tags
| Tag | Color | Description |
|-----|-------|-------------|
| unreviewed | Gray | Not yet analyzed |
| important | Gold | Significant but not malicious |
| suspicious | Red | Potentially malicious |
| benign | Teal | Confirmed legitimate |
| initial_access | Orange-red | ATT&CK: Initial Access |
| persistence | Purple | ATT&CK: Persistence |
| privilege_escalation | Dark Red | ATT&CK: Privilege Escalation |
| lateral_movement | Orange | ATT&CK: Lateral Movement |
| data_exfiltration | Crimson | ATT&CK: Data Exfiltration |

## Running the Project

```bash
# Install dependencies
uv sync

# Run unit tests
uv run pytest tests/

# Launch FastAPI web application (primary UI)
uv run secdash serve
# → http://localhost:8000

# Launch with custom settings
SECDASH_REGION=us-east-1 SECDASH_DUCKDB_PATH=./local.duckdb uv run secdash serve --port 9000

# Run demo investigation (no AWS required)
uv run python scripts/example_investigation.py --demo

# Build API docs
uv sync --group docs && uv run mkdocs serve
```

## Available Security Lake Tables

1. amazon_security_lake_table_us_west_2_cloud_trail_mgmt_2_0 (CloudTrail)
2. amazon_security_lake_table_us_west_2_eks_audit_2_0
3. amazon_security_lake_table_us_west_2_lambda_execution_2_0
4. amazon_security_lake_table_us_west_2_route53_2_0
5. amazon_security_lake_table_us_west_2_sh_findings_2_0 (Security Hub)
6. amazon_security_lake_table_us_west_2_vpc_flow_2_0

Note: OCSF 2.0 `time` field is epoch milliseconds (bigint), not a SQL timestamp.

## Git Commit History (Recent)

```
0cabfc9 Deploy Lambda with lazy imports for fast cold starts
0d5d3b1 Add Cognito passkey authentication and Cedar authorization (#13)
df9258d Update CURRENT_STATE.md with PR #12 cleanup
27a5c89 Merge pull request #12 from lexicone42/feature/remove-marimo-docker
2bef56e Remove Marimo notebooks, Docker, and App Runner artifacts
8a43b73 Update CURRENT_STATE.md with FastAPI migration (PRs #6-#11)
7c266e4 Merge pull request #11 from lexicone42/feature/cleanup-deps
8c25db0 Merge pull request #10 from lexicone42/feature/reports-cdk
4d01a81 Merge pull request #9 from lexicone42/feature/complex-routers
2727cbf Deprecate marimo notebook command, update deps and keywords
1787b6f Add HTML report generator and CDK FastAPI stack
91b4463 Add complex routers (detections, investigations, deploy) and JSON API
828d38a Add base templates, static assets, and simple routers
e13a864 Add FastAPI core, CLI serve command, and Lambda handler
30fb1ed Add DuckDB connector for local/Lambda SQL engine
```

## Completed Improvements

All 14 originally tracked improvements are done:

1. ~~Fix remaining `datetime.utcnow()` deprecation warnings~~ Done
2. ~~Add more detection rules for VPC Flow, Route53, Security Hub data~~ Done (18 rules across 4 sources)
3. ~~Test Lambda deployment workflow end-to-end~~ Done (test_deploy_e2e.py)
4. ~~Add alert notification integrations (SNS, Slack, etc.)~~ Done (notifications module)
5. ~~Add `py.typed` marker for PEP 561 type checking support~~ Done
6. ~~Consider adding mkdocs or sphinx for API documentation~~ Done (mkdocs-material + mkdocstrings)
7. ~~Add timeline export to LaTeX reports~~ Done
8. ~~Implement Neptune persistence for timelines~~ Done
9. ~~Wire notification module into Lambda handler templates~~ Done (NotificationManager)
10. ~~Wire notification module into CDK alerting stack~~ Done (alerting_handler.py + DetectionRulesStack)
11. ~~Add property-based tests for SQL sanitization and alert serialization~~ Done
12. ~~Fix case-sensitive SQL keyword detection in `rule_store.py`~~ Verified (already case-insensitive)
13. ~~Add URL validation to `SlackNotifier` and `URLAnalyzer` constructors~~ Done (HTTPS enforcement)
14. ~~Add bounds validation to `LambdaBuilder.deploy_lambda()` parameters~~ Done
15. ~~Migrate from Marimo notebooks to FastAPI + HTMX~~ Done (PRs #6–#11)
16. ~~Remove Marimo notebooks, Docker, App Runner artifacts~~ Done (PR #12)
17. ~~Integrate Cognito passkey auth + Cedar authorization~~ Done (PR #13)

## Potential Next Steps

- Create `scripts/build_lambda.sh` to automate Lambda packaging (`uv pip install --target` + source copy)
- Enable passkey auth once custom domain is configured (WebAuthn RP ID needs custom domain, not `.amazoncognito.com`)
- Add per-route Cedar enforcement (currently global allow/deny + `/auth/authorize` endpoint)
- Deploy alerting and detection rules stacks (`secdash-alerting`, `secdash-detections`)
- Store session secret in SSM Parameter Store or Secrets Manager (currently set via env var)
- Add GitHub Actions CI back when ruff version alignment is sorted out
- Real-world detection rule tuning against live Security Lake data
- Add WebSocket support for real-time detection alerts
