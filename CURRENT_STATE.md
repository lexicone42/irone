# Security Dashboards - Current State

**Last Updated**: 2026-02-11

## Project Overview

A security operations platform for connecting to AWS Security Lake, creating detection rules, deploying them to Lambda for automated security monitoring, and testing detections with adversary emulation. Includes investigation graph visualization with Neptune, AI-assisted analysis via Bedrock, and professional report generation.

**Primary UI**: FastAPI + HTMX web application. Server-rendered HTML with HTMX for dynamic updates, DuckDB for local/Lambda SQL, deployable to Lambda via Mangum.

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
│   │   ├── app.py         # create_app() factory, router registration
│   │   ├── config.py      # WebConfig(BaseSettings) with SECDASH_ env prefix
│   │   ├── state.py       # AppState dataclass, create_app_state() factory
│   │   ├── lambda_handler.py  # Mangum ASGI→Lambda adapter
│   │   ├── report_generator.py  # HTML report rendering (Report models → HTML)
│   │   ├── routers/
│   │   │   ├── dashboard.py      # GET / — overview with source/rule counts
│   │   │   ├── monitoring.py     # /monitoring/ — health checks
│   │   │   ├── security_lake.py  # /security-lake/ — connectivity testing
│   │   │   ├── detections.py     # /detections/ — rule CRUD, testing, AI generation
│   │   │   ├── investigations.py # /investigations/ — graph investigations
│   │   │   ├── deploy.py         # /deploy/ — Lambda build dashboard
│   │   │   └── api.py            # /api/ — JSON API for programmatic access
│   │   ├── templates/
│   │   │   ├── base.html         # Base layout with nav, HTMX, terminal CSS
│   │   │   ├── components/       # Reusable HTMX fragments
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
│       │   └── fastapi_stack.py     # FastAPIStack (Lambda + API Gateway v2) (NEW)
│       └── tests/
│           ├── test_health_dashboard_stack.py  # 12 tests
│           ├── test_alerting_stack.py          # 7 tests
│           └── test_detection_rules_stack.py   # 10 tests
├── docs/                    # mkdocs-material API documentation
├── tests/                   # 609 tests total (+ 29 CDK tests separate)
├── catalog.example.yaml     # Example catalog configuration
├── mkdocs.yml               # Documentation site config
├── pyproject.toml           # Project configuration (uv, ruff, ty)
└── README.md                # Documentation
```

## Recent Changes (2026-02-11)

### FastAPI Migration (PRs #6–#11)

Replaced Marimo notebook UI with FastAPI + HTMX web application. 6 PRs, all merged to `main`.

**PR #6 — DuckDB Connector** (`feature/duckdb-connector`)
- New `DuckDBConnector` implementing `DataConnector` ABC
- Supports `:memory:` mode for testing, file-backed for persistence, S3 Parquet import
- `DUCKDB` added to `DataSourceType` enum, auto-registered in catalog
- 21 new tests including Hypothesis property-based SQL safety tests

**PR #7 — FastAPI Core + CLI serve** (`feature/fastapi-core`)
- `WebConfig(BaseSettings)` with `SECDASH_` env prefix for 12-factor config
- `AppState` dataclass holding catalog, runner, DuckDB connector, investigations
- `create_app()` factory with Jinja2Templates, static file mounting, shutdown cleanup
- `secdash serve` CLI command via uvicorn
- `lambda_handler.py` — 5-line Mangum adapter for serverless deployment
- 10 new tests

**PR #8 — Base Templates + Simple Routers** (`feature/base-templates`)
- Dark terminal-aesthetic CSS (monospace, green/cyan accents)
- Base layout with nav sidebar, HTMX from CDN, `hx-boost="true"` SPA navigation
- Reusable components: `nav.html`, `data_table.html`, `loading.html`, `alert.html`
- Routers: dashboard (`/`), monitoring (`/monitoring/`), security-lake (`/security-lake/`)
- 14 new tests

**PR #9 — Complex Routers** (`feature/complex-routers`)
- Detections router: rule CRUD, DuckDB testing, query explorer, AI rule generation
- Investigations router: graph building, enrichment, AI analysis, pyvis visualization
- Deploy router: Lambda build dashboard with operation tracking
- JSON API router: `/api/sources`, `/api/rules`, `/api/query`, `/api/operations`
- HTMX patterns: inline test results, loading spinners, polling for long-running ops
- 50 new tests (detections: 13, investigations: 15, API: 13, deploy: 9)

**PR #10 — Reports + CDK** (`feature/reports-cdk`)
- `HTMLReportGenerator`: renders `Report` Pydantic models to self-contained HTML
- Health report template with healthy/unhealthy/total summary stats
- `FastAPIStack` CDK: Lambda (Python 3.13, 512MB) + HTTP API Gateway v2 + S3 report bucket
- 16 new tests

**PR #11 — Cleanup** (`feature/cleanup-deps`)
- `secdash notebook` command marked deprecated with warning → use `secdash serve`
- Moved `marimo` from core dependencies to optional `[dependency-groups.notebook]`
- Updated keywords: removed "marimo", added "fastapi", "htmx", "duckdb"
- Added `visualization.py` to ty excludes (optional marimo dep)

**Test count**: 498 → 609 (+111 new tests)

### Type Hints & Any Audit
- Tightened ty rules: `possibly-missing-attribute` from "warn" to "error", added `division-by-zero = "warn"`
- Replaced 8 `Any` annotations with concrete types (GraphNode, GraphEdge, NeptuneConnector, etc.)
- Added missing return type annotations to `TimelineVisualizer.__init__` and `alerting_handler.handler`
- Fixed `import importlib.util` in runner.py for ty compliance

### Notebook Fixes (API Drift)
- **detection_engineering.py**: Fixed `DetectionRunner` API (catalog kwarg + register_rule), `matched_events` → `matches`, dict iteration instead of DataFrame
- **investigation.py**: Fixed `graph` variable scope (added `graph = None` initialization)
- **monitoring.py**: Removed unused datetime import
- Added `F821` to notebook ruff per-file-ignores for Marimo cross-cell type annotations

### New Security Lake Health Notebook
- **security_lake_health.py**: Quick connectivity check for 6 Security Lake tables
- Auto-discovers Athena output bucket via STS account ID
- Handles OCSF 2.0 bigint epoch time format (`to_unixtime`/`from_unixtime`)
- Shows record counts, latest event time, data age, and health status

### Detection Lifecycle Tests
- 14 new tests in `test_detections.py` covering register/get/list/delete/overwrite/run/export
- Full create-delete-roundtrip lifecycle test

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
- fastapi>=0.115.0 - Web framework (NEW)
- uvicorn[standard]>=0.32.0 - Local dev server (NEW)
- mangum>=0.19.0 - ASGI→Lambda adapter (NEW)
- duckdb>=1.1.0 - Local/Lambda SQL engine (NEW)
- python-multipart>=0.0.22 - Form data parsing for FastAPI (NEW)
- boto3>=1.35.0 - AWS SDK
- polars>=1.0.0 - Data processing
- pydantic>=2.10.0 - Data validation
- pyvis>=0.3.2 - Graph visualization
- plotly>=5.24.0 - Timeline visualization
- gremlinpython>=3.7.0 - Neptune client
- networkx>=3.2 - Graph analysis
- jinja2>=3.1.0 - Template rendering

## Test Status

### Unit Tests (609 total - all passing)
```bash
uv run pytest tests/ -v
```

Test breakdown:
- Catalog: 8
- DuckDB Connector: 21 (NEW)
- Detection: 23
- Adversary: 36
- Graph: 50
- AI/Bedrock: 26
- Reports: 58
- Report Generator (HTML): 16 (NEW)
- Rule Store: 32
- SQL Utils: 32
- Timeline: 24
- Notifications: 28
- Deployment: 33
- Alerting Handler: 8
- Neptune Connector: 39
- Web App: 10 (NEW)
- Web Routers (simple): 14 (NEW)
- Web Routers (detections): 13 (NEW)
- Web Routers (investigations): 15 (NEW)
- Web Routers (API): 13 (NEW)
- Web Routers (deploy): 9 (NEW)
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
| CDK FastAPIStack | `cdk/stacks/fastapi_stack.py` | Ready (tested) — **NEW** |
| CDK AlertingStack | `cdk/stacks/alerting.py` | Ready (tested) |
| CDK DetectionRulesStack | `cdk/stacks/detection_rules.py` | Ready (tested) |
| CDK HealthDashboardStack | `cdk/stacks/health_dashboard.py` | Ready (tested) |
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
7c266e4 Merge pull request #11 from lexicone42/feature/cleanup-deps
8c25db0 Merge pull request #10 from lexicone42/feature/reports-cdk
4d01a81 Merge pull request #9 from lexicone42/feature/complex-routers
2727cbf Deprecate marimo notebook command, update deps and keywords
1787b6f Add HTML report generator and CDK FastAPI stack
91b4463 Add complex routers (detections, investigations, deploy) and JSON API
828d38a Add base templates, static assets, and simple routers
e13a864 Add FastAPI core, CLI serve command, and Lambda handler
30fb1ed Add DuckDB connector for local/Lambda SQL engine
0eb02be Update CURRENT_STATE.md with 2026-02-11 changes
56207ba Fix Security Lake health notebook: add Athena output location and OCSF time format
ccbedd6 Fix notebook API drift, add Security Lake health notebook and detection lifecycle tests
bd9a4f8 Add type hints, tighten ty rules, and replace Any with concrete types
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

## Potential Next Steps

- Deploy FastAPI stack to AWS (CDK `cdk deploy secdash-web`)
- Add Cognito JWT authorizer to FastAPIStack (pool exists in HealthDashboardStack)
- Add GitHub Actions CI back when ruff version alignment is sorted out
- Real-world detection rule tuning against live Security Lake data
- Add WebSocket support for real-time detection alerts
