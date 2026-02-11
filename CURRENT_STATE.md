# Security Dashboards - Current State

**Last Updated**: 2026-02-10

## Project Overview

A local Marimo notebook-based tool for connecting to AWS Security Lake, creating detection rules, deploying them to Lambda for automated security monitoring, and testing detections with adversary emulation. Includes investigation graph visualization with Neptune, AI-assisted analysis via Bedrock, and professional PDF report generation.

**NEW**: Now supports hybrid hot/cold tier architecture with CloudWatch Logs Insights for real-time queries (0-7 days) and Security Lake for long-term storage (7+ days), with unified dual-target detection rules that work across both tiers.

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
│   ├── reports/           # Report generation
│   │   ├── latex_renderer.py  # LaTeX/PDF report generation
│   │   ├── exporters.py   # S3 export and PDF compilation
│   │   ├── converters.py  # Graph to report data conversion
│   │   └── templates/     # Jinja2 LaTeX templates
│   ├── health/            # Health monitoring
│   │   ├── monitor.py     # HealthMonitor for checking data sources
│   │   ├── alerting_handler.py # Lambda handler for alerting stack (with DetectionRunner)
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
│   └── cli.py             # Command-line interface
├── notebooks/
│   ├── main.py            # Main Marimo notebook (navigation hub)
│   ├── investigation.py   # Investigation notebook with graph + timeline
│   └── deployment.py      # CDK deployment management notebook
├── scripts/
│   └── example_investigation.py  # Demo investigation workflow
├── detections/
│   ├── sample_rules.yaml         # 6 CloudTrail detection rules
│   ├── vpc_flow_rules.yaml       # 4 VPC Flow detection rules
│   ├── dns_rules.yaml            # 4 Route53 DNS detection rules
│   └── security_hub_rules.yaml   # 4 Security Hub detection rules
├── infrastructure/
│   ├── neptune.yaml           # Neptune Serverless CloudFormation stack
│   ├── marimo-apprunner.yaml  # App Runner VPC deployment
│   └── cdk/                   # AWS CDK stacks (alerting, detections, health dashboard)
│       ├── stacks/
│       │   ├── alerting.py          # AlertingStack (SNS, Lambda, EventBridge)
│       │   ├── detection_rules.py   # DetectionRulesStack (Lambda per rule, shared Layer)
│       │   └── health_dashboard.py  # HealthDashboardStack (API Gateway, Cognito)
│       └── tests/
│           ├── test_health_dashboard_stack.py  # 12 tests
│           ├── test_alerting_stack.py          # 7 tests
│           └── test_detection_rules_stack.py   # 10 tests
├── docs/                    # mkdocs-material API documentation
├── tests/                   # 484 tests total (+ 29 CDK tests separate)
├── Dockerfile.marimo        # Container for AWS App Runner deployment
├── catalog.example.yaml     # Example catalog configuration
├── mkdocs.yml               # Documentation site config
├── pyproject.toml           # Project configuration (uv, ruff, ty)
└── README.md                # Documentation
```

## Recent Changes (2026-02-10)

### PR #5: Detection Runner Wiring, CDK Tests, Detection Rules, Neptune Tests
- **DetectionRunner in alerting Lambda**: Wired `DetectionRunner` + `S3RuleStore` into `alerting_handler.py`, completing the last TODO
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
- **Type Checker**: ty (Astral) — manual only, not in pre-commit or CI
- **Pre-commit**: prek (Rust-based)
- **Default Region**: us-west-2
- **Python Version**: 3.13

## Dependencies

Key dependencies in pyproject.toml:
- marimo>=0.10.0 - Interactive notebooks
- boto3>=1.35.0 - AWS SDK
- polars>=1.0.0 - Data processing
- pydantic>=2.10.0 - Data validation
- pyvis>=0.3.2 - Graph visualization
- plotly>=5.24.0 - Timeline visualization
- gremlinpython>=3.7.0 - Neptune client
- networkx>=3.2 - Graph analysis
- jinja2>=3.1.0 - Template rendering

## Test Status

### Unit Tests (484 total - all passing)
```bash
uv run pytest tests/ -v --ignore=tests/test_notebook_main.py
```

Test breakdown:
- Catalog: 8
- Detection: 9
- Adversary: 36
- Graph: 50
- AI/Bedrock: 26
- Reports: 58
- Rule Store: 32
- SQL Utils: 32
- Timeline: 24
- Notifications: 28
- Deployment: 33
- Alerting Handler: 8
- Neptune Connector: 39
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
# Available but not automated — not in pre-commit or CI
```

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
| CDK AlertingStack | `cdk/stacks/alerting.py` | Ready (tested) |
| CDK DetectionRulesStack | `cdk/stacks/detection_rules.py` | Ready (tested) |
| CDK HealthDashboardStack | `cdk/stacks/health_dashboard.py` | Ready (tested) |
| Neptune Serverless | `neptune.yaml` | CloudFormation template ready |
| App Runner + VPC | `marimo-apprunner.yaml` | CloudFormation template ready, placeholder values |
| Dockerfile | `Dockerfile.marimo` | Ready, not pushed to ECR |

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
uv run pytest tests/ --ignore=tests/test_notebook_main.py

# Launch main Marimo notebook
uv run marimo edit notebooks/main.py

# Launch investigation notebook
uv run marimo edit notebooks/investigation.py

# Run demo investigation (no AWS required)
uv run python scripts/example_investigation.py --demo

# Build API docs
uv sync --group docs && uv run mkdocs serve

# Via CLI
uv run secdash notebook
```

## Available Security Lake Tables

1. amazon_security_lake_table_us_west_2_cloud_trail_mgmt_2_0 (CloudTrail)
2. amazon_security_lake_table_us_west_2_eks_audit_2_0
3. amazon_security_lake_table_us_west_2_lambda_2_0
4. amazon_security_lake_table_us_west_2_route53_2_0
5. amazon_security_lake_table_us_west_2_sh_findings_2_0 (Security Hub)
6. amazon_security_lake_table_us_west_2_vpc_flow_2_0

## Git Commit History (Recent)

```
69f688b Merge pull request #5 from lexicone42/enhance-detection-ci-neptune
f86810f Merge pull request #4 from lexicone42/add-mkdocs-timeline-wiring
283eb4b Merge pull request #3 from lexicone42/consolidate-cdk-notifications
2682802 Add input validation for security-sensitive parameters (#2)
9f49558 Add documentation updates, SECURITY.md, and property-based tests (#1)
4bcbd64 Add notification integrations module (SNS, Slack) with multi-channel routing
be0d9b0 Add deployment E2E tests and fix StrEnum serialization in SAM templates
82a0dcb Add timeline features, Neptune persistence, and upgrade to Claude Opus 4.6
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

## Potential Next Steps

- Deploy infrastructure to AWS (CDK stacks, Neptune, App Runner)
- Build and push Docker image to ECR for App Runner
- Set up real VPC/subnets for App Runner and Neptune templates
- Add GitHub Actions CI back when ruff version alignment is sorted out
- Add ty type checking to pre-commit or CI
- Real-world detection rule tuning against live Security Lake data
