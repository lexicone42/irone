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
│   └── cli.py             # Command-line interface
├── notebooks/
│   ├── main.py            # Main Marimo notebook (navigation hub)
│   └── investigation.py   # Investigation notebook with graph + timeline
├── scripts/
│   └── example_investigation.py  # Demo investigation workflow
├── detections/
│   └── sample_rules.yaml  # 6 sample detection rules
├── infrastructure/
│   ├── neptune.yaml           # Neptune Serverless CloudFormation stack
│   ├── marimo-apprunner.yaml  # App Runner VPC deployment
│   └── cdk/                   # AWS CDK stacks (alerting, detections, monitoring)
├── tests/                 # 414 tests total
│   ├── test_catalog.py    # Catalog tests (8)
│   ├── test_detections.py # Detection tests (9)
│   ├── test_adversary.py  # Adversary tests (37)
│   ├── test_graph.py      # Graph tests (50)
│   ├── test_ai.py         # AI/Bedrock tests (26)
│   ├── test_reports.py    # Report generation tests (58)
│   ├── test_rule_store.py # S3RuleStore tests (32)
│   ├── test_sql_utils.py  # SQL injection protection tests (32)
│   ├── test_timeline.py   # Timeline tests (24)
│   ├── test_notifications.py # Notification tests (28)
│   ├── test_deploy_e2e.py # Deployment E2E tests
│   └── test_security_lake_integration.py  # Integration tests (10)
├── output/investigations/ # Demo output directory
├── Dockerfile.marimo      # Container for AWS App Runner deployment
├── catalog.example.yaml   # Example catalog configuration
├── pyproject.toml         # Project configuration (uv, ruff, ty)
└── README.md              # Documentation
```

## Recent Changes (2026-02-10)

### CDK Consolidation & Notifications Wiring

- **Removed SAM templates**: Deleted `template.yaml`, `health-dashboard.yaml`, `deploy-dashboard.sh`
- **New DetectionRulesStack** (`infrastructure/cdk/stacks/detection_rules.py`): CDK stack for deploying detection Lambdas with shared notifications layer, EventBridge schedules, and cross-stack SNS topic import
- **Updated AlertingStack**: Extracted inline Lambda code into `alerting_handler.py`, switched from `Code.from_inline()` to `Code.from_asset()`, removed separate Slack Lambda in favor of NotificationManager multi-channel routing
- **Lambda handler templates**: Now use `NotificationManager` (SNS + Slack) instead of inline `sns.publish()` calls
- **Notifications Lambda Layer**: `LambdaBuilder.build_notifications_layer()` packages the notifications module with httpx/pydantic deps
- **CLI updates**: Removed `--sam` flag from `deploy`, removed `--api` flag from `adversary deploy-lambda`

## Previous Changes (2026-01-17)

### Application Log Onboarding

**CloudWatch Logs Connector** (`cloudwatch_logs.py`):
- Query Lambda, EKS, ALB, API Gateway, and Cloudflare logs via Logs Insights
- Async query handling with exponential backoff
- Log group discovery with pattern matching
- Pre-built query methods: `query_lambda_errors()`, `query_eks_pod_errors()`, `query_alb_access_logs()`, `query_cloudflare_waf_events()`

**Log ETL Pipeline** (`log_etl.py`):
- OCSF transformers for Lambda, ALB, EKS, and Cloudflare logs
- Cost-effective CloudWatch Export Task API (avoids Firehose costs)
- Parquet/JSON Lines export for Security Lake ingestion
- Hot/cold tier architecture: CloudWatch (0-7 days) → Security Lake (7+ days)

**Security Lake Enhancements**:
- `query_vpc_flow()` - VPC Flow log queries with IP/port/action filters
- `query_dns_logs()` - Route53 resolver log queries
- `query_suspicious_dns()` - DGA and suspicious TLD detection
- `query_lambda_execution()` - Lambda execution logs from Security Lake
- `get_data_source_health_summary()` - Unified health check across event classes

**Dual-Target Detection Rules** (`DualTargetDetectionRule`):
- Single rule definition works on both CloudWatch and Athena/Security Lake
- Automatic query format adaptation per target
- Run against hot tier (real-time) or cold tier (historical) or both

**Application Detection Rules** (`application_rules.yaml`):
- 20+ rules for Lambda, EKS, ALB, Cloudflare, API Gateway
- MITRE ATT&CK mapping for each rule
- Severity-based threshold evaluation

**Dual-Target Lambda Builder**:
- Generate Lambda handlers that query both CloudWatch and Athena
- CDK-based deployment via DetectionRulesStack
- Shared notifications Lambda Layer (SNS + Slack via NotificationManager)
- Scheduled execution via EventBridge

### Previous Changes (2026-01-14)

### Timeline Visualization Feature
- **New module**: `src/secdashboards/graph/timeline.py`
- Interactive Plotly timeline for investigation events
- Event tagging with 11 classification options (including MITRE ATT&CK phases)
- AI summary generation via Bedrock with editable analyst field
- Auto-tagging of high-severity security findings
- Integrated into investigation notebook and example script

### Report Generation
- LaTeX/PDF report generation with professional formatting
- Table overflow protection with intelligent column sizing and truncation
- Templates for investigation reports and detection reports
- S3 export with presigned URLs
- pdflatex integration for local PDF compilation

### Security Infrastructure
- S3RuleStore for secure YAML-only detection rule storage
- SQL injection protection with parameterized queries
- OIDCAuthenticator for ALB/Cognito authentication
- Comprehensive input validation and sanitization

## Configuration

- **Package Manager**: uv
- **Linter**: ruff
- **Type Checker**: ty (Astral)
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

### Unit Tests (437 total - all passing)
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
- Deploy E2E + others: 99

### Integration Tests (10 total - all passing)
```bash
RUN_INTEGRATION_TESTS=1 uv run pytest tests/test_security_lake_integration.py -v
```

### Type Checking
```bash
uv run ty check src/
# All checks passed!
```

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
uv run pytest

# Run integration tests (requires AWS credentials)
RUN_INTEGRATION_TESTS=1 uv run pytest tests/test_security_lake_integration.py -v

# Launch main Marimo notebook
uv run marimo edit notebooks/main.py

# Launch investigation notebook
uv run marimo edit notebooks/investigation.py

# Run demo investigation (no AWS required)
uv run python scripts/example_investigation.py --demo

# Via CLI
uv run secdash notebook
```

## Demo Investigation Output

Running `--demo` generates:
```
output/investigations/
├── investigation_graph.html      # Interactive pyvis graph
├── investigation_timeline.html   # Interactive Plotly timeline
├── investigation_report.tex      # LaTeX source
├── investigation_report.pdf      # PDF report (if pdflatex installed)
└── investigation_data.json       # Full data export with timeline
```

## AWS Configuration

- **Account**: 651804262336
- **User**: bryan
- **Region**: us-west-2
- **Security Lake Database**: amazon_security_lake_glue_db_us_west_2
- **CloudTrail Table**: amazon_security_lake_table_us_west_2_cloud_trail_mgmt_2_0
- **Athena Output Bucket**: s3://aws-athena-query-results-651804262336-us-west-2/

## Available Security Lake Tables

1. amazon_security_lake_table_us_west_2_cloud_trail_mgmt_2_0 (CloudTrail)
2. amazon_security_lake_table_us_west_2_eks_audit_2_0
3. amazon_security_lake_table_us_west_2_lambda_2_0
4. amazon_security_lake_table_us_west_2_route53_2_0
5. amazon_security_lake_table_us_west_2_sh_findings_2_0 (Security Hub)
6. amazon_security_lake_table_us_west_2_vpc_flow_2_0

## Adversary Emulation Module

### Available Attack Scenarios

| Scenario ID | MITRE Techniques | Expected Detections |
|-------------|------------------|---------------------|
| root-account-compromise | T1078.004 | detect-root-login |
| iam-privilege-escalation | T1098, T1098.001 | detect-iam-policy-changes, detect-access-key-creation |
| credential-brute-force | T1110 | detect-failed-logins |
| security-group-evasion | T1562.007 | detect-security-group-changes |
| api-reconnaissance | T1106, T1595 | detect-unusual-api-calls |
| network-discovery | T1046 | VPC Flow detections |
| dns-c2-exfil | T1071.004, T1048.003 | Route53 detections |
| full-attack-chain | Multiple | All detections |

### CLI Commands

```bash
# List available attack scenarios
secdash adversary list-scenarios

# Run a scenario and generate events
secdash adversary run-scenario root-account-compromise -o events.json

# Test detection rules against scenarios
secdash adversary test-detections --rules ./detections

# Run network tests locally
secdash adversary network-test --target 10.0.0.50 --type scan

# Build Lambda deployment package
secdash adversary deploy-lambda --output ./build

# Invoke deployed Lambda
secdash adversary invoke-lambda --scenario port_scan_sim
```

## AI/Bedrock Module

### Capabilities
- Detection rule generation from natural language
- Alert triage and analysis
- Investigation graph analysis
- Natural language to SQL conversion
- Incident report generation
- Timeline summary generation
- Cost tracking per session

### Supported Models
- Claude 3.5 Sonnet (default)
- Claude 3.5 Haiku (fast/cheap)
- Claude 3 Opus (deep analysis)
- Claude Sonnet 4
- Claude Opus 4

## Notebooks

| Notebook | Purpose | Roles |
|----------|---------|-------|
| `main.py` | Navigation hub | All |
| `investigation.py` | Graph + timeline visualization, AI analysis | SOC/IR |
| `detection_engineering.py` | Create/test rules + AI generation | Detection Engineers |
| `monitoring.py` | Health checks, data freshness | SOC |
| `deployment.py` | Infrastructure deployment | Admin only |

## Git Commit History (Recent)

```
4bcbd64 Add notification integrations module (SNS, Slack) with multi-channel routing
be0d9b0 Add deployment E2E tests and fix StrEnum serialization in SAM templates
82a0dcb Add timeline features, Neptune persistence, and upgrade to Claude Opus 4.6
2a02feb Switch from pre-commit to prek for faster hook execution
061f338 Add CloudWatch Logs connector, dual-target detections, and health dashboard
8a8a92e Add investigation timeline with event tagging and AI summaries
```

## Pending Improvements

1. ~~Fix remaining `datetime.utcnow()` deprecation warnings~~ Done (already fixed)
2. ~~Add more detection rules for VPC Flow, Route53, Security Hub data~~ Done
3. ~~Test Lambda deployment workflow end-to-end~~ Done (test_deploy_e2e.py)
4. ~~Add alert notification integrations (SNS, Slack, etc.)~~ Done (notifications module)
5. ~~Add `py.typed` marker for PEP 561 type checking support~~ Done
6. ~~Consider adding mkdocs or sphinx for API documentation~~ Done (mkdocs-material + mkdocstrings)
7. ~~Add timeline export to LaTeX reports~~ Done (wired timeline into report generation)
8. ~~Implement Neptune persistence for timelines~~ Done (already implemented, wired into notebook)
9. ~~Wire notification module into Lambda handler templates (replace inline SNS publishing)~~ Done (uses NotificationManager)
10. ~~Wire notification module into CDK alerting stack (replace inline Slack webhook code)~~ Done (alerting_handler.py + DetectionRulesStack)
11. ~~Add property-based tests for SQL sanitization and alert serialization~~ Done (test_property_based.py)
12. ~~Fix case-sensitive SQL keyword detection in `rule_store.py`~~ Verified as false positive (already case-insensitive)
13. ~~Add URL validation to `SlackNotifier` and `URLAnalyzer` constructors~~ Done (HTTPS enforcement)
14. ~~Add bounds validation to `LambdaBuilder.deploy_lambda()` parameters~~ Done (memory 128-10240, timeout 1-900)
