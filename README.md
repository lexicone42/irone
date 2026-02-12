# Security Data Lake Analytics (secdashboards)

[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-6B48FF?style=flat&logo=claude)](https://claude.com/claude-code)

A FastAPI + HTMX security analytics platform for AWS Security Lake. Create detection rules, visualize security investigation graphs, and deploy automated monitoring to AWS.

## Features

- **AWS Security Lake Integration**: Native support for OCSF-formatted Security Lake data
- **CloudWatch Logs Integration**: Query Lambda, EKS, ALB, and API Gateway logs via Logs Insights
- **Hybrid Hot/Cold Architecture**: Dual-target detection rules across CloudWatch (0-7 days) and Security Lake (7+ days)
- **Detection Rules Framework**: Create, test, and manage SQL-based security detection rules
- **Alert Notifications**: Route alerts to SNS topics and Slack webhooks with severity filtering
- **Investigation Graph Visualization**: Interactive graph visualization for security investigations using pyvis
- **Investigation Timeline**: Plotly-based interactive timelines with event tagging and AI summaries
- **Neptune Graph Database**: Persist and query security graphs with AWS Neptune Serverless
- **Adversary Emulation**: Test detections with MITRE ATT&CK-aligned attack scenarios
- **Lambda Deployment**: Deploy detection rules to Lambda with CloudWatch schedules
- **FastAPI + HTMX Web Interface**: Server-rendered dashboard with DuckDB for local SQL
- **Health Monitoring**: Check data freshness and source connectivity

## Quick Start

### Prerequisites

- **Python 3.13+**
- **[uv](https://docs.astral.sh/uv/)** package manager
- **AWS credentials** configured via `aws configure` or environment variables
- **pdflatex** (optional, for PDF report generation)

### Installation

```bash
# Clone and install with uv
cd secdashboards
uv sync

# Install dev dependencies
uv sync --group dev
```

### Launch the Web Dashboard

```bash
# Start the FastAPI web server
uv run secdash serve
```

Open http://localhost:8000 in your browser.

### Configure AWS Credentials

The tool uses your local AWS credentials. Ensure you have credentials configured:

```bash
# Using AWS CLI
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-west-2
```

Required IAM permissions:
- `athena:StartQueryExecution`, `athena:GetQueryExecution`, `athena:GetQueryResults`
- `s3:GetObject`, `s3:PutObject` on Athena results bucket
- `s3:GetObject` on Security Lake buckets
- `glue:GetTable`, `glue:GetDatabase`

## Usage

### Data Catalog

Create a `catalog.yaml` from the example:

```bash
cp catalog.example.yaml catalog.yaml
```

Or initialize via CLI:

```bash
uv run secdash init-catalog --region us-west-2 --output catalog.yaml
```

### Health Checks

Check connectivity and data freshness:

```bash
uv run secdash health --catalog catalog.yaml
```

### Detection Rules

Detection rules can be defined in YAML or Python:

**YAML Rules** (`detections/sample_rules.yaml`):
```yaml
- id: detect-root-login
  name: Root Account Login Detected
  severity: high
  threshold: 1
  query: |
    SELECT time, actor.user.name, src_endpoint.ip
    FROM "{database}"."{table}"
    WHERE time >= TIMESTAMP '{start_time}'
      AND time < TIMESTAMP '{end_time}'
      AND actor.user.type = 'Root'
```

**Run Detections**:
```bash
uv run secdash run-detections \
  --catalog catalog.yaml \
  --rules detections/ \
  --source cloudtrail \
  --lookback 60
```

### Deploy to Lambda

Build detection Lambda packages and notifications layer:

```bash
uv run secdash deploy \
  --rules detections/ \
  --output deploy_output/ \
  --source cloudtrail
```

Deploy via CDK:

```bash
cd infrastructure/cdk
npx cdk deploy secdash-alerting secdash-detections \
  --parameters AlertEmail=security@example.com \
  --parameters SlackWebhookUrl=https://hooks.slack.com/services/T.../B.../xxx
```

## Project Structure

```
secdashboards/
├── src/secdashboards/
│   ├── catalog/          # Data catalog and source management
│   ├── connectors/       # Data source connectors (Athena, Security Lake, DuckDB)
│   ├── detections/       # Detection rules framework (SQL, dual-target)
│   ├── graph/            # Investigation graph module
│   │   ├── models.py     # Node/edge entity models
│   │   ├── builder.py    # Graph construction from detections
│   │   ├── connector.py  # Neptune database connector
│   │   ├── enrichment.py # Security Lake enrichment queries
│   │   ├── visualization.py  # pyvis graph visualization
│   │   ├── timeline.py   # Plotly timeline visualization
│   │   └── queries.py    # Gremlin/openCypher templates
│   ├── web/              # FastAPI + HTMX web application
│   │   ├── app.py        # create_app() factory
│   │   ├── config.py     # WebConfig with SECDASH_ env prefix
│   │   ├── state.py      # AppState dataclass
│   │   ├── routers/      # Route handlers (dashboard, detections, etc.)
│   │   ├── templates/    # Jinja2 HTML templates
│   │   └── static/       # CSS and JS assets
│   ├── notifications/    # Alert delivery (SNS, Slack)
│   ├── ai/               # AI assistance (Bedrock)
│   ├── health/           # Health monitoring and URL analysis
│   ├── adversary/        # Adversary emulation and testing
│   ├── deploy/           # Lambda deployment utilities
│   └── cli.py            # Command-line interface
├── detections/
│   └── sample_rules.yaml # Example detection rules
├── infrastructure/
│   ├── neptune.yaml      # Neptune Serverless stack
│   └── cdk/              # AWS CDK stacks (alerting, detections, web, monitoring)
├── tests/                # Unit and integration tests
├── catalog.example.yaml  # Example catalog configuration
└── pyproject.toml        # Project configuration
```

## Security Lake OCSF Classes

The Security Lake connector supports querying by OCSF event class:

| Class | ID | Description |
|-------|-----|-------------|
| Authentication | 3002 | Login/logout events |
| API Activity | 6003 | CloudTrail API calls |
| Network Activity | 4001 | VPC Flow, network events |
| Security Finding | 2001 | Security Hub findings |

Example query by event class:

```python
from secdashboards.connectors.security_lake import SecurityLakeConnector, OCSFEventClass

connector = catalog.get_connector("cloudtrail")
df = connector.query_by_event_class(OCSFEventClass.AUTHENTICATION, limit=100)
```

## Investigation Graph

Build interactive security investigation graphs from detection results:

```python
from secdashboards.graph import GraphBuilder, GraphVisualizer, NeptuneConnector

# Build graph from a triggered detection
builder = GraphBuilder(security_lake_connector)
graph = builder.build_from_detection(
    detection_result,
    enrichment_window_minutes=60,
    max_related_events=500,
)

# Visualize as interactive HTML
visualizer = GraphVisualizer(height="700px")
html = visualizer.to_html(graph)

# Optionally persist to Neptune
neptune = NeptuneConnector(
    endpoint="my-cluster.xxx.neptune.amazonaws.com",
    use_iam_auth=True,
)
neptune.save_graph(graph)
```

### Graph Node Types

| Type | Description | Color |
|------|-------------|-------|
| Principal | Users, roles, AWS identities | Red |
| IPAddress | Source/destination IPs | Teal |
| Resource | AWS resources (S3, EC2, etc.) | Blue |
| APIOperation | AWS API calls | Green |
| SecurityFinding | Detection triggers | Bright Red |

## Alert Notifications

Route detection alerts to SNS topics and Slack webhooks:

```python
from secdashboards.notifications import (
    NotificationManager, SecurityAlert, SlackNotifier, SNSNotifier,
)
from secdashboards.detections.rule import Severity

# Configure channels
sns = SNSNotifier(topic_arn="arn:aws:sns:us-west-2:123456789:security-alerts")
slack = SlackNotifier(webhook_url="https://hooks.slack.com/services/T.../B.../xxx")

# Create manager with severity filter (only HIGH+ alerts go to Slack)
manager = NotificationManager(channels=[sns, slack], severity_filter=Severity.HIGH)

# Send from a detection result
results = manager.notify_detection(detection_result)

# Or create an alert directly
alert = SecurityAlert(
    rule_id="custom-001",
    rule_name="Manual Alert",
    severity=Severity.CRITICAL,
    message="Suspicious activity detected",
    match_count=5,
)
manager.notify(alert)
```

## AI Assistance (Amazon Bedrock)

Use Claude models via Amazon Bedrock for AI-assisted security workflows:

```python
from secdashboards.ai import BedrockAssistant, BedrockModel, TaskConfig

# Initialize assistant
assistant = BedrockAssistant(region="us-west-2")

# Generate a detection rule from natural language
response = assistant.generate_detection_rule(
    "Detect when root user logs in from an unusual IP"
)
print(response.content)
print(f"Cost: ${response.cost_usd:.4f}")

# Analyze an investigation graph
response = assistant.analyze_graph(graph, focus_area="lateral movement")

# Convert natural language to SQL
response = assistant.natural_language_to_sql(
    "Show me all failed API calls in the last hour"
)
```

### Supported Tasks

| Task | Recommended Model | Est. Cost |
|------|-------------------|-----------|
| Detection Generation | Claude 3.5 Sonnet | ~$0.02 |
| Alert Triage | Claude 3.5 Haiku | ~$0.005 |
| Graph Analysis | Claude 3.5 Sonnet | ~$0.03 |
| Attack Chain Analysis | Claude 3 Opus | ~$0.10 |
| Incident Reports | Claude 3.5 Sonnet | ~$0.05 |

Pricing source: [AWS Bedrock Pricing](https://aws.amazon.com/bedrock/pricing/)

## AWS Deployment

### Deploy Neptune Graph Database

```bash
aws cloudformation deploy \
  --template-file infrastructure/neptune.yaml \
  --stack-name secdash-neptune-dev \
  --parameter-overrides \
    Environment=dev \
    VpcId=vpc-xxx \
    PrivateSubnetIds=subnet-xxx,subnet-yyy \
  --capabilities CAPABILITY_NAMED_IAM
```

## Development

### Run Tests

```bash
# Full test suite
uv run pytest tests/

# Integration tests (require AWS credentials)
RUN_INTEGRATION_TESTS=1 uv run pytest tests/test_security_lake_integration.py -v
```

### Linting and Type Checking

```bash
# Lint with ruff
uv run ruff check src/

# Type check with ty (Astral)
uv run ty check src/
```

Pre-commit hooks run automatically via [prek](https://github.com/catppuccin/prek) (Rust-based, drop-in replacement for pre-commit). Hooks include ruff, ruff-format, YAML/JSON validation, and Lambda handler syntax checks.

### Adding Custom Connectors

Extend `DataConnector` for custom data sources:

```python
from secdashboards.connectors.base import DataConnector

class MyCustomConnector(DataConnector):
    def query(self, sql: str) -> pl.DataFrame:
        # Implementation
        ...

    def get_schema(self) -> dict[str, str]:
        # Implementation
        ...

    def check_health(self) -> HealthCheckResult:
        # Implementation
        ...

# Register with catalog
catalog.register_connector(DataSourceType.CUSTOM, MyCustomConnector)
```

## Troubleshooting

**"No AWS credentials found"** — Ensure `aws configure` has been run or `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` environment variables are set. For SSO, run `aws sso login` first.

**Athena query fails with "Access Denied"** — Check that your IAM user/role has `s3:GetObject` on the Security Lake S3 buckets and `s3:PutObject` on the Athena results bucket.

**"No data returned" for health checks** — Verify the data catalog (`catalog.yaml`) has the correct database/table names. Run `uv run secdash init-catalog --region <your-region>` to auto-discover tables.

**pdflatex not found** — PDF report generation requires a LaTeX distribution. On Debian/Ubuntu: `apt install texlive-latex-base`. On macOS: `brew install --cask mactex-no-gui`.

**Pre-commit hooks fail** — This project uses `prek` instead of `pre-commit`. Install with `uv sync --group dev`, which includes prek as a dependency.

## Security

See [SECURITY.md](SECURITY.md) for security design decisions, known sharp edges, and responsible disclosure guidelines.

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
