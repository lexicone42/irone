# Security Data Lake Analytics (secdashboards)

A Marimo notebook-based security analytics platform for AWS Security Lake. Create detection rules, visualize security investigation graphs, and deploy automated monitoring to AWS.

## Features

- **AWS Security Lake Integration**: Native support for OCSF-formatted Security Lake data
- **Detection Rules Framework**: Create, test, and manage SQL-based security detection rules
- **Investigation Graph Visualization**: Interactive graph visualization for security investigations using pyvis
- **Neptune Graph Database**: Persist and query security graphs with AWS Neptune Serverless
- **Adversary Emulation**: Test detections with MITRE ATT&CK-aligned attack scenarios
- **Lambda Deployment**: Deploy detection rules to Lambda with CloudWatch schedules
- **AWS App Runner Deployment**: Deploy Marimo notebooks to AWS with VPC-only access
- **Health Monitoring**: Check data freshness and source connectivity
- **Interactive Marimo Notebook**: Visual interface for exploration and rule development

## Quick Start

### Installation

```bash
# Clone and install with uv
cd secdashboards
uv sync

# Install dev dependencies
uv sync --group dev
```

### Launch the Notebook

```bash
# Run the interactive Marimo notebook
uv run marimo edit notebooks/main.py
```

Or use the CLI:

```bash
uv run secdash notebook
```

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

Generate SAM deployment packages:

```bash
uv run secdash deploy \
  --rules detections/ \
  --output deploy_output/ \
  --source cloudtrail \
  --sam
```

Deploy with SAM CLI:

```bash
cd deploy_output
sam deploy --guided
```

Or use the provided CloudFormation template:

```bash
aws cloudformation deploy \
  --template-file infrastructure/template.yaml \
  --stack-name secdashboards-dev \
  --parameter-overrides \
    Environment=dev \
    AthenaOutputBucket=my-athena-results \
    AlertEmail=security@example.com \
  --capabilities CAPABILITY_NAMED_IAM
```

## Project Structure

```
secdashboards/
├── src/secdashboards/
│   ├── catalog/          # Data catalog and source management
│   ├── connectors/       # Data source connectors (Athena, Security Lake)
│   ├── detections/       # Detection rules framework
│   ├── graph/            # Investigation graph module
│   │   ├── models.py     # Node/edge entity models
│   │   ├── builder.py    # Graph construction from detections
│   │   ├── connector.py  # Neptune database connector
│   │   ├── enrichment.py # Security Lake enrichment queries
│   │   ├── visualization.py  # pyvis graph visualization
│   │   └── queries.py    # Gremlin/openCypher templates
│   ├── ai/               # AI assistance (Bedrock)
│   │   ├── assistant.py  # BedrockAssistant class
│   │   ├── models.py     # Model configs and pricing
│   │   ├── prompts.py    # Security-focused prompts
│   │   └── tools.py      # Agent tools skeleton
│   ├── health/           # Health monitoring and URL analysis
│   ├── adversary/        # Adversary emulation and testing
│   ├── deploy/           # Lambda deployment utilities
│   └── cli.py            # Command-line interface
├── notebooks/
│   ├── main.py               # Navigation hub
│   ├── detection_engineering.py  # Create/test detection rules
│   ├── investigation.py      # Graph visualization & IR
│   ├── monitoring.py         # Health monitoring
│   └── deployment.py         # Infrastructure (admin only)
├── detections/
│   └── sample_rules.yaml # Example detection rules
├── infrastructure/
│   ├── template.yaml     # Lambda SAM/CloudFormation template
│   ├── neptune.yaml      # Neptune Serverless stack
│   └── marimo-apprunner.yaml  # App Runner VPC deployment
├── tests/                # Unit and integration tests
├── Dockerfile.marimo     # Container for AWS deployment
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

Deploy Marimo notebooks to AWS with VPC-only access using App Runner.

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

### Deploy Marimo App Runner

```bash
# Build and push container
docker build -f Dockerfile.marimo -t secdash-marimo .
aws ecr get-login-password | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com
docker tag secdash-marimo:latest <account>.dkr.ecr.<region>.amazonaws.com/secdash-marimo:latest
docker push <account>.dkr.ecr.<region>.amazonaws.com/secdash-marimo:latest

# Deploy App Runner
aws cloudformation deploy \
  --template-file infrastructure/marimo-apprunner.yaml \
  --stack-name secdash-marimo-dev \
  --parameter-overrides \
    Environment=dev \
    VpcId=vpc-xxx \
    PrivateSubnetIds=subnet-xxx,subnet-yyy \
    ImageUri=<account>.dkr.ecr.<region>.amazonaws.com/secdash-marimo:latest \
    AthenaOutputBucket=my-athena-results \
  --capabilities CAPABILITY_NAMED_IAM
```

## Development

### Run Tests

```bash
uv run pytest
```

### Linting and Type Checking

```bash
# Lint with ruff
uv run ruff check src/

# Type check with ty
uv run ty check src/
```

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

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
