# Security Dashboards - Current State

**Last Updated**: 2026-01-13

## Project Overview

A local Marimo notebook-based tool for connecting to AWS Security Lake, creating detection rules, deploying them to Lambda for automated security monitoring, and testing detections with adversary emulation.

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
│   │   └── runner.py      # DetectionRunner for executing rules
│   ├── graph/             # Investigation graph module
│   │   ├── models.py      # Node/edge entity models (Pydantic)
│   │   ├── builder.py     # Graph construction from detections
│   │   ├── connector.py   # Neptune database connector
│   │   ├── enrichment.py  # Security Lake enrichment queries
│   │   ├── visualization.py  # pyvis graph visualization
│   │   └── queries.py     # Gremlin/openCypher query templates
│   ├── health/            # Health monitoring
│   │   ├── monitor.py     # HealthMonitor for checking data sources
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
│   └── cli.py             # Command-line interface
├── notebooks/
│   └── main.py            # Main Marimo notebook (includes Investigation Graph)
├── detections/
│   └── sample_rules.yaml  # 6 sample detection rules
├── infrastructure/
│   ├── template.yaml      # Lambda SAM/CloudFormation template
│   ├── neptune.yaml       # Neptune Serverless CloudFormation stack
│   └── marimo-apprunner.yaml  # App Runner VPC deployment
├── tests/
│   ├── test_catalog.py    # Unit tests for catalog (8 tests)
│   ├── test_detections.py # Unit tests for detections (9 tests)
│   ├── test_adversary.py  # Unit tests for adversary module (37 tests)
│   ├── test_graph.py      # Unit tests for graph module (50 tests)
│   └── test_security_lake_integration.py  # Integration tests (10 tests)
├── Dockerfile.marimo      # Container for AWS App Runner deployment
├── catalog.example.yaml   # Example catalog configuration
├── pyproject.toml         # Project configuration (uv, ruff, ty)
└── README.md              # Documentation
```

## Configuration

- **Package Manager**: uv
- **Linter**: ruff
- **Type Checker**: ty (Astral)
- **Default Region**: us-west-2

## Security Lake Schema Fixes Applied

The following issues were discovered and fixed after testing against actual Security Lake:

### 1. OCSFEventClass Enum (security_lake.py:15-66)
- **Issue**: Used `StrEnum` with string values like `"3002"`
- **Fix**: Changed to `IntEnum` with integer values like `3002`
- **Reason**: `class_uid` in Security Lake is stored as bigint, not string

### 2. Timestamp Column (all query methods)
- **Issue**: Queries used `time` column (epoch milliseconds bigint)
- **Fix**: Changed to `time_dt` column (proper timestamp)
- **Affected methods**: `query_by_event_class`, `get_event_summary`, `check_health`

### 3. Timestamp Formatting for Athena
- **Issue**: Python's `.isoformat()` returns `2026-01-11T20:26:14+00:00`
- **Fix**: Added `_format_timestamp()` method returning `2026-01-11 20:26:14.000000`
- **Reason**: Athena TIMESTAMP literals require specific format (no T, no timezone)

### 4. Sample Detection Rules (detections/sample_rules.yaml)
- Changed all `time` references to `time_dt`
- Changed `class_uid = '3002'` (string) to `class_uid = 3002` (integer)

### 5. Catalog Example (catalog.example.yaml)
- Updated health_check_query to use `time_dt`
- Updated all database/table names to use `us_west_2` region

## Test Status

### Unit Tests (130 total - all passing)
```bash
uv run pytest tests/ -v
```

- Catalog tests: 8
- Detection tests: 9
- Adversary tests: 37
- Graph tests: 50
- AI/Bedrock tests: 26

### Integration Tests (10 total - all passing)
```bash
RUN_INTEGRATION_TESTS=1 uv run pytest tests/test_security_lake_integration.py -v
```

**Note**: Integration tests auto-detect the Athena output bucket using AWS account ID.

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

## Sample Detection Run Results (from last 24h)

- **API Activity Events**: 1,217
- **Authentication Events**: 219
- **Failed API Calls**: 15 (mostly S3 bucket policy access)
- **Security-Sensitive Operations**: 20+ AssumeRole calls
- **Top Services**: KMS (352), STS (254), S3 (229), Glue (180), Athena (159)

## Running the Project

```bash
# Install dependencies
uv sync

# Run unit tests
uv run pytest

# Run integration tests (requires AWS credentials)
RUN_INTEGRATION_TESTS=1 uv run pytest tests/test_security_lake_integration.py -v

# Launch Marimo notebook
uv run marimo edit notebooks/main.py

# Or via CLI
uv run secdash notebook
```

## Known Deprecation Warnings

Several files still use `datetime.utcnow()` which is deprecated. These work but generate warnings:
- src/secdashboards/detections/rule.py
- src/secdashboards/detections/runner.py
- src/secdashboards/connectors/athena.py
- src/secdashboards/connectors/base.py
- src/secdashboards/health/url_analyzer.py
- src/secdashboards/health/monitor.py
- src/secdashboards/deploy/lambda_builder.py

**Fix**: Replace `datetime.utcnow()` with `datetime.now(UTC)` and import `UTC` from datetime.

## Adversary Emulation Module

The adversary module provides red team and detection testing capabilities:

### Components

1. **events.py** - OCSF-compliant synthetic event generators
   - `OCSFEventGenerator` - Main class for generating test events
   - Supports: root logins, IAM changes, security group modifications, brute force, API abuse, port scans, DNS queries

2. **network.py** - Network packet generation
   - `NetworkEmulator` - TCP/UDP/DNS packet generation
   - Simulates: port scans, DNS exfiltration, C2 beacons

3. **scenarios.py** - Pre-built MITRE ATT&CK scenarios
   - 8 attack scenarios mapped to techniques
   - Full attack chain simulation

4. **runner.py** - Test orchestration
   - `AdversaryTestRunner` - Tests detections against scenarios
   - `LocalDetectionTester` - Quick local testing

5. **Lambda deployment** - Network testing from AWS VPC
   - `lambda_handler.py` - Lambda for running network tests
   - `deploy.py` - SAM/CloudFormation template generation

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
secdash adversary deploy-lambda --output ./build --api

# Invoke deployed Lambda
secdash adversary invoke-lambda --scenario port_scan_sim
```

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

## Type Checking Status

- **ty check**: All errors fixed, only deprecation warnings remain (17 warnings for `datetime.utcnow()`)
- All type annotations added to adversary module with proper TypedDict definitions

## AI/Bedrock Module

The AI module (`src/secdashboards/ai/`) provides Amazon Bedrock integration:

### Components

1. **assistant.py** - BedrockAssistant class
   - Detection rule generation from natural language
   - Alert triage and analysis
   - Investigation graph analysis
   - Natural language to SQL conversion
   - Incident report generation
   - Cost tracking per session

2. **models.py** - Model configurations
   - All Claude models (3.5 Sonnet, 3.5 Haiku, 3 Opus, Sonnet 4, Opus 4)
   - Pricing per million tokens (input/output)
   - Task-to-model recommendations
   - Cost estimation functions

3. **prompts.py** - Security-focused prompts
   - Detection engineering prompts
   - Alert analysis prompts
   - Investigation prompts
   - Query generation prompts

4. **tools.py** - Agent tools skeleton
   - Tool specifications for future agent use
   - ToolExecutor class (not yet implemented)

## Notebooks

Notebooks are split by role and security sensitivity:

| Notebook | Purpose | Roles |
|----------|---------|-------|
| `main.py` | Navigation hub | All |
| `detection_engineering.py` | Create/test rules + AI generation | Detection Engineers |
| `investigation.py` | Graph visualization + AI analysis | SOC/IR |
| `monitoring.py` | Health checks, data freshness | SOC |
| `deployment.py` | Infrastructure deployment | Admin only |

## Investigation Graph Module

The graph module (`src/secdashboards/graph/`) provides security investigation graph capabilities:

### Components

1. **models.py** - Pydantic models for graph entities
   - Node types: Principal, IPAddress, Resource, APIOperation, SecurityFinding, Event
   - Edge types: AUTHENTICATED_FROM, CALLED_API, ACCESSED_RESOURCE, etc.
   - SecurityGraph container with NetworkX export

2. **builder.py** - Graph construction
   - `GraphBuilder` - Builds graphs from DetectionResult with enrichment
   - Extracts identifiers (users, IPs, operations) from matched events
   - Creates nodes and edges automatically

3. **enrichment.py** - Security Lake queries for graph enrichment
   - `SecurityLakeEnricher` - Query helpers with SQL injection protection
   - Methods: enrich_by_user, enrich_by_ip, enrich_by_resource

4. **visualization.py** - Interactive graph visualization
   - `GraphVisualizer` - Creates pyvis HTML graphs
   - Color-coded nodes by type
   - Interactive physics and zoom

5. **connector.py** - Neptune database operations
   - `NeptuneConnector` - Gremlin/openCypher client
   - IAM authentication support
   - Graph persistence and traversal queries

6. **queries.py** - Query templates
   - `GremlinQueries` - Gremlin query builders
   - `OpenCypherQueries` - openCypher query builders

### AWS Infrastructure

- **infrastructure/neptune.yaml** - Neptune Serverless (1-32 NCUs auto-scaling)
- **infrastructure/marimo-apprunner.yaml** - App Runner with VPC connector
- **Dockerfile.marimo** - Container for deployment

## Pending Improvements

1. Fix remaining `datetime.utcnow()` deprecation warnings
2. Add more detection rules for VPC Flow, Route53, Security Hub data
3. Test Lambda deployment workflow
4. Add alert notification integrations (SNS, Slack, etc.)
5. Add VPC Flow and Route53 specific detection rules for adversary scenarios
6. Add `py.typed` marker for PEP 561 type checking support
7. Consider adding mkdocs or sphinx for API documentation
