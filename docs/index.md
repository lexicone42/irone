# secdashboards

**Security Data Lake Analytics for AWS Security Lake**

A FastAPI + HTMX security analytics platform for AWS Security Lake. Create detection rules, visualize security investigation graphs, and deploy automated monitoring to AWS.

## Features

- **AWS Security Lake Integration** — Native OCSF-formatted Security Lake queries
- **CloudWatch Logs Integration** — Query Lambda, EKS, ALB, and API Gateway logs
- **Hybrid Hot/Cold Architecture** — Dual-target detection rules across CloudWatch (0-7 days) and Security Lake (7+ days)
- **Detection Rules Framework** — SQL-based security detection rules with scheduling
- **Alert Notifications** — Route alerts to SNS topics and Slack webhooks with severity filtering
- **Investigation Graphs** — Interactive graph visualization with Neptune persistence
- **Investigation Timelines** — Plotly-based interactive timelines with event tagging and AI summaries
- **Adversary Emulation** — MITRE ATT&CK-aligned attack scenarios for testing detections
- **Lambda Deployment** — Deploy detection rules as Lambda functions via CDK
- **AI Assistance** — Claude via Amazon Bedrock for detection generation, alert triage, and graph analysis

## Quick Example

```python
from secdashboards import DataCatalog, SecurityLakeConnector

catalog = DataCatalog.from_yaml("catalog.yaml")
connector = catalog.get_connector("cloudtrail")
df = connector.query_time_range("time_dt", start, end)
```

## Navigation

- [Getting Started](getting-started/installation.md) — Installation, configuration, first steps
- [API Reference](api/index.md) — Full API documentation for all modules
- [Security](security.md) — Security design decisions and sharp edges
