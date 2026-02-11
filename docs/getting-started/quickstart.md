# Quick Start

## 1. Configure the Data Catalog

```bash
# Auto-discover Security Lake tables
uv run secdash init-catalog --region us-west-2 --output catalog.yaml

# Or copy the example
cp catalog.example.yaml catalog.yaml
```

## 2. Launch the Notebook

```bash
# Interactive Marimo notebook
uv run secdash notebook

# Or directly
uv run marimo edit notebooks/main.py
```

## 3. Run Health Checks

```bash
uv run secdash health --catalog catalog.yaml
```

## 4. Run Detections

```bash
uv run secdash run-detections \
  --catalog catalog.yaml \
  --rules detections/ \
  --source cloudtrail \
  --lookback 60
```

## 5. Deploy to Lambda (CDK)

```bash
# Build detection packages and notifications layer
uv run secdash deploy \
  --rules detections/ \
  --output deploy_output/ \
  --source cloudtrail

# Deploy via CDK
cd infrastructure/cdk
npx cdk deploy secdash-alerting secdash-detections
```

## CLI Commands

Run `uv run secdash --help` for the full command list:

| Command | Description |
|---------|-------------|
| `notebook` | Launch Marimo notebook |
| `health` | Check data source connectivity and freshness |
| `run-detections` | Execute detection rules |
| `deploy` | Build Lambda deployment packages |
| `init-catalog` | Auto-discover Security Lake tables |
| `adversary list-scenarios` | List attack scenarios |
| `adversary run-scenario` | Run adversary emulation |
| `adversary test-detections` | Test detections against synthetic events |
