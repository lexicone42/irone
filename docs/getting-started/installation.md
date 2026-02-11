# Installation

## Prerequisites

- **Python 3.13+**
- **[uv](https://docs.astral.sh/uv/)** package manager
- **AWS credentials** configured via `aws configure` or environment variables
- **pdflatex** (optional, for PDF report generation)

## Install

```bash
git clone https://github.com/lexicone42/secdashboards.git
cd secdashboards
uv sync
```

### Development dependencies

```bash
uv sync --group dev
```

### Documentation dependencies

```bash
uv sync --group docs
```

### CDK dependencies (for deployment stacks)

```bash
uv sync --group cdk
```

## AWS Credentials

```bash
# Using AWS CLI
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-west-2
```

### Required IAM Permissions

| Service | Permissions |
|---------|------------|
| Athena | `StartQueryExecution`, `GetQueryExecution`, `GetQueryResults` |
| S3 | `GetObject`, `PutObject` on Athena results bucket; `GetObject` on Security Lake buckets |
| Glue | `GetTable`, `GetDatabase` |
