"""Deployment Notebook (Security-Sensitive)

Deploy detection rules to AWS Lambda and manage infrastructure via CDK.

**SECURITY NOTE:** This notebook contains operations that can modify
AWS infrastructure. Only authorized personnel should have access.

Run with: marimo edit notebooks/deployment.py
"""

import marimo

__generated_with = "0.19.2"
app = marimo.App(width="full")


@app.cell
def _():
    import marimo as mo

    mo.md(
        """
        # Deployment Management

        Deploy detection rules to AWS Lambda and manage infrastructure via CDK.

        ⚠️ **SECURITY NOTICE:** This notebook performs infrastructure operations.
        Ensure you have appropriate authorization before proceeding.

        **Capabilities:**
        - Build Lambda deployment packages for detection rules
        - Build notifications Lambda Layer
        - Deploy via AWS CDK stacks
        - Manage EventBridge schedules
        """
    )
    return (mo,)


@app.cell
def _(mo):
    mo.callout(
        mo.md(
            """
            **Authorization Required**

            Deployment operations require IAM permissions for:
            - Lambda function management
            - IAM role creation
            - EventBridge rule management
            - CDK / CloudFormation stack operations
            - SNS topic management

            Verify your credentials have the necessary permissions.
            """
        ),
        kind="warn",
    )
    return


@app.cell
def _():
    from pathlib import Path

    import polars as pl

    from secdashboards.catalog.models import DataSource, DataSourceType
    from secdashboards.catalog.registry import DataCatalog
    from secdashboards.deploy.lambda_builder import LambdaBuilder
    from secdashboards.detections.rule import DetectionMetadata, Severity, SQLDetectionRule

    return (
        DataCatalog,
        DataSource,
        DataSourceType,
        DetectionMetadata,
        LambdaBuilder,
        Path,
        SQLDetectionRule,
        Severity,
        pl,
    )


# =============================================================================
# Configuration
# =============================================================================


@app.cell
def _(mo):
    mo.md("## Configuration")
    return


@app.cell
def _(mo):
    region_input = mo.ui.dropdown(
        options=[
            "us-west-2",
            "us-west-1",
            "us-east-1",
            "us-east-2",
            "eu-west-1",
            "eu-central-1",
        ],
        value="us-west-2",
        label="AWS Region",
    )
    environment = mo.ui.dropdown(
        options=["dev", "staging", "prod"],
        value="dev",
        label="Environment",
    )

    mo.hstack([region_input, environment])
    return environment, region_input


@app.cell
def _(environment, mo):
    if environment.value == "prod":
        mo.callout(
            mo.md(
                "**Production Environment Selected** - Deployments will affect production systems."
            ),
            kind="danger",
        )
    return


@app.cell
def _(DataCatalog, DataSource, DataSourceType, region_input):
    catalog = DataCatalog()
    region = region_input.value
    region_underscore = region.replace("-", "_")

    catalog.add_source(
        DataSource(
            name="cloudtrail",
            type=DataSourceType.SECURITY_LAKE,
            database=f"amazon_security_lake_glue_db_{region_underscore}",
            table=f"amazon_security_lake_table_{region_underscore}_cloud_trail_mgmt_2_0",
            region=region,
            description="CloudTrail management events",
        )
    )
    return catalog, region, region_underscore


# =============================================================================
# Build Lambda Packages
# =============================================================================


@app.cell
def _(mo):
    mo.md(
        """
        ## Build Lambda Packages

        Build deployment packages for detection rules and the shared
        notifications Lambda Layer. These are consumed by the CDK stacks.
        """
    )
    return


@app.cell
def _(mo):
    build_dir = mo.ui.text(
        value="./build",
        label="Build Output Directory",
        full_width=True,
    )
    rules_dir = mo.ui.text(
        value="./detections",
        label="Rules Directory",
        full_width=True,
    )

    mo.vstack([build_dir, rules_dir])
    return build_dir, rules_dir


@app.cell
def _(mo):
    build_btn = mo.ui.run_button(label="Build Deployment Packages")
    build_btn
    return (build_btn,)


@app.cell
def _(LambdaBuilder, Path, build_btn, build_dir, mo, region, rules_dir):
    build_output = mo.md("_Configure options and click 'Build Deployment Packages'_")

    if build_btn.value:
        try:
            builder = LambdaBuilder(
                output_dir=Path(build_dir.value),
                region=region,
            )

            # Build notifications layer
            layer_path = builder.build_notifications_layer()

            # Build handler packages for each rule
            rules_path = Path(rules_dir.value)
            packages = []
            if rules_path.exists():
                for rule_file in sorted(rules_path.glob("*.yaml")):
                    pkg = builder.build_handler_package(rule_file)
                    packages.append(str(pkg))

            build_output = mo.vstack(
                [
                    mo.callout(
                        mo.md(f"**Built {len(packages)} packages** + notifications layer"),
                        kind="success",
                    ),
                    mo.md(f"**Notifications Layer:** `{layer_path}`"),
                    mo.md(f"**Rule Packages:** {len(packages)}"),
                    mo.md("---"),
                    mo.md(
                        """
                    **Next step:** Deploy with CDK:
                    ```bash
                    cd infrastructure/cdk
                    npx cdk deploy secdash-detections
                    ```
                    """
                    ),
                ]
            )
        except Exception as e:
            build_output = mo.md(f"**Error:** {e}")

    build_output
    return (build_output,)


# =============================================================================
# CDK Deployment
# =============================================================================


@app.cell
def _(mo):
    mo.md(
        """
        ## CDK Deployment

        Deploy infrastructure using AWS CDK stacks.

        | Stack | Description | Key Resources |
        |-------|-------------|---------------|
        | `secdash-alerting` | Health monitoring & alerting | Lambda, SNS, EventBridge |
        | `secdash-detections` | Detection rule Lambdas | Lambda per rule, shared Layer |
        | `secdash-health-dashboard` | Health dashboard API | Lambda, API Gateway, Cognito |
        | Neptune | Graph database | Neptune Serverless (`neptune.yaml`) |
        | App Runner | Marimo hosting | App Runner VPC (`marimo-apprunner.yaml`) |
        """
    )
    return


@app.cell
def _(mo):
    athena_bucket = mo.ui.text(
        value="",
        label="Athena Output S3 Bucket",
        full_width=True,
        placeholder="my-athena-results-bucket",
    )
    alert_email = mo.ui.text(
        value="",
        label="Alert Email (optional)",
        full_width=True,
        placeholder="security@example.com",
    )
    slack_webhook = mo.ui.text(
        value="",
        label="Slack Webhook URL (optional)",
        full_width=True,
        placeholder="https://hooks.slack.com/services/...",
    )

    mo.vstack([athena_bucket, alert_email, slack_webhook])
    return alert_email, athena_bucket, slack_webhook


@app.cell
def _(alert_email, athena_bucket, environment, mo, region, slack_webhook):
    # CDK deploy commands
    alerting_cmd = f"""cd infrastructure/cdk
npx cdk deploy secdash-alerting \\
  --context region={region} \\
  --context environment={environment.value} \\
  --context athenaOutput=s3://{athena_bucket.value or 'YOUR-BUCKET'}/ \\
  --context alertEmail={alert_email.value or ''} \\
  --context slackWebhookUrl={slack_webhook.value or ''}"""

    detections_cmd = f"""cd infrastructure/cdk
npx cdk deploy secdash-detections \\
  --context region={region} \\
  --context environment={environment.value} \\
  --context buildDir=../../build \\
  --context layerPath=../../build/notifications_layer"""

    all_cmd = f"""cd infrastructure/cdk
npx cdk deploy --all \\
  --context region={region} \\
  --context environment={environment.value}"""

    mo.vstack(
        [
            mo.md("### Deploy Alerting Stack"),
            mo.ui.code_editor(value=alerting_cmd, language="bash", min_height=130),
            mo.md("### Deploy Detection Rules Stack"),
            mo.ui.code_editor(value=detections_cmd, language="bash", min_height=110),
            mo.md("### Deploy All Stacks"),
            mo.ui.code_editor(value=all_cmd, language="bash", min_height=90),
        ]
    )
    return alerting_cmd, all_cmd, detections_cmd


# =============================================================================
# CloudFormation Stacks (Non-CDK)
# =============================================================================


@app.cell
def _(environment, mo, region):
    neptune_cmd = f"""aws cloudformation deploy \\
  --template-file infrastructure/neptune.yaml \\
  --stack-name secdash-neptune-{environment.value} \\
  --region {region} \\
  --parameter-overrides \\
    Environment={environment.value} \\
    VpcId=vpc-XXXXX \\
    PrivateSubnetIds=subnet-XXXXX,subnet-YYYYY \\
  --capabilities CAPABILITY_NAMED_IAM"""

    apprunner_cmd = f"""aws cloudformation deploy \\
  --template-file infrastructure/marimo-apprunner.yaml \\
  --stack-name secdash-marimo-{environment.value} \\
  --region {region} \\
  --parameter-overrides \\
    Environment={environment.value} \\
    VpcId=vpc-XXXXX \\
    PrivateSubnetIds=subnet-XXXXX,subnet-YYYYY \\
    ImageUri=ACCOUNT.dkr.ecr.{region}.amazonaws.com/secdash-marimo:latest \\
    AthenaOutputBucket=my-athena-results \\
  --capabilities CAPABILITY_NAMED_IAM"""

    mo.vstack(
        [
            mo.md("### Deploy Neptune (CloudFormation)"),
            mo.ui.code_editor(value=neptune_cmd, language="bash", min_height=120),
            mo.md("### Deploy App Runner (CloudFormation)"),
            mo.ui.code_editor(value=apprunner_cmd, language="bash", min_height=150),
        ]
    )
    return apprunner_cmd, neptune_cmd


# =============================================================================
# AWS Console Links
# =============================================================================


@app.cell
def _(mo):
    mo.md("## AWS Console Links")
    return


@app.cell
def _(mo, region):
    infra_links = [
        (
            "CloudFormation Stacks",
            f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks",
        ),
        (
            "Lambda Functions",
            f"https://{region}.console.aws.amazon.com/lambda/home?region={region}#/functions",
        ),
        (
            "EventBridge Rules",
            f"https://{region}.console.aws.amazon.com/events/home?region={region}#/rules",
        ),
        (
            "SNS Topics",
            f"https://{region}.console.aws.amazon.com/sns/v3/home?region={region}#/topics",
        ),
        (
            "App Runner Services",
            f"https://{region}.console.aws.amazon.com/apprunner/home?region={region}#/services",
        ),
        (
            "Neptune Databases",
            f"https://{region}.console.aws.amazon.com/neptune/home?region={region}#databases",
        ),
    ]

    links_md = "\n".join(f"- [{name}]({url})" for name, url in infra_links)
    mo.md(links_md)
    return infra_links, links_md


if __name__ == "__main__":
    app.run()
