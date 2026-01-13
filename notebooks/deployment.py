"""Deployment Notebook (Security-Sensitive)

Deploy detection rules to AWS Lambda and manage infrastructure.

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

        Deploy detection rules to AWS Lambda and manage infrastructure.

        ⚠️ **SECURITY NOTICE:** This notebook performs infrastructure operations.
        Ensure you have appropriate authorization before proceeding.

        **Capabilities:**
        - Generate SAM/CloudFormation templates
        - Deploy detection Lambda functions
        - Manage EventBridge schedules
        - Infrastructure stack management
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
            - CloudFormation stack operations

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
            mo.md("**Production Environment Selected** - Deployments will affect production systems."),
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
# Generate Deployment Package
# =============================================================================


@app.cell
def _(mo):
    mo.md(
        """
        ## Generate Deployment Package

        Create SAM/CloudFormation templates and Lambda deployment packages
        for detection rules.
        """
    )
    return


@app.cell
def _(mo):
    output_dir = mo.ui.text(
        value="./deploy_output",
        label="Output Directory",
        full_width=True,
    )
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

    mo.vstack([output_dir, athena_bucket, alert_email])
    return alert_email, athena_bucket, output_dir


@app.cell
def _(mo):
    template_type = mo.ui.radio(
        options=["SAM Template", "CloudFormation Template"],
        value="SAM Template",
        label="Template Type",
    )
    schedule_rate = mo.ui.dropdown(
        options=[
            ("Every 5 minutes", "rate(5 minutes)"),
            ("Every 15 minutes", "rate(15 minutes)"),
            ("Every hour", "rate(1 hour)"),
            ("Every 6 hours", "rate(6 hours)"),
            ("Daily", "rate(1 day)"),
        ],
        value="rate(15 minutes)",
        label="Detection Schedule",
    )

    mo.hstack([template_type, schedule_rate])
    return schedule_rate, template_type


@app.cell
def _(mo):
    generate_btn = mo.ui.run_button(label="Generate Deployment Package")
    generate_btn
    return (generate_btn,)


@app.cell
def _(
    LambdaBuilder,
    Path,
    alert_email,
    athena_bucket,
    environment,
    generate_btn,
    mo,
    output_dir,
    region,
    schedule_rate,
    template_type,
):
    deploy_output = mo.md("_Configure options and click 'Generate Deployment Package'_")

    if generate_btn.value:
        if not athena_bucket.value:
            deploy_output = mo.md("**Error:** Athena Output S3 Bucket is required")
        else:
            try:
                builder = LambdaBuilder(
                    output_dir=Path(output_dir.value),
                    region=region,
                )

                # Generate template based on selection
                if "SAM" in template_type.value:
                    template = builder.generate_sam_template(
                        athena_bucket=athena_bucket.value,
                        schedule_rate=schedule_rate.value,
                        alert_email=alert_email.value if alert_email.value else None,
                        environment=environment.value,
                    )
                else:
                    template = builder.generate_cloudformation_template(
                        athena_bucket=athena_bucket.value,
                        schedule_rate=schedule_rate.value,
                        alert_email=alert_email.value if alert_email.value else None,
                        environment=environment.value,
                    )

                deploy_output = mo.vstack(
                    [
                        mo.md(f"**Generated:** {template_type.value}"),
                        mo.md(f"**Output Directory:** {output_dir.value}"),
                        mo.md("---"),
                        mo.md("**Template Preview:**"),
                        mo.ui.code_editor(value=template, language="yaml", min_height=400),
                        mo.md("---"),
                        mo.md(
                            f"""
                        **Deploy with AWS SAM CLI:**
                        ```bash
                        cd {output_dir.value}
                        sam build
                        sam deploy --guided
                        ```

                        **Or with CloudFormation:**
                        ```bash
                        aws cloudformation deploy \\
                          --template-file {output_dir.value}/template.yaml \\
                          --stack-name secdash-detections-{environment.value} \\
                          --capabilities CAPABILITY_NAMED_IAM
                        ```
                        """
                        ),
                    ]
                )

            except Exception as e:
                deploy_output = mo.md(f"**Error:** {e}")

    deploy_output
    return deploy_output, template


# =============================================================================
# Infrastructure Stacks
# =============================================================================


@app.cell
def _(mo):
    mo.md(
        """
        ## Infrastructure Stacks

        Pre-built CloudFormation stacks for secdashboards infrastructure.

        | Stack | Description | Template |
        |-------|-------------|----------|
        | Neptune | Graph database for investigations | `infrastructure/neptune.yaml` |
        | App Runner | Marimo notebook hosting | `infrastructure/marimo-apprunner.yaml` |
        | Detections | Lambda + EventBridge | `infrastructure/template.yaml` |
        """
    )
    return


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
            mo.md("### Deploy Neptune"),
            mo.ui.code_editor(value=neptune_cmd, language="bash", min_height=120),
            mo.md("### Deploy App Runner"),
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
            "App Runner Services",
            f"https://{region}.console.aws.amazon.com/apprunner/home?region={region}#/services",
        ),
        (
            "Neptune Databases",
            f"https://{region}.console.aws.amazon.com/neptune/home?region={region}#databases",
        ),
        (
            "ECR Repositories",
            f"https://{region}.console.aws.amazon.com/ecr/repositories?region={region}",
        ),
    ]

    links_md = "\n".join(f"- [{name}]({url})" for name, url in infra_links)
    mo.md(links_md)
    return infra_links, links_md


if __name__ == "__main__":
    app.run()
