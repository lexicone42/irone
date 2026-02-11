"""Detection Rules Stack - CDK deployment for detection Lambda functions.

Replaces SAM template generation with a CDK-native approach. Each detection
rule gets its own Lambda function with EventBridge schedule, sharing a common
notifications Lambda Layer for SNS/Slack alert delivery.

Cross-stack reference:
    Imports ``AlertsTopicArn`` from the AlertingStack so detection Lambdas
    can publish to the same SNS topic used by health-check alerts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aws_cdk import (
    CfnOutput,
    Duration,
    Fn,
    Stack,
)
from aws_cdk import (
    aws_events as events,
)
from aws_cdk import (
    aws_events_targets as targets,
)
from aws_cdk import (
    aws_iam as iam,
)
from aws_cdk import (
    aws_lambda as lambda_,
)
from aws_cdk import (
    aws_logs as logs,
)
from constructs import Construct


class DetectionRulesStack(Stack):
    """Deploy detection rules as individual Lambda functions with schedules.

    Each subfolder in *build_dir* is treated as a pre-built handler package.
    The stack creates one Lambda per subfolder, an EventBridge rate-based
    schedule, and grants Athena/S3/SNS permissions.

    A shared Lambda Layer containing ``secdashboards.notifications`` (plus
    ``httpx`` and ``pydantic``) is attached to every function so handlers
    can use ``NotificationManager`` for multi-channel alerting.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        build_dir: Path | str,
        notifications_layer_path: Path | str,
        security_lake_db: str = "amazon_security_lake_glue_db_us_west_2",
        athena_output: str = "s3://aws-athena-query-results/",
        slack_webhook_url: str = "",
        alerting_stack_name: str = "secdash-alerting",
        schedule_rate_minutes: int = 15,
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        build_path = Path(build_dir)
        layer_path = Path(notifications_layer_path)

        # Import SNS topic ARN exported by AlertingStack
        alerts_topic_arn = Fn.import_value(f"{alerting_stack_name}-AlertsTopicArn")

        # -----------------------------------------------------------------
        # Shared Lambda Layer (notifications + deps)
        # -----------------------------------------------------------------
        notifications_layer = lambda_.LayerVersion(
            self,
            "NotificationsLayer",
            layer_version_name="secdash-notifications",
            code=lambda_.Code.from_asset(str(layer_path)),
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_12],
            description="secdashboards.notifications + httpx + pydantic",
        )

        # -----------------------------------------------------------------
        # One Lambda per rule subfolder
        # -----------------------------------------------------------------
        if not build_path.exists():
            return  # Nothing to deploy yet

        rule_dirs = sorted(
            d for d in build_path.iterdir() if d.is_dir() and d.name.startswith("package_")
        )

        for rule_dir in rule_dirs:
            rule_id = rule_dir.name.removeprefix("package_")
            safe_id = rule_id.replace("-", "").replace("_", "").title()

            log_group = logs.LogGroup(
                self,
                f"LogGroup{safe_id}",
                log_group_name=f"/aws/lambda/secdash-detection-{rule_id}",
                retention=logs.RetentionDays.TWO_WEEKS,
            )

            fn = lambda_.Function(
                self,
                f"Detection{safe_id}",
                function_name=f"secdash-detection-{rule_id}",
                runtime=lambda_.Runtime.PYTHON_3_12,
                handler="handler.handler",
                code=lambda_.Code.from_asset(str(rule_dir)),
                layers=[notifications_layer],
                memory_size=256,
                timeout=Duration.minutes(5),
                environment={
                    "ATHENA_DATABASE": security_lake_db,
                    "ATHENA_OUTPUT_LOCATION": athena_output,
                    "SNS_TOPIC_ARN": alerts_topic_arn,
                    "SLACK_WEBHOOK_URL": slack_webhook_url,
                },
                log_group=log_group,
            )

            # Athena + Glue + S3 permissions
            fn.add_to_role_policy(
                iam.PolicyStatement(
                    actions=[
                        "athena:StartQueryExecution",
                        "athena:GetQueryExecution",
                        "athena:GetQueryResults",
                        "athena:StopQueryExecution",
                    ],
                    resources=["*"],
                )
            )
            fn.add_to_role_policy(
                iam.PolicyStatement(
                    actions=["glue:GetTable", "glue:GetTables", "glue:GetDatabase"],
                    resources=["*"],
                )
            )
            fn.add_to_role_policy(
                iam.PolicyStatement(
                    actions=[
                        "s3:GetBucketLocation",
                        "s3:GetObject",
                        "s3:ListBucket",
                        "s3:PutObject",
                    ],
                    resources=[
                        f"arn:aws:s3:::{athena_output.replace('s3://', '').split('/')[0]}",
                        f"arn:aws:s3:::{athena_output.replace('s3://', '').split('/')[0]}/*",
                        "arn:aws:s3:::amazon-security-lake-*",
                        "arn:aws:s3:::amazon-security-lake-*/*",
                    ],
                )
            )
            fn.add_to_role_policy(
                iam.PolicyStatement(
                    actions=["sns:Publish"],
                    resources=[alerts_topic_arn],
                )
            )

            # EventBridge schedule
            rule = events.Rule(
                self,
                f"Schedule{safe_id}",
                rule_name=f"secdash-schedule-{rule_id}",
                description=f"Run detection: {rule_id}",
                schedule=events.Schedule.rate(Duration.minutes(schedule_rate_minutes)),
            )
            rule.add_target(targets.LambdaFunction(fn))

        # -----------------------------------------------------------------
        # Outputs
        # -----------------------------------------------------------------
        CfnOutput(
            self,
            "NotificationsLayerArn",
            value=notifications_layer.layer_version_arn,
            description="Notifications Lambda Layer ARN",
            export_name=f"{construct_id}-NotificationsLayerArn",
        )
