"""Alerting Stack - Real-time alerting for Security Lake data freshness and detections.

This stack creates:
1. SNS Topic for alerts with email subscriptions
2. Lambda function for health checks and detection execution (uses notifications layer)
3. EventBridge scheduler for periodic checks

The Lambda handler is loaded from ``src/secdashboards/health/alerting_handler.py``
via ``Code.from_asset()``, enabling it to import ``secdashboards.notifications``
through the shared notifications Lambda Layer.

Alert Types:
- DATA_FRESHNESS: Security Lake data source is stale
- DETECTION_MATCH: A detection rule triggered
- APP_LOG_GAP: Application logs missing for period
- SYSTEM_ERROR: Health check or detection failed
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aws_cdk import (
    CfnOutput,
    Duration,
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
from aws_cdk import (
    aws_sns as sns,
)
from aws_cdk import (
    aws_sns_subscriptions as subscriptions,
)
from constructs import Construct


class AlertingStack(Stack):
    """Real-time alerting for Security Lake health and detection matches.

    Features:
    - Data freshness monitoring for all Security Lake sources
    - Detection rule execution on schedule
    - Multi-channel notifications via NotificationManager (SNS + Slack)
    - Alert deduplication and severity routing
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        alert_email: str = "",
        slack_webhook_url: str = "",
        security_lake_db: str = "amazon_security_lake_glue_db_us_west_2",
        athena_output: str = "s3://aws-athena-query-results-651804262336-us-west-2/",
        freshness_threshold_minutes: int = 60,
        check_interval_minutes: int = 15,
        notifications_layer_path: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the Alerting Stack.

        Args:
            alert_email: Email address for alert notifications
            slack_webhook_url: Slack incoming webhook URL for notifications
            security_lake_db: Security Lake Glue database name
            athena_output: S3 location for Athena query results
            freshness_threshold_minutes: Alert if data older than this (default: 60)
            check_interval_minutes: How often to run health checks (default: 15)
            notifications_layer_path: Path to notifications layer directory
        """
        super().__init__(scope, construct_id, **kwargs)

        # =====================================================================
        # SNS Topics for Alert Routing
        # =====================================================================
        alerts_topic = sns.Topic(
            self,
            "AlertsTopic",
            topic_name="secdash-alerts",
            display_name="Security Dashboards Alerts",
        )

        critical_topic = sns.Topic(
            self,
            "CriticalAlertsTopic",
            topic_name="secdash-critical-alerts",
            display_name="Security Dashboards Critical Alerts",
        )

        if alert_email:
            alerts_topic.add_subscription(subscriptions.EmailSubscription(alert_email))
            critical_topic.add_subscription(subscriptions.EmailSubscription(alert_email))

        # =====================================================================
        # Notifications Lambda Layer (optional - for NotificationManager)
        # =====================================================================
        layers: list[lambda_.ILayerVersion] = []
        if notifications_layer_path and Path(notifications_layer_path).exists():
            notifications_layer = lambda_.LayerVersion(
                self,
                "AlertingNotificationsLayer",
                layer_version_name="secdash-alerting-notifications",
                code=lambda_.Code.from_asset(notifications_layer_path),
                compatible_runtimes=[lambda_.Runtime.PYTHON_3_12],
                description="secdashboards.notifications + httpx + pydantic",
            )
            layers.append(notifications_layer)

        # =====================================================================
        # Lambda Function for Health Checks and Alerting
        # =====================================================================
        # Resolve handler asset path (relative to CDK app directory)
        handler_asset_path = str(
            Path(__file__).resolve().parents[3] / "src" / "secdashboards" / "health"
        )

        alerting_log_group = logs.LogGroup.from_log_group_name(
            self,
            "AlertingLogGroup",
            "/aws/lambda/secdash-alerting",
        )

        alerting_function = lambda_.Function(
            self,
            "AlertingFunction",
            function_name="secdash-alerting",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="alerting_handler.handler",
            code=lambda_.Code.from_asset(handler_asset_path),
            layers=layers,
            memory_size=512,
            timeout=Duration.minutes(5),
            environment={
                "SECURITY_LAKE_DB": security_lake_db,
                "ATHENA_OUTPUT": athena_output,
                "ALERTS_TOPIC_ARN": alerts_topic.topic_arn,
                "CRITICAL_TOPIC_ARN": critical_topic.topic_arn,
                "FRESHNESS_THRESHOLD_MINUTES": str(freshness_threshold_minutes),
                "SLACK_WEBHOOK_URL": slack_webhook_url,
            },
            log_group=alerting_log_group,
        )

        # Grant permissions
        alerts_topic.grant_publish(alerting_function)
        critical_topic.grant_publish(alerting_function)

        alerting_function.add_to_role_policy(
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

        alerting_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["glue:GetTable", "glue:GetTables", "glue:GetDatabase"],
                resources=["*"],
            )
        )

        alerting_function.add_to_role_policy(
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

        alerting_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "logs:StartQuery",
                    "logs:GetQueryResults",
                    "logs:DescribeLogGroups",
                ],
                resources=["*"],
            )
        )

        # =====================================================================
        # EventBridge Scheduler for Periodic Health Checks
        # =====================================================================
        freshness_rule = events.Rule(
            self,
            "FreshnessCheckRule",
            rule_name="secdash-freshness-check",
            description="Check Security Lake data source freshness",
            schedule=events.Schedule.rate(Duration.minutes(check_interval_minutes)),
        )
        freshness_rule.add_target(
            targets.LambdaFunction(
                alerting_function,
                event=events.RuleTargetInput.from_object(
                    {
                        "check_type": "freshness",
                        "sources": [
                            "cloud_trail_mgmt",
                            "vpc_flow",
                            "route53",
                            "sh_findings",
                            "lambda_execution",
                        ],
                    }
                ),
            )
        )

        detection_rule = events.Rule(
            self,
            "DetectionCheckRule",
            rule_name="secdash-detection-check",
            description="Run detection rules against Security Lake",
            schedule=events.Schedule.rate(Duration.minutes(15)),
        )
        detection_rule.add_target(
            targets.LambdaFunction(
                alerting_function,
                event=events.RuleTargetInput.from_object({"check_type": "detections"}),
            )
        )

        # =====================================================================
        # Outputs
        # =====================================================================
        CfnOutput(
            self,
            "AlertsTopicArn",
            value=alerts_topic.topic_arn,
            description="SNS Topic ARN for all alerts",
            export_name=f"{construct_id}-AlertsTopicArn",
        )

        CfnOutput(
            self,
            "CriticalTopicArn",
            value=critical_topic.topic_arn,
            description="SNS Topic ARN for critical alerts only",
            export_name=f"{construct_id}-CriticalTopicArn",
        )

        CfnOutput(
            self,
            "AlertingFunctionArn",
            value=alerting_function.function_arn,
            description="Alerting Lambda function ARN",
        )
