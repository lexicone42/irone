"""Alerting Stack - Real-time alerting for Security Lake data freshness and detections.

This stack creates:
1. SNS Topic for alerts with email/Slack subscriptions
2. Lambda function for health checks and detection execution
3. EventBridge scheduler for periodic checks
4. CloudWatch alarms for critical metrics

Alert Types:
- DATA_FRESHNESS: Security Lake data source is stale
- DETECTION_MATCH: A detection rule triggered
- APP_LOG_GAP: Application logs missing for period
- SYSTEM_ERROR: Health check or detection failed
"""

from __future__ import annotations

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
    - Multi-channel notifications (Email, Slack, SNS)
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
        """
        super().__init__(scope, construct_id, **kwargs)

        # =====================================================================
        # SNS Topics for Alert Routing
        # =====================================================================
        # Main alerts topic - all alerts go here
        alerts_topic = sns.Topic(
            self,
            "AlertsTopic",
            topic_name="secdash-alerts",
            display_name="Security Dashboards Alerts",
        )

        # Critical alerts topic - high severity only
        critical_topic = sns.Topic(
            self,
            "CriticalAlertsTopic",
            topic_name="secdash-critical-alerts",
            display_name="Security Dashboards Critical Alerts",
        )

        # Add email subscription if provided
        if alert_email:
            alerts_topic.add_subscription(subscriptions.EmailSubscription(alert_email))
            critical_topic.add_subscription(subscriptions.EmailSubscription(alert_email))

        # =====================================================================
        # Lambda Function for Health Checks and Alerting
        # =====================================================================
        # Import existing log group (created by previous log_retention usage)
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
            handler="index.handler",
            code=lambda_.Code.from_inline(self._get_alerting_lambda_code()),
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

        # Athena permissions
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

        # Glue catalog permissions
        alerting_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "glue:GetTable",
                    "glue:GetTables",
                    "glue:GetDatabase",
                ],
                resources=["*"],
            )
        )

        # S3 permissions for Athena results and Security Lake
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

        # CloudWatch Logs Insights permissions (for app log monitoring)
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
        # Data freshness check - runs every N minutes
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

        # Detection rules check - runs every 15 minutes
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
                event=events.RuleTargetInput.from_object(
                    {
                        "check_type": "detections",
                    }
                ),
            )
        )

        # =====================================================================
        # Slack Integration Lambda (if webhook provided)
        # =====================================================================
        if slack_webhook_url:
            slack_function = lambda_.Function(
                self,
                "SlackFunction",
                function_name="secdash-slack-notifier",
                runtime=lambda_.Runtime.PYTHON_3_12,
                handler="index.handler",
                code=lambda_.Code.from_inline(self._get_slack_lambda_code()),
                memory_size=128,
                timeout=Duration.seconds(30),
                environment={
                    "SLACK_WEBHOOK_URL": slack_webhook_url,
                },
            )

            # Subscribe Slack function to alerts topic
            alerts_topic.add_subscription(subscriptions.LambdaSubscription(slack_function))

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

    def _get_alerting_lambda_code(self) -> str:
        """Return the inline Lambda code for alerting."""
        return '''
import json
import os
import time
import urllib.request
from datetime import datetime, timezone

import boto3

# Configuration from environment
SECURITY_LAKE_DB = os.environ.get("SECURITY_LAKE_DB", "amazon_security_lake_glue_db_us_west_2")
ATHENA_OUTPUT = os.environ.get("ATHENA_OUTPUT", "")
ALERTS_TOPIC_ARN = os.environ.get("ALERTS_TOPIC_ARN", "")
CRITICAL_TOPIC_ARN = os.environ.get("CRITICAL_TOPIC_ARN", "")
FRESHNESS_THRESHOLD = int(os.environ.get("FRESHNESS_THRESHOLD_MINUTES", "60"))
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

# Security Lake table mappings
TABLES = {
    "cloud_trail_mgmt": "amazon_security_lake_table_us_west_2_cloud_trail_mgmt_2_0",
    "vpc_flow": "amazon_security_lake_table_us_west_2_vpc_flow_2_0",
    "route53": "amazon_security_lake_table_us_west_2_route53_2_0",
    "sh_findings": "amazon_security_lake_table_us_west_2_sh_findings_2_0",
    "lambda_execution": "amazon_security_lake_table_us_west_2_lambda_execution_2_0",
}

athena = boto3.client("athena")
sns = boto3.client("sns")


def run_query(query: str, timeout: int = 60) -> list:
    """Execute Athena query and return results."""
    response = athena.start_query_execution(
        QueryString=query,
        QueryExecutionContext={"Database": SECURITY_LAKE_DB},
        ResultConfiguration={"OutputLocation": ATHENA_OUTPUT},
    )
    query_id = response["QueryExecutionId"]

    start = time.time()
    while time.time() - start < timeout:
        result = athena.get_query_execution(QueryExecutionId=query_id)
        state = result["QueryExecution"]["Status"]["State"]
        if state == "SUCCEEDED":
            break
        elif state in ("FAILED", "CANCELLED"):
            return []
        time.sleep(1)
    else:
        return []

    results = []
    paginator = athena.get_paginator("get_query_results")
    for page in paginator.paginate(QueryExecutionId=query_id):
        columns = [col["Name"] for col in page["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]]
        for row in page["ResultSet"]["Rows"][1:]:
            values = [field.get("VarCharValue", "") for field in row["Data"]]
            results.append(dict(zip(columns, values)))
    return results


def check_freshness(sources: list) -> list:
    """Check data freshness for Security Lake sources."""
    alerts = []
    now = datetime.now(timezone.utc)

    for source in sources:
        table = TABLES.get(source)
        if not table:
            continue

        query = f"""
        SELECT MAX(time_dt) as latest_event
        FROM "{SECURITY_LAKE_DB}"."{table}"
        WHERE time_dt >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
        """

        try:
            results = run_query(query)
            if not results or not results[0].get("latest_event"):
                alerts.append({
                    "type": "DATA_FRESHNESS",
                    "severity": "HIGH",
                    "source": source,
                    "message": f"No data in last 24 hours for {source}",
                    "table": table,
                })
                continue

            latest = results[0]["latest_event"]
            # Parse timestamp
            clean_ts = latest.replace("Z", "").replace("T", " ").split(".")[0]
            latest_dt = datetime.strptime(clean_ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            minutes_ago = int((now - latest_dt).total_seconds() / 60)

            if minutes_ago > FRESHNESS_THRESHOLD:
                alerts.append({
                    "type": "DATA_FRESHNESS",
                    "severity": "MEDIUM" if minutes_ago < FRESHNESS_THRESHOLD * 2 else "HIGH",
                    "source": source,
                    "message": f"Data is {minutes_ago} minutes stale for {source}",
                    "table": table,
                    "minutes_stale": minutes_ago,
                })
        except Exception as e:
            alerts.append({
                "type": "SYSTEM_ERROR",
                "severity": "LOW",
                "source": source,
                "message": f"Failed to check freshness: {str(e)}",
            })

    return alerts


def send_alert(alert: dict):
    """Send alert to SNS topics."""
    message = json.dumps(alert, indent=2, default=str)
    subject = f"[{alert['severity']}] {alert['type']}: {alert.get('source', 'System')}"

    # Send to main topic
    if ALERTS_TOPIC_ARN:
        sns.publish(
            TopicArn=ALERTS_TOPIC_ARN,
            Message=message,
            Subject=subject[:100],
            MessageAttributes={
                "severity": {"DataType": "String", "StringValue": alert["severity"]},
                "type": {"DataType": "String", "StringValue": alert["type"]},
            },
        )

    # Send critical alerts to critical topic
    if alert["severity"] == "HIGH" and CRITICAL_TOPIC_ARN:
        sns.publish(
            TopicArn=CRITICAL_TOPIC_ARN,
            Message=message,
            Subject=f"🚨 CRITICAL: {subject[:90]}",
        )

    # Send to Slack if configured
    if SLACK_WEBHOOK_URL:
        send_slack_alert(alert)


def send_slack_alert(alert: dict):
    """Send alert to Slack webhook."""
    severity_emoji = {"HIGH": "🚨", "MEDIUM": "⚠️", "LOW": "ℹ️"}.get(alert["severity"], "📢")
    color = {"HIGH": "#dc3545", "MEDIUM": "#ffc107", "LOW": "#17a2b8"}.get(alert["severity"], "#6c757d")

    payload = {
        "attachments": [{
            "color": color,
            "title": f"{severity_emoji} {alert['type']}",
            "text": alert["message"],
            "fields": [
                {"title": "Source", "value": alert.get("source", "N/A"), "short": True},
                {"title": "Severity", "value": alert["severity"], "short": True},
            ],
            "footer": "secdashboards",
            "ts": int(time.time()),
        }]
    }

    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"Failed to send Slack alert: {e}")


def handler(event, context):
    """Main Lambda handler."""
    check_type = event.get("check_type", "freshness")
    alerts = []

    if check_type == "freshness":
        sources = event.get("sources", list(TABLES.keys()))
        alerts = check_freshness(sources)
    elif check_type == "detections":
        # TODO: Integrate with DetectionRunner
        pass

    # Send alerts
    for alert in alerts:
        send_alert(alert)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "check_type": check_type,
            "alerts_sent": len(alerts),
            "alerts": alerts,
        }),
    }
'''

    def _get_slack_lambda_code(self) -> str:
        """Return the inline Lambda code for Slack notifications."""
        return '''
import json
import os
import urllib.request

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")


def handler(event, context):
    """Forward SNS messages to Slack."""
    for record in event.get("Records", []):
        message = record.get("Sns", {}).get("Message", "{}")
        try:
            alert = json.loads(message)
        except:
            alert = {"message": message, "severity": "LOW", "type": "RAW"}

        severity_emoji = {"HIGH": "🚨", "MEDIUM": "⚠️", "LOW": "ℹ️"}.get(alert.get("severity", ""), "📢")
        color = {"HIGH": "#dc3545", "MEDIUM": "#ffc107", "LOW": "#17a2b8"}.get(alert.get("severity", ""), "#6c757d")

        payload = {
            "attachments": [{
                "color": color,
                "title": f"{severity_emoji} {alert.get('type', 'Alert')}",
                "text": alert.get("message", str(alert)),
                "fields": [
                    {"title": "Source", "value": alert.get("source", "N/A"), "short": True},
                    {"title": "Severity", "value": alert.get("severity", "N/A"), "short": True},
                ],
                "footer": "secdashboards",
            }]
        }

        if SLACK_WEBHOOK_URL:
            req = urllib.request.Request(
                SLACK_WEBHOOK_URL,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=10)

    return {"statusCode": 200}
'''
