"""Lambda handler for Security Lake data freshness checks and detection alerting.

Extracted from the CDK AlertingStack inline code to enable use of the
``secdashboards.notifications`` module (provided via Lambda Layer).
"""

import json
import logging
import os
import time
from datetime import UTC, datetime
from typing import Any

import boto3

from secdashboards.notifications import (
    NotificationManager,
    SecurityAlert,
    SlackNotifier,
    SNSNotifier,
)

logger = logging.getLogger(__name__)

# Configuration from environment
SECURITY_LAKE_DB = os.environ.get("SECURITY_LAKE_DB", "amazon_security_lake_glue_db_us_west_2")
ATHENA_OUTPUT = os.environ.get("ATHENA_OUTPUT", "")
ALERTS_TOPIC_ARN = os.environ.get("ALERTS_TOPIC_ARN", "")
CRITICAL_TOPIC_ARN = os.environ.get("CRITICAL_TOPIC_ARN", "")
FRESHNESS_THRESHOLD = int(os.environ.get("FRESHNESS_THRESHOLD_MINUTES", "60"))
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
RULES_BUCKET = os.environ.get("RULES_BUCKET", "")
RULES_PREFIX = os.environ.get("RULES_PREFIX", "detection-rules/")
LOOKBACK_MINUTES = int(os.environ.get("LOOKBACK_MINUTES", "15"))

# Security Lake table mappings
TABLES = {
    "cloud_trail_mgmt": "amazon_security_lake_table_us_west_2_cloud_trail_mgmt_2_0",
    "vpc_flow": "amazon_security_lake_table_us_west_2_vpc_flow_2_0",
    "route53": "amazon_security_lake_table_us_west_2_route53_2_0",
    "sh_findings": "amazon_security_lake_table_us_west_2_sh_findings_2_0",
    "lambda_execution": "amazon_security_lake_table_us_west_2_lambda_execution_2_0",
}

athena = boto3.client("athena")
sns_client = boto3.client("sns")


def _build_notification_manager() -> NotificationManager:
    """Build notification manager from environment variables."""
    channels = []
    if ALERTS_TOPIC_ARN:
        channels.append(SNSNotifier(topic_arn=ALERTS_TOPIC_ARN))
    if SLACK_WEBHOOK_URL:
        channels.append(SlackNotifier(webhook_url=SLACK_WEBHOOK_URL))
    return NotificationManager(channels=channels)


def run_query(query: str, timeout: int = 60) -> list:
    """Execute Athena query and return results."""
    kwargs: dict = {
        "QueryString": query,
        "QueryExecutionContext": {"Database": SECURITY_LAKE_DB},
    }
    if ATHENA_OUTPUT:
        kwargs["ResultConfiguration"] = {"OutputLocation": ATHENA_OUTPUT}
    response = athena.start_query_execution(**kwargs)
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
            results.append(dict(zip(columns, values, strict=False)))
    return results


def check_freshness(sources: list) -> list:
    """Check data freshness for Security Lake sources."""
    alerts = []
    now = datetime.now(UTC)

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
                alerts.append(
                    {
                        "type": "DATA_FRESHNESS",
                        "severity": "high",
                        "source": source,
                        "message": f"No data in last 24 hours for {source}",
                        "table": table,
                    }
                )
                continue

            latest = results[0]["latest_event"]
            clean_ts = latest.replace("Z", "").replace("T", " ").split(".")[0]
            latest_dt = datetime.strptime(clean_ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
            minutes_ago = int((now - latest_dt).total_seconds() / 60)

            if minutes_ago > FRESHNESS_THRESHOLD:
                alerts.append(
                    {
                        "type": "DATA_FRESHNESS",
                        "severity": "medium" if minutes_ago < FRESHNESS_THRESHOLD * 2 else "high",
                        "source": source,
                        "message": f"Data is {minutes_ago} minutes stale for {source}",
                        "table": table,
                        "minutes_stale": minutes_ago,
                    }
                )
        except Exception as e:
            alerts.append(
                {
                    "type": "SYSTEM_ERROR",
                    "severity": "low",
                    "source": source,
                    "message": f"Failed to check freshness: {e!s}",
                }
            )

    return alerts


def send_alert(alert_data: dict) -> None:
    """Send alert via NotificationManager (SNS + Slack)."""
    manager = _build_notification_manager()
    alert = SecurityAlert(
        rule_id=f"freshness-{alert_data.get('source', 'unknown')}",
        rule_name=alert_data["type"],
        severity=alert_data.get("severity", "medium"),
        message=alert_data["message"],
        metadata={k: v for k, v in alert_data.items() if k not in ("type", "severity", "message")},
    )
    manager.notify(alert)

    # Also send to critical topic for HIGH severity alerts
    if alert_data.get("severity") == "high" and CRITICAL_TOPIC_ARN:
        sns_client.publish(
            TopicArn=CRITICAL_TOPIC_ARN,
            Message=json.dumps(alert_data, indent=2, default=str),
            Subject=f"CRITICAL: {alert_data['type']}: {alert_data.get('source', 'System')}"[:100],
        )


def run_detections(event: dict) -> list:
    """Run detection rules via DetectionRunner and return alerts for triggered rules."""
    from secdashboards.catalog import DataCatalog
    from secdashboards.detections.rule import Severity
    from secdashboards.detections.rule_store import S3RuleStore
    from secdashboards.detections.runner import DetectionRunner

    lookback = event.get("lookback_minutes", LOOKBACK_MINUTES)
    rule_ids = event.get("rule_ids")

    # Build catalog with Security Lake connector
    catalog = DataCatalog()
    catalog.create_security_lake_source(
        name="cloudtrail",
        database=SECURITY_LAKE_DB,
        table=TABLES["cloud_trail_mgmt"],
        connector_config={"output_location": ATHENA_OUTPUT},
    )
    connector = catalog.get_connector("cloudtrail")

    # Load rules from S3RuleStore
    runner = DetectionRunner(catalog=catalog, allow_python_rules=False)
    if RULES_BUCKET:
        store = S3RuleStore(bucket=RULES_BUCKET, prefix=RULES_PREFIX)
        for rule, _version in store.load_all_rules():
            runner.register_rule(rule)
    else:
        logger.warning("No RULES_BUCKET configured, no detection rules loaded")
        return []

    # Filter to specific rule IDs if requested
    if rule_ids:
        for rid in list(runner._rules):
            if rid not in rule_ids:
                del runner._rules[rid]

    results = runner.run_all(connector, lookback_minutes=lookback)

    # Convert triggered results to alert dicts
    alerts = []
    for result in results:
        if result.triggered:
            alert_dict = result.to_alert_dict()
            alerts.append(
                {
                    "type": "DETECTION",
                    "severity": result.severity.value
                    if isinstance(result.severity, Severity)
                    else str(result.severity),
                    "source": result.rule_id,
                    "message": result.message or f"Detection triggered: {result.rule_name}",
                    "rule_name": result.rule_name,
                    "match_count": result.match_count,
                    "sample_matches": alert_dict.get("sample_matches", []),
                }
            )
        elif result.error:
            alerts.append(
                {
                    "type": "DETECTION_ERROR",
                    "severity": "low",
                    "source": result.rule_id,
                    "message": f"Detection rule error: {result.error}",
                }
            )

    return alerts


def handler(event: dict, context: Any) -> dict:
    """Main Lambda handler."""
    check_type = event.get("check_type", "freshness")
    alerts = []

    if check_type == "freshness":
        sources = event.get("sources", list(TABLES.keys()))
        alerts = check_freshness(sources)
    elif check_type == "detections":
        alerts = run_detections(event)

    # Send alerts
    for alert_data in alerts:
        send_alert(alert_data)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "check_type": check_type,
                "alerts_sent": len(alerts),
                "alerts": alerts,
            }
        ),
    }
