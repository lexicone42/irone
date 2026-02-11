"""Lambda function builder for detection rules."""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import boto3
from jinja2 import Template

from secdashboards.detections.rule import DetectionRule

if TYPE_CHECKING:
    from secdashboards.detections.rule import DualTargetDetectionRule

# Lambda handler template
LAMBDA_HANDLER_TEMPLATE = '''"""Auto-generated Lambda handler for detection: {{ rule_id }}"""

import json
import os
from datetime import UTC, datetime, timedelta

import boto3

# Detection configuration
RULE_ID = "{{ rule_id }}"
RULE_NAME = "{{ rule_name }}"
SEVERITY = "{{ severity }}"
DATA_SOURCE = "{{ data_source }}"
THRESHOLD = {{ threshold }}
LOOKBACK_MINUTES = {{ lookback_minutes }}

# Query template
QUERY_TEMPLATE = """{{ query_template }}"""


def get_athena_client():
    return boto3.client("athena", region_name=os.environ.get("AWS_REGION", "us-west-2"))


def get_sns_client():
    return boto3.client("sns", region_name=os.environ.get("AWS_REGION", "us-west-2"))


def execute_query(athena, query: str, database: str, output_location: str) -> list[dict]:
    """Execute Athena query and return results."""
    response = athena.start_query_execution(
        QueryString=query,
        QueryExecutionContext={"Database": database},
        ResultConfiguration={"OutputLocation": output_location},
    )

    query_execution_id = response["QueryExecutionId"]

    # Wait for completion
    while True:
        result = athena.get_query_execution(QueryExecutionId=query_execution_id)
        state = result["QueryExecution"]["Status"]["State"]

        if state == "SUCCEEDED":
            break
        elif state in ("FAILED", "CANCELLED"):
            reason = result["QueryExecution"]["Status"].get("StateChangeReason")
            raise RuntimeError(f"Query {state}: {reason}")

        import time
        time.sleep(1)

    # Get results
    results = []
    paginator = athena.get_paginator("get_query_results")

    for page in paginator.paginate(QueryExecutionId=query_execution_id):
        columns = [col["Name"] for col in page["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]]

        for row in page["ResultSet"]["Rows"][1:]:  # Skip header
            values = [field.get("VarCharValue", "") for field in row["Data"]]
            results.append(dict(zip(columns, values)))

    return results


def handler(event, context):
    """Lambda handler for detection rule execution."""
    print(f"Running detection: {RULE_NAME} ({RULE_ID})")

    # Configuration from environment
    database = os.environ.get("ATHENA_DATABASE", "amazon_security_lake_glue_db_us_east_1")
    output_location = os.environ.get("ATHENA_OUTPUT_LOCATION", "s3://aws-athena-query-results/")
    sns_topic_arn = os.environ.get("SNS_TOPIC_ARN")

    # Calculate time window
    end_time = datetime.now(UTC)
    start_time = end_time - timedelta(minutes=LOOKBACK_MINUTES)

    # Render query
    query = QUERY_TEMPLATE.format(
        start_time=start_time.isoformat(),
        end_time=end_time.isoformat(),
    )

    print(f"Executing query: {query[:200]}...")

    try:
        athena = get_athena_client()
        results = execute_query(athena, query, database, output_location)

        match_count = len(results)
        triggered = match_count >= THRESHOLD

        print(f"Detection results: {match_count} matches, triggered={triggered}")

        # Send alert if triggered
        if triggered and sns_topic_arn:
            sns = get_sns_client()

            alert = {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "match_count": match_count,
                "threshold": THRESHOLD,
                "time_window": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                },
                "sample_matches": results[:5],
                "triggered_at": datetime.now(UTC).isoformat(),
            }

            sns.publish(
                TopicArn=sns_topic_arn,
                Subject=f"[{SEVERITY.upper()}] Security Detection: {RULE_NAME}",
                Message=json.dumps(alert, indent=2),
            )
            print(f"Alert sent to {sns_topic_arn}")

        return {
            "statusCode": 200,
            "body": json.dumps({
                "rule_id": RULE_ID,
                "triggered": triggered,
                "match_count": match_count,
            }),
        }

    except Exception as e:
        print(f"Detection failed: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }
'''


class LambdaBuilder:
    """Builds Lambda deployment packages for detection rules."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._lambda_client = None
        self._iam_client = None

    @property
    def lambda_client(self) -> Any:
        if not self._lambda_client:
            self._lambda_client = boto3.client("lambda")
        return self._lambda_client

    @property
    def iam_client(self) -> Any:
        if not self._iam_client:
            self._iam_client = boto3.client("iam")
        return self._iam_client

    def build_handler(
        self,
        rule: DetectionRule,
        data_source: str,
        lookback_minutes: int = 15,
    ) -> Path:
        """Generate Lambda handler code for a detection rule."""
        template = Template(LAMBDA_HANDLER_TEMPLATE)

        # Get query template if SQLDetectionRule
        query_template = ""
        threshold = 1
        if hasattr(rule, "query_template") and hasattr(rule, "threshold"):
            query_template = rule.query_template
            threshold = rule.threshold

        handler_code = template.render(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.metadata.severity,
            data_source=data_source,
            threshold=threshold,
            lookback_minutes=lookback_minutes,
            query_template=query_template,
        )

        handler_path = self.output_dir / f"handler_{rule.id}.py"
        handler_path.write_text(handler_code)

        return handler_path

    def build_package(
        self,
        rule: DetectionRule,
        data_source: str,
        lookback_minutes: int = 15,
        include_dependencies: bool = False,
    ) -> Path:
        """Build a complete Lambda deployment package."""
        # Create handler
        handler_path = self.build_handler(rule, data_source, lookback_minutes)

        # Create zip package
        package_dir = self.output_dir / f"package_{rule.id}"
        package_dir.mkdir(exist_ok=True)

        # Copy handler
        shutil.copy(handler_path, package_dir / "handler.py")

        # Optionally install dependencies
        if include_dependencies:
            subprocess.run(
                ["pip", "install", "boto3", "-t", str(package_dir), "--quiet"],
                check=True,
            )

        # Create zip
        zip_path = self.output_dir / f"detection_{rule.id}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in package_dir.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(package_dir)
                    zf.write(file_path, arcname)

        return zip_path

    def deploy_lambda(
        self,
        rule: DetectionRule,
        package_path: Path,
        role_arn: str,
        environment: dict[str, str] | None = None,
        memory_mb: int = 256,
        timeout_seconds: int = 300,
    ) -> dict[str, Any]:
        """Deploy or update a Lambda function."""
        function_name = f"secdash-detection-{rule.id}"

        env_vars = {
            "RULE_ID": rule.id,
            "RULE_NAME": rule.name,
        }
        if environment:
            env_vars.update(environment)

        with package_path.open("rb") as f:
            zip_content = f.read()

        try:
            # Try to update existing function
            response = self.lambda_client.update_function_code(
                FunctionName=function_name,
                ZipFile=zip_content,
            )

            # Update configuration
            self.lambda_client.update_function_configuration(
                FunctionName=function_name,
                Runtime="python3.12",
                Handler="handler.handler",
                MemorySize=memory_mb,
                Timeout=timeout_seconds,
                Environment={"Variables": env_vars},
            )

        except self.lambda_client.exceptions.ResourceNotFoundException:
            # Create new function
            response = self.lambda_client.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": zip_content},
                MemorySize=memory_mb,
                Timeout=timeout_seconds,
                Environment={"Variables": env_vars},
                Tags={
                    "Application": "secdashboards",
                    "RuleId": rule.id,
                },
            )

        return {
            "function_name": function_name,
            "function_arn": response["FunctionArn"],
            "rule_id": rule.id,
        }

    def generate_sam_template(
        self,
        rules: list[DetectionRule],
        data_source: str,
        role_arn: str | None = None,
        sns_topic_arn: str | None = None,
    ) -> dict[str, Any]:
        """Generate a SAM template for deploying detection rules."""
        template: dict[str, Any] = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Transform": "AWS::Serverless-2016-10-31",
            "Description": "Security Detection Rules - Generated by secdashboards",
            "Parameters": {
                "AthenaDatabase": {
                    "Type": "String",
                    "Default": "amazon_security_lake_glue_db_us_east_1",
                },
                "AthenaOutputLocation": {
                    "Type": "String",
                    "Default": "s3://aws-athena-query-results/",
                },
                "SnsTopicArn": {
                    "Type": "String",
                    "Default": sns_topic_arn or "",
                },
            },
            "Resources": {},
        }

        for rule in rules:
            safe_name = rule.id.replace("-", "").replace("_", "").title()

            # Lambda function
            template["Resources"][f"Detection{safe_name}Function"] = {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "FunctionName": f"secdash-detection-{rule.id}",
                    "CodeUri": f"./package_{rule.id}/",
                    "Handler": "handler.handler",
                    "Runtime": "python3.12",
                    "MemorySize": 256,
                    "Timeout": 300,
                    "Environment": {
                        "Variables": {
                            "ATHENA_DATABASE": {"Ref": "AthenaDatabase"},
                            "ATHENA_OUTPUT_LOCATION": {"Ref": "AthenaOutputLocation"},
                            "SNS_TOPIC_ARN": {"Ref": "SnsTopicArn"},
                        }
                    },
                    "Policies": [
                        "AmazonAthenaFullAccess",
                        "AmazonS3ReadOnlyAccess",
                        "AmazonSNSFullAccess",
                    ],
                    "Events": {
                        "ScheduleEvent": {
                            "Type": "Schedule",
                            "Properties": {
                                "Schedule": rule.metadata.schedule,
                                "Enabled": rule.metadata.enabled,
                            },
                        }
                    },
                    "Tags": {
                        "Application": "secdashboards",
                        "RuleId": rule.id,
                        "Severity": str(rule.metadata.severity),
                    },
                },
            }

        return template

    def write_sam_template(self, template: dict[str, Any], output_path: Path) -> None:
        """Write SAM template to file."""
        import yaml

        with output_path.open("w") as f:
            yaml.dump(template, f, default_flow_style=False, sort_keys=False)


# Dual-target Lambda handler template for CloudWatch + Athena
DUAL_TARGET_LAMBDA_TEMPLATE = '''"""Auto-generated dual-target handler: {{ rule_id }}

Supports querying both:
- CloudWatch Logs Insights (hot tier, recent data)
- Athena/Security Lake (cold tier, historical data)
"""

import json
import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3

# Detection configuration
RULE_ID = "{{ rule_id }}"
RULE_NAME = "{{ rule_name }}"
SEVERITY = "{{ severity }}"
THRESHOLD = {{ threshold }}
LOOKBACK_MINUTES = {{ lookback_minutes }}

# Query templates for each target
CLOUDWATCH_QUERY = """{{ cloudwatch_query }}"""
ATHENA_QUERY = """{{ athena_query }}"""

# Log groups for CloudWatch Logs Insights
LOG_GROUPS = {{ log_groups }}


def get_logs_client():
    return boto3.client("logs", region_name=os.environ.get("AWS_REGION", "us-west-2"))


def get_athena_client():
    return boto3.client("athena", region_name=os.environ.get("AWS_REGION", "us-west-2"))


def get_sns_client():
    return boto3.client("sns", region_name=os.environ.get("AWS_REGION", "us-west-2"))


def execute_cloudwatch_query(
    logs_client, query: str, log_groups: list, start: datetime, end: datetime
) -> list[dict]:
    """Execute CloudWatch Logs Insights query."""
    if not log_groups:
        print("No log groups configured for CloudWatch query")
        return []

    response = logs_client.start_query(
        logGroupNames=log_groups,
        startTime=int(start.timestamp() * 1000),
        endTime=int(end.timestamp() * 1000),
        queryString=query,
    )
    query_id = response["queryId"]

    # Poll for results
    timeout = 60
    start_time = time.time()
    while time.time() - start_time < timeout:
        result = logs_client.get_query_results(queryId=query_id)
        status = result.get("status")

        if status == "Complete":
            # Parse results
            rows = []
            for row_data in result.get("results", []):
                row = {}
                for field in row_data:
                    if field.get("field") != "@ptr":
                        row[field.get("field", "unknown")] = field.get("value")
                rows.append(row)
            return rows
        elif status in ("Failed", "Cancelled", "Timeout"):
            print(f"CloudWatch query failed: {status}")
            return []

        time.sleep(1)

    print("CloudWatch query timed out")
    return []


def execute_athena_query(
    athena_client, query: str, database: str, output_location: str
) -> list[dict]:
    """Execute Athena query and return results."""
    response = athena_client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={"Database": database},
        ResultConfiguration={"OutputLocation": output_location},
    )
    query_execution_id = response["QueryExecutionId"]

    # Wait for completion
    timeout = 300
    start_time = time.time()
    while time.time() - start_time < timeout:
        result = athena_client.get_query_execution(QueryExecutionId=query_execution_id)
        state = result["QueryExecution"]["Status"]["State"]

        if state == "SUCCEEDED":
            break
        elif state in ("FAILED", "CANCELLED"):
            reason = result["QueryExecution"]["Status"].get("StateChangeReason")
            print(f"Athena query {state}: {reason}")
            return []

        time.sleep(2)

    # Get results
    results = []
    paginator = athena_client.get_paginator("get_query_results")

    for page in paginator.paginate(QueryExecutionId=query_execution_id):
        columns = [col["Name"] for col in page["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]]

        for row in page["ResultSet"]["Rows"][1:]:  # Skip header
            values = [field.get("VarCharValue", "") for field in row["Data"]]
            results.append(dict(zip(columns, values)))

    return results


def send_alert(sns_client, topic_arn: str, results: list[dict], target: str) -> None:
    """Send alert to SNS topic."""
    alert = {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": SEVERITY,
        "target": target,
        "match_count": len(results),
        "threshold": THRESHOLD,
        "triggered_at": datetime.now(UTC).isoformat(),
        "sample_matches": results[:5],
    }

    sns_client.publish(
        TopicArn=topic_arn,
        Subject=f"[{SEVERITY.upper()}] Security Detection: {RULE_NAME}",
        Message=json.dumps(alert, indent=2),
    )
    print(f"Alert sent to {topic_arn}")


def handler(event, context):
    """Lambda handler for dual-target detection rule execution.

    Event parameters:
    - target: "cloudwatch", "athena", or "both" (default: "both")
    - lookback_minutes: Override default lookback window
    """
    print(f"Running detection: {RULE_NAME} ({RULE_ID})")

    # Configuration from environment
    database = os.environ.get("ATHENA_DATABASE", "amazon_security_lake_glue_db_us_west_2")
    output_location = os.environ.get("ATHENA_OUTPUT_LOCATION", "s3://aws-athena-query-results/")
    sns_topic_arn = os.environ.get("SNS_TOPIC_ARN")

    # Get target from event or default to both
    target = event.get("target", "both")
    lookback = event.get("lookback_minutes", LOOKBACK_MINUTES)

    # Calculate time window
    end_time = datetime.now(UTC)
    start_time = end_time - timedelta(minutes=lookback)

    results_summary = {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "targets_executed": [],
        "total_matches": 0,
        "triggered": False,
    }

    # Execute CloudWatch query if requested
    if target in ("cloudwatch", "both") and CLOUDWATCH_QUERY.strip():
        try:
            logs_client = get_logs_client()
            cw_results = execute_cloudwatch_query(
                logs_client, CLOUDWATCH_QUERY, LOG_GROUPS, start_time, end_time
            )
            match_count = len(cw_results)
            triggered = match_count >= THRESHOLD

            print(f"CloudWatch results: {match_count} matches, triggered={triggered}")

            results_summary["targets_executed"].append({
                "target": "cloudwatch",
                "match_count": match_count,
                "triggered": triggered,
            })
            results_summary["total_matches"] += match_count

            if triggered:
                results_summary["triggered"] = True
                if sns_topic_arn:
                    sns_client = get_sns_client()
                    send_alert(sns_client, sns_topic_arn, cw_results, "cloudwatch")

        except Exception as e:
            print(f"CloudWatch query failed: {e}")
            results_summary["targets_executed"].append({
                "target": "cloudwatch",
                "error": str(e),
            })

    # Execute Athena query if requested
    if target in ("athena", "both") and ATHENA_QUERY.strip():
        try:
            # Format query with time parameters
            formatted_query = ATHENA_QUERY.format(
                start_time=start_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
                end_time=end_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
                database=database,
            )

            athena_client = get_athena_client()
            athena_results = execute_athena_query(
                athena_client, formatted_query, database, output_location
            )
            match_count = len(athena_results)
            triggered = match_count >= THRESHOLD

            print(f"Athena results: {match_count} matches, triggered={triggered}")

            results_summary["targets_executed"].append({
                "target": "athena",
                "match_count": match_count,
                "triggered": triggered,
            })
            results_summary["total_matches"] += match_count

            if triggered:
                results_summary["triggered"] = True
                if sns_topic_arn:
                    sns_client = get_sns_client()
                    send_alert(sns_client, sns_topic_arn, athena_results, "athena")

        except Exception as e:
            print(f"Athena query failed: {e}")
            results_summary["targets_executed"].append({
                "target": "athena",
                "error": str(e),
            })

    return {
        "statusCode": 200,
        "body": json.dumps(results_summary),
    }
'''


class DualTargetLambdaBuilder(LambdaBuilder):
    """Builds Lambda deployment packages for dual-target detection rules."""

    def build_dual_target_handler(
        self,
        rule_id: str,
        rule_name: str,
        severity: str,
        cloudwatch_query: str,
        athena_query: str,
        log_groups: list[str],
        threshold: int = 1,
        lookback_minutes: int = 15,
    ) -> Path:
        """Generate Lambda handler code for a dual-target detection rule."""
        template = Template(DUAL_TARGET_LAMBDA_TEMPLATE)

        handler_code = template.render(
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            threshold=threshold,
            lookback_minutes=lookback_minutes,
            cloudwatch_query=cloudwatch_query.replace('"""', '\\"\\"\\"'),
            athena_query=athena_query.replace('"""', '\\"\\"\\"'),
            log_groups=log_groups,
        )

        handler_path = self.output_dir / f"handler_{rule_id}.py"
        handler_path.write_text(handler_code)

        return handler_path

    def build_from_dual_rule(
        self,
        rule: DualTargetDetectionRule,  # noqa: F821
        log_groups: list[str],
        lookback_minutes: int = 15,
    ) -> Path:
        """Build handler from a DualTargetDetectionRule."""
        from secdashboards.detections.rule import DualTargetDetectionRule, QueryTarget

        if not isinstance(rule, DualTargetDetectionRule):
            raise TypeError("Expected DualTargetDetectionRule")

        # Get queries for each target (use empty string if not supported)
        cw_query = ""
        athena_query = ""

        if rule.has_target(QueryTarget.CLOUDWATCH):
            cw_query = rule._queries[QueryTarget.CLOUDWATCH]
        if rule.has_target(QueryTarget.ATHENA):
            athena_query = rule._queries[QueryTarget.ATHENA]

        return self.build_dual_target_handler(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.metadata.severity,
            cloudwatch_query=cw_query,
            athena_query=athena_query,
            log_groups=log_groups,
            threshold=rule.threshold,
            lookback_minutes=lookback_minutes,
        )

    def generate_dual_target_sam_template(
        self,
        rules: list[DualTargetDetectionRule],  # noqa: F821
        log_groups_map: dict[str, list[str]],
        sns_topic_arn: str | None = None,
    ) -> dict[str, Any]:
        """Generate SAM template for dual-target detection rules.

        Args:
            rules: List of DualTargetDetectionRule instances
            log_groups_map: Mapping of rule_id to log group list
            sns_topic_arn: SNS topic for alerts
        """
        template: dict[str, Any] = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Transform": "AWS::Serverless-2016-10-31",
            "Description": "Dual-Target Security Detection Rules - Generated by secdashboards",
            "Parameters": {
                "AthenaDatabase": {
                    "Type": "String",
                    "Default": "amazon_security_lake_glue_db_us_west_2",
                },
                "AthenaOutputLocation": {
                    "Type": "String",
                    "Default": "s3://aws-athena-query-results/",
                },
                "SnsTopicArn": {
                    "Type": "String",
                    "Default": sns_topic_arn or "",
                },
            },
            "Resources": {},
        }

        for rule in rules:
            safe_name = rule.id.replace("-", "").replace("_", "").title()
            log_groups_map.get(rule.id, [])

            template["Resources"][f"Detection{safe_name}Function"] = {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "FunctionName": f"secdash-dual-{rule.id}",
                    "CodeUri": f"./package_{rule.id}/",
                    "Handler": "handler.handler",
                    "Runtime": "python3.12",
                    "MemorySize": 256,
                    "Timeout": 300,
                    "Environment": {
                        "Variables": {
                            "ATHENA_DATABASE": {"Ref": "AthenaDatabase"},
                            "ATHENA_OUTPUT_LOCATION": {"Ref": "AthenaOutputLocation"},
                            "SNS_TOPIC_ARN": {"Ref": "SnsTopicArn"},
                        }
                    },
                    "Policies": [
                        "AmazonAthenaFullAccess",
                        "CloudWatchLogsReadOnlyAccess",
                        "AmazonS3ReadOnlyAccess",
                        "AmazonSNSFullAccess",
                    ],
                    "Events": {
                        "ScheduleEvent": {
                            "Type": "Schedule",
                            "Properties": {
                                "Schedule": rule.metadata.schedule,
                                "Enabled": rule.metadata.enabled,
                            },
                        }
                    },
                    "Tags": {
                        "Application": "secdashboards",
                        "RuleId": rule.id,
                        "Severity": str(rule.metadata.severity),
                        "DualTarget": "true",
                    },
                },
            }

        return template
