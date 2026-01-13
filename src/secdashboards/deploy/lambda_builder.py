"""Lambda function builder for detection rules."""

import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import boto3
from jinja2 import Template

from secdashboards.detections.rule import DetectionRule

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
                        "Severity": rule.metadata.severity,
                    },
                },
            }

        return template

    def write_sam_template(self, template: dict[str, Any], output_path: Path) -> None:
        """Write SAM template to file."""
        import yaml

        with output_path.open("w") as f:
            yaml.dump(template, f, default_flow_style=False, sort_keys=False)
