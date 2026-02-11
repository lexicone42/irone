"""Tests for the DetectionRules CDK Stack.

Uses CDK assertions to validate CloudFormation output without deploying.
Run with: uv run pytest infrastructure/cdk/tests/ -v
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import assertions
from stacks.detection_rules import DetectionRulesStack


class TestDetectionRulesStack:
    """Tests for DetectionRulesStack CloudFormation output."""

    def _make_stack(
        self, build_dir: str | Path, layer_dir: str | Path, **kwargs
    ) -> assertions.Template:
        app = cdk.App()
        stack = DetectionRulesStack(
            app,
            "TestDetections",
            env=cdk.Environment(account="123456789012", region="us-west-2"),
            build_dir=build_dir,
            notifications_layer_path=layer_dir,
            **kwargs,
        )
        return assertions.Template.from_stack(stack)

    def test_notifications_layer_created(self) -> None:
        """Should create a notifications Lambda layer."""
        with tempfile.TemporaryDirectory() as build_dir, tempfile.TemporaryDirectory() as layer_dir:
            template = self._make_stack(build_dir, layer_dir)

        template.has_resource_properties(
            "AWS::Lambda::LayerVersion",
            {
                "LayerName": "secdash-notifications",
                "CompatibleRuntimes": ["python3.12"],
            },
        )

    def test_no_lambdas_when_build_dir_empty(self) -> None:
        """Should create no Lambda functions when build_dir has no rule packages."""
        with tempfile.TemporaryDirectory() as build_dir, tempfile.TemporaryDirectory() as layer_dir:
            template = self._make_stack(build_dir, layer_dir)

        # Only the layer, no function resources
        template.resource_count_is("AWS::Lambda::Function", 0)

    def test_lambda_per_rule_package(self) -> None:
        """Should create one Lambda function per package_* subdirectory."""
        with tempfile.TemporaryDirectory() as build_dir, tempfile.TemporaryDirectory() as layer_dir:
            # Create two fake rule packages
            (Path(build_dir) / "package_root-login").mkdir()
            (Path(build_dir) / "package_root-login" / "handler.py").write_text(
                "def handler(e,c): pass"
            )
            (Path(build_dir) / "package_iam-changes").mkdir()
            (Path(build_dir) / "package_iam-changes" / "handler.py").write_text(
                "def handler(e,c): pass"
            )

            template = self._make_stack(build_dir, layer_dir)

        template.resource_count_is("AWS::Lambda::Function", 2)

    def test_lambda_has_correct_configuration(self) -> None:
        """Each detection Lambda should have correct runtime and handler."""
        with tempfile.TemporaryDirectory() as build_dir, tempfile.TemporaryDirectory() as layer_dir:
            (Path(build_dir) / "package_test-rule").mkdir()
            (Path(build_dir) / "package_test-rule" / "handler.py").write_text(
                "def handler(e,c): pass"
            )

            template = self._make_stack(build_dir, layer_dir)

        template.has_resource_properties(
            "AWS::Lambda::Function",
            {
                "FunctionName": "secdash-detection-test-rule",
                "Runtime": "python3.12",
                "Handler": "handler.handler",
                "MemorySize": 256,
                "Timeout": 300,
            },
        )

    def test_lambda_environment_variables(self) -> None:
        """Lambda should receive database and output location env vars."""
        with tempfile.TemporaryDirectory() as build_dir, tempfile.TemporaryDirectory() as layer_dir:
            (Path(build_dir) / "package_test-rule").mkdir()
            (Path(build_dir) / "package_test-rule" / "handler.py").write_text(
                "def handler(e,c): pass"
            )

            template = self._make_stack(
                build_dir,
                layer_dir,
                security_lake_db="my_test_db",
                athena_output="s3://my-output-bucket/",
                slack_webhook_url="https://hooks.slack.com/test",
            )

        template.has_resource_properties(
            "AWS::Lambda::Function",
            {
                "Environment": {
                    "Variables": assertions.Match.object_like(
                        {
                            "ATHENA_DATABASE": "my_test_db",
                            "ATHENA_OUTPUT_LOCATION": "s3://my-output-bucket/",
                            "SLACK_WEBHOOK_URL": "https://hooks.slack.com/test",
                        }
                    )
                }
            },
        )

    def test_eventbridge_schedule_per_rule(self) -> None:
        """Should create an EventBridge schedule for each detection Lambda."""
        with tempfile.TemporaryDirectory() as build_dir, tempfile.TemporaryDirectory() as layer_dir:
            (Path(build_dir) / "package_test-rule").mkdir()
            (Path(build_dir) / "package_test-rule" / "handler.py").write_text(
                "def handler(e,c): pass"
            )

            template = self._make_stack(build_dir, layer_dir, schedule_rate_minutes=30)

        template.has_resource_properties(
            "AWS::Events::Rule",
            {
                "Name": "secdash-schedule-test-rule",
                "ScheduleExpression": "rate(30 minutes)",
            },
        )

    def test_lambda_has_athena_permissions(self) -> None:
        """Detection Lambdas should have Athena permissions."""
        with tempfile.TemporaryDirectory() as build_dir, tempfile.TemporaryDirectory() as layer_dir:
            (Path(build_dir) / "package_test-rule").mkdir()
            (Path(build_dir) / "package_test-rule" / "handler.py").write_text(
                "def handler(e,c): pass"
            )

            template = self._make_stack(build_dir, layer_dir)

        template.has_resource_properties(
            "AWS::IAM::Policy",
            {
                "PolicyDocument": {
                    "Statement": assertions.Match.array_with(
                        [
                            assertions.Match.object_like(
                                {
                                    "Action": assertions.Match.array_with(
                                        ["athena:StartQueryExecution"]
                                    ),
                                    "Effect": "Allow",
                                }
                            )
                        ]
                    )
                }
            },
        )

    def test_notifications_layer_arn_exported(self) -> None:
        """Should export the notifications layer ARN."""
        with tempfile.TemporaryDirectory() as build_dir, tempfile.TemporaryDirectory() as layer_dir:
            template = self._make_stack(build_dir, layer_dir)

        template.has_output(
            "NotificationsLayerArn",
            {"Export": {"Name": "TestDetections-NotificationsLayerArn"}},
        )

    def test_nonexistent_build_dir_creates_no_lambdas(self) -> None:
        """Should handle non-existent build directory gracefully."""
        with tempfile.TemporaryDirectory() as layer_dir:
            template = self._make_stack("/nonexistent/path", layer_dir)

        template.resource_count_is("AWS::Lambda::Function", 0)

    def test_log_groups_created_per_rule(self) -> None:
        """Should create a log group for each detection Lambda."""
        with tempfile.TemporaryDirectory() as build_dir, tempfile.TemporaryDirectory() as layer_dir:
            (Path(build_dir) / "package_test-rule").mkdir()
            (Path(build_dir) / "package_test-rule" / "handler.py").write_text(
                "def handler(e,c): pass"
            )

            template = self._make_stack(build_dir, layer_dir)

        template.has_resource_properties(
            "AWS::Logs::LogGroup",
            {
                "LogGroupName": "/aws/lambda/secdash-detection-test-rule",
                "RetentionInDays": 14,
            },
        )
