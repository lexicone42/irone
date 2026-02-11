"""Tests for the Alerting CDK Stack.

Uses CDK assertions to validate CloudFormation output without deploying.
Run with: uv run pytest infrastructure/cdk/tests/ -v
"""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import assertions
from stacks.alerting import AlertingStack


class TestAlertingStack:
    """Tests for AlertingStack CloudFormation output."""

    def _make_stack(self, **kwargs) -> assertions.Template:
        app = cdk.App()
        stack = AlertingStack(
            app,
            "TestAlerting",
            env=cdk.Environment(account="123456789012", region="us-west-2"),
            **kwargs,
        )
        return assertions.Template.from_stack(stack)

    def test_sns_topics_created(self) -> None:
        """Should create alerts and critical alerts SNS topics."""
        template = self._make_stack()

        template.has_resource_properties(
            "AWS::SNS::Topic",
            {"TopicName": "secdash-alerts"},
        )
        template.has_resource_properties(
            "AWS::SNS::Topic",
            {"TopicName": "secdash-critical-alerts"},
        )

    def test_email_subscription_when_configured(self) -> None:
        """Should add email subscription when alert_email is provided."""
        template = self._make_stack(alert_email="alerts@example.com")

        template.has_resource_properties(
            "AWS::SNS::Subscription",
            {
                "Protocol": "email",
                "Endpoint": "alerts@example.com",
            },
        )

    def test_lambda_function_created(self) -> None:
        """Alerting Lambda should be created with correct configuration."""
        template = self._make_stack()

        template.has_resource_properties(
            "AWS::Lambda::Function",
            {
                "FunctionName": "secdash-alerting",
                "Runtime": "python3.12",
                "Handler": "alerting_handler.handler",
                "MemorySize": 512,
                "Timeout": 300,
            },
        )

    def test_lambda_environment_variables(self) -> None:
        """Lambda should have correct environment variables."""
        template = self._make_stack(
            security_lake_db="test_db",
            freshness_threshold_minutes=30,
        )

        template.has_resource_properties(
            "AWS::Lambda::Function",
            {
                "Environment": {
                    "Variables": assertions.Match.object_like(
                        {
                            "SECURITY_LAKE_DB": "test_db",
                            "FRESHNESS_THRESHOLD_MINUTES": "30",
                        }
                    )
                }
            },
        )

    def test_eventbridge_freshness_rule(self) -> None:
        """Should create EventBridge rule for freshness checks."""
        template = self._make_stack(check_interval_minutes=30)

        template.has_resource_properties(
            "AWS::Events::Rule",
            {
                "Name": "secdash-freshness-check",
                "ScheduleExpression": "rate(30 minutes)",
            },
        )

    def test_eventbridge_detection_rule(self) -> None:
        """Should create EventBridge rule for detection checks."""
        template = self._make_stack()

        template.has_resource_properties(
            "AWS::Events::Rule",
            {
                "Name": "secdash-detection-check",
                "ScheduleExpression": "rate(15 minutes)",
            },
        )

    def test_cfn_outputs_exported(self) -> None:
        """Should export topic ARNs as CloudFormation outputs."""
        template = self._make_stack()

        template.has_output(
            "AlertsTopicArn",
            {"Export": {"Name": "TestAlerting-AlertsTopicArn"}},
        )
        template.has_output(
            "CriticalTopicArn",
            {"Export": {"Name": "TestAlerting-CriticalTopicArn"}},
        )
