"""Tests for the Health Dashboard CDK Stack.

Uses CDK assertions to validate CloudFormation output without deploying.
Run with: uv run pytest infrastructure/cdk/tests/ -v
"""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import assertions
from stacks.health_dashboard import HealthDashboardStack


class TestHealthDashboardStack:
    """Tests for HealthDashboardStack CloudFormation output."""

    def test_lambda_function_created(self) -> None:
        """Lambda function should be created with correct configuration."""
        app = cdk.App()
        stack = HealthDashboardStack(
            app,
            "TestStack",
            env=cdk.Environment(account="123456789012", region="us-west-2"),
        )

        template = assertions.Template.from_stack(stack)

        # Verify Lambda function exists with correct runtime
        template.has_resource_properties(
            "AWS::Lambda::Function",
            {
                "Runtime": "python3.12",
                "Handler": "dashboard_handler.handler",
                "Timeout": 300,  # 5 minutes for slow Security Lake queries
                "MemorySize": 512,
            },
        )

    def test_cognito_user_pool_created(self) -> None:
        """Cognito User Pool should be created with passkey support."""
        app = cdk.App()
        stack = HealthDashboardStack(
            app,
            "TestStack",
            env=cdk.Environment(account="123456789012", region="us-west-2"),
        )

        template = assertions.Template.from_stack(stack)

        # Verify User Pool exists
        template.has_resource_properties(
            "AWS::Cognito::UserPool",
            {
                "UserPoolName": "secdash-health-pool",
                "AutoVerifiedAttributes": ["email"],
            },
        )

    def test_api_gateway_created_with_cors(self) -> None:
        """HTTP API should be created with CORS configuration."""
        app = cdk.App()
        stack = HealthDashboardStack(
            app,
            "TestStack",
            env=cdk.Environment(account="123456789012", region="us-west-2"),
        )

        template = assertions.Template.from_stack(stack)

        # Verify API Gateway exists
        template.has_resource_properties(
            "AWS::ApiGatewayV2::Api",
            {
                "Name": "secdash-health-api",
                "ProtocolType": "HTTP",
            },
        )

    def test_s3_buckets_created(self) -> None:
        """S3 buckets for dashboard and cache should be created."""
        app = cdk.App()
        stack = HealthDashboardStack(
            app,
            "TestStack",
            env=cdk.Environment(account="123456789012", region="us-west-2"),
        )

        template = assertions.Template.from_stack(stack)

        # Should have at least 2 S3 buckets (dashboard + cache)
        template.resource_count_is("AWS::S3::Bucket", 2)

    def test_cache_bucket_has_lifecycle_rule(self) -> None:
        """Cache bucket should have lifecycle rule for cleanup."""
        app = cdk.App()
        stack = HealthDashboardStack(
            app,
            "TestStack",
            env=cdk.Environment(account="123456789012", region="us-west-2"),
        )

        template = assertions.Template.from_stack(stack)

        # Find cache bucket with lifecycle rules
        template.has_resource_properties(
            "AWS::S3::Bucket",
            {
                "LifecycleConfiguration": {
                    "Rules": assertions.Match.array_with(
                        [
                            assertions.Match.object_like(
                                {
                                    "ExpirationInDays": 30,
                                    "Status": "Enabled",
                                }
                            )
                        ]
                    )
                }
            },
        )

    def test_eventbridge_rule_created(self) -> None:
        """EventBridge rule for hourly caching should be created."""
        app = cdk.App()
        stack = HealthDashboardStack(
            app,
            "TestStack",
            env=cdk.Environment(account="123456789012", region="us-west-2"),
        )

        template = assertions.Template.from_stack(stack)

        # Verify EventBridge rule exists with hourly schedule
        template.has_resource_properties(
            "AWS::Events::Rule",
            {
                "Name": "secdash-health-hourly-cache",
                "ScheduleExpression": "rate(1 hour)",
            },
        )

    def test_cloudfront_distribution_created(self) -> None:
        """CloudFront distribution should be created."""
        app = cdk.App()
        stack = HealthDashboardStack(
            app,
            "TestStack",
            env=cdk.Environment(account="123456789012", region="us-west-2"),
        )

        template = assertions.Template.from_stack(stack)

        # Verify CloudFront distribution exists
        template.resource_count_is("AWS::CloudFront::Distribution", 1)

    def test_lambda_has_required_permissions(self) -> None:
        """Lambda should have IAM permissions for Athena, S3, CloudWatch, etc."""
        app = cdk.App()
        stack = HealthDashboardStack(
            app,
            "TestStack",
            env=cdk.Environment(account="123456789012", region="us-west-2"),
        )

        template = assertions.Template.from_stack(stack)

        # Verify IAM policy with Athena permissions exists
        template.has_resource_properties(
            "AWS::IAM::Policy",
            {
                "PolicyDocument": {
                    "Statement": assertions.Match.array_with(
                        [
                            assertions.Match.object_like(
                                {
                                    "Action": assertions.Match.array_with(
                                        [
                                            "athena:StartQueryExecution",
                                            "athena:GetQueryExecution",
                                        ]
                                    ),
                                    "Effect": "Allow",
                                }
                            )
                        ]
                    )
                }
            },
        )

    def test_jwt_authorizer_configured(self) -> None:
        """API Gateway should have JWT authorizer for Cognito."""
        app = cdk.App()
        stack = HealthDashboardStack(
            app,
            "TestStack",
            env=cdk.Environment(account="123456789012", region="us-west-2"),
        )

        template = assertions.Template.from_stack(stack)

        # Verify JWT authorizer exists
        template.has_resource_properties(
            "AWS::ApiGatewayV2::Authorizer",
            {
                "AuthorizerType": "JWT",
                "Name": "CognitoAuthorizer",
            },
        )

    def test_api_routes_configured(self) -> None:
        """All required API routes should be configured."""
        app = cdk.App()
        stack = HealthDashboardStack(
            app,
            "TestStack",
            env=cdk.Environment(account="123456789012", region="us-west-2"),
        )

        template = assertions.Template.from_stack(stack)

        # Check for expected routes
        expected_routes = [
            "GET /health",
            "GET /health/sources",
            "GET /health/costs",
            "GET /health/detections",
            "GET /health/history",
            "GET /health/refresh",
        ]

        for route in expected_routes:
            template.has_resource_properties(
                "AWS::ApiGatewayV2::Route",
                {
                    "RouteKey": route,
                    "AuthorizationType": "JWT",
                },
            )

    def test_custom_domain_optional(self) -> None:
        """Stack should work without custom domain configuration."""
        app = cdk.App()

        # Create stack without domain config
        stack = HealthDashboardStack(
            app,
            "TestStack",
            env=cdk.Environment(account="123456789012", region="us-west-2"),
            domain_name="",
            certificate_arn="",
        )

        template = assertions.Template.from_stack(stack)

        # Should still create distribution
        template.resource_count_is("AWS::CloudFront::Distribution", 1)

        # Should NOT create Route53 record
        template.resource_count_is("AWS::Route53::RecordSet", 0)


class TestStackWithCustomDomain:
    """Tests for stack with custom domain configuration."""

    def test_route53_record_created_with_domain(self) -> None:
        """Route53 record should be created when domain is configured."""
        app = cdk.App()

        stack = HealthDashboardStack(
            app,
            "TestStack",
            env=cdk.Environment(account="123456789012", region="us-west-2"),
            domain_name="health.example.com",
            hosted_zone_id="Z1234567890ABC",
            certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/abc-123",
        )

        template = assertions.Template.from_stack(stack)

        # Should create Route53 A record
        template.has_resource_properties(
            "AWS::Route53::RecordSet",
            {
                "Name": "health.example.com.",
                "Type": "A",
            },
        )
