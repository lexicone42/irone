"""Tests for the IrisStack CDK stack (edge-first architecture)."""

import pytest

cdk = pytest.importorskip("aws_cdk")
from aws_cdk.assertions import Match, Template  # noqa: E402

from infrastructure.cdk.stacks.iris_stack import IrisStack  # noqa: E402


def _synth(*, api_gateway_id: str = "", **kwargs) -> Template:
    """Synthesize the IrisStack and return a Template for assertions."""
    app = cdk.App()
    stack = IrisStack(
        app,
        "TestIrisStack",
        api_gateway_id=api_gateway_id,
        env=cdk.Environment(account="123456789012", region="us-west-2"),
        **kwargs,
    )
    return Template.from_stack(stack)


class TestDynamoDB:
    def test_health_cache_table_created(self) -> None:
        template = _synth()
        template.has_resource_properties(
            "AWS::DynamoDB::Table",
            {
                "TableName": "secdash_health_cache",
                "BillingMode": "PAY_PER_REQUEST",
                "KeySchema": Match.array_with(
                    [
                        {"AttributeName": "source_name", "KeyType": "HASH"},
                        {"AttributeName": "checked_at", "KeyType": "RANGE"},
                    ]
                ),
                "TimeToLiveSpecification": {
                    "AttributeName": "ttl",
                    "Enabled": True,
                },
            },
        )


class TestHealthCheckerLambda:
    def test_lambda_function_created(self) -> None:
        template = _synth()
        template.has_resource_properties(
            "AWS::Lambda::Function",
            {
                "FunctionName": "secdash-health-checker",
                "Runtime": "python3.13",
                "MemorySize": 1024,
                "Timeout": 300,
                "Handler": "secdashboards.health.scheduled_checker.handler",
            },
        )

    def test_lambda_has_required_env_vars(self) -> None:
        template = _synth()
        template.has_resource_properties(
            "AWS::Lambda::Function",
            {
                "Environment": {
                    "Variables": Match.object_like(
                        {
                            "SECDASH_SECURITY_LAKE_DB": Match.any_value(),
                            "SECDASH_HEALTH_CACHE_TABLE": "secdash_health_cache",
                            "SECDASH_USE_DIRECT_QUERY": "true",
                        }
                    )
                }
            },
        )

    def test_lambda_has_dynamodb_write_policy(self) -> None:
        template = _synth()
        template.has_resource_properties(
            "AWS::IAM::Policy",
            {
                "PolicyDocument": {
                    "Statement": Match.array_with(
                        [
                            Match.object_like(
                                {
                                    "Action": Match.array_with(["dynamodb:PutItem"]),
                                    "Effect": "Allow",
                                }
                            )
                        ]
                    )
                }
            },
        )

    def test_lambda_has_glue_policy(self) -> None:
        template = _synth()
        template.has_resource_properties(
            "AWS::IAM::Policy",
            {
                "PolicyDocument": {
                    "Statement": Match.array_with(
                        [
                            Match.object_like(
                                {
                                    "Action": Match.array_with(
                                        [
                                            "glue:GetTable",
                                            "glue:GetTables",
                                            "glue:GetDatabase",
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


class TestEventBridge:
    def test_schedule_rule_created(self) -> None:
        template = _synth()
        template.has_resource_properties(
            "AWS::Events::Rule",
            {
                "ScheduleExpression": "rate(15 minutes)",
                "State": "ENABLED",
            },
        )

    def test_custom_interval(self) -> None:
        template = _synth(check_interval_minutes=30)
        template.has_resource_properties(
            "AWS::Events::Rule",
            {
                "ScheduleExpression": "rate(30 minutes)",
            },
        )


class TestS3Frontend:
    def test_frontend_bucket_created(self) -> None:
        template = _synth()
        template.has_resource_properties(
            "AWS::S3::Bucket",
            {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "BlockPublicPolicy": True,
                    "IgnorePublicAcls": True,
                    "RestrictPublicBuckets": True,
                },
            },
        )


class TestCloudFront:
    def test_distribution_created(self) -> None:
        template = _synth()
        template.has_resource_properties(
            "AWS::CloudFront::Distribution",
            {
                "DistributionConfig": Match.object_like(
                    {
                        "DefaultRootObject": "index.html",
                        "PriceClass": "PriceClass_100",
                    }
                )
            },
        )

    def test_security_headers_policy(self) -> None:
        template = _synth()
        template.has_resource_properties(
            "AWS::CloudFront::ResponseHeadersPolicy",
            {
                "ResponseHeadersPolicyConfig": Match.object_like(
                    {
                        "SecurityHeadersConfig": Match.object_like(
                            {
                                "ContentTypeOptions": {"Override": True},
                                "FrameOptions": {
                                    "FrameOption": "DENY",
                                    "Override": True,
                                },
                                "StrictTransportSecurity": Match.object_like(
                                    {
                                        "IncludeSubdomains": True,
                                        "Preload": True,
                                        "Override": True,
                                    }
                                ),
                            }
                        )
                    }
                )
            },
        )

    def test_api_gateway_behaviors_when_provided(self) -> None:
        template = _synth(api_gateway_id="abc123def")
        template.has_resource_properties(
            "AWS::CloudFront::Distribution",
            {
                "DistributionConfig": Match.object_like(
                    {
                        "CacheBehaviors": Match.array_with(
                            [
                                Match.object_like({"PathPattern": "/api/*"}),
                                Match.object_like({"PathPattern": "/auth/*"}),
                            ]
                        )
                    }
                )
            },
        )

    def test_spa_error_responses(self) -> None:
        template = _synth()
        template.has_resource_properties(
            "AWS::CloudFront::Distribution",
            {
                "DistributionConfig": Match.object_like(
                    {
                        "CustomErrorResponses": Match.array_with(
                            [
                                Match.object_like(
                                    {
                                        "ErrorCode": 403,
                                        "ResponseCode": 200,
                                        "ResponsePagePath": "/index.html",
                                    }
                                ),
                                Match.object_like(
                                    {
                                        "ErrorCode": 404,
                                        "ResponseCode": 200,
                                        "ResponsePagePath": "/index.html",
                                    }
                                ),
                            ]
                        )
                    }
                )
            },
        )


class TestOutputs:
    def test_outputs_exist(self) -> None:
        template = _synth()
        template.has_output("FrontendBucketName", {})
        template.has_output("DistributionDomainName", {})
        template.has_output("DistributionId", {})
        template.has_output("HealthCacheTableName", {})
        template.has_output("HealthCheckerArn", {})
