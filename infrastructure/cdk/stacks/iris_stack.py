"""Iris Stack — Edge-first architecture for iris.lexicone.com.

Three tiers:
1. CloudFront + S3 — static HTML/CSS/JS frontend (Alpine.js)
2. API Gateway + Lambda — lightweight JSON API (no DuckDB)
3. Health Checker Lambda — scheduled DuckDB+Iceberg queries → DynamoDB cache

Reuses the shared Cognito pool from secdash-web (us-west-2_EgkXXauzP).
"""

from __future__ import annotations

import hashlib
from typing import Any

from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
)
from aws_cdk import (
    aws_certificatemanager as acm,
)
from aws_cdk import (
    aws_cloudfront as cloudfront,
)
from aws_cdk import (
    aws_cloudfront_origins as origins,
)
from aws_cdk import (
    aws_dynamodb as dynamodb,
)
from aws_cdk import (
    aws_events as events,
)
from aws_cdk import (
    aws_events_targets as events_targets,
)
from aws_cdk import (
    aws_iam as iam,
)
from aws_cdk import (
    aws_lambda as lambda_,
)
from aws_cdk import (
    aws_route53 as route53,
)
from aws_cdk import (
    aws_route53_targets as targets,
)
from aws_cdk import (
    aws_s3 as s3,
)
from constructs import Construct


class IrisStack(Stack):
    """Edge-first architecture stack for the iris security dashboard."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        domain_name: str = "iris.lexicone.com",
        hosted_zone_id: str = "",
        certificate_arn: str = "",
        cognito_user_pool_id: str = "",
        cognito_client_id: str = "",
        security_lake_db: str = "amazon_security_lake_glue_db_us_west_2",
        athena_output: str = "s3://aws-athena-query-results-651804262336-us-west-2/",
        api_gateway_id: str = "",
        lambda_package_dir: str = "/tmp/secdash-lambda",
        check_interval_minutes: int = 15,
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # =================================================================
        # DynamoDB — Health Cache Table
        # =================================================================
        health_cache_table = dynamodb.Table(
            self,
            "HealthCacheTable",
            table_name="secdash_health_cache",
            partition_key=dynamodb.Attribute(
                name="source_name",
                type=dynamodb.AttributeType.STRING,
            ),
            sort_key=dynamodb.Attribute(
                name="checked_at",
                type=dynamodb.AttributeType.STRING,
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            time_to_live_attribute="ttl",
        )

        # =================================================================
        # Health Checker Lambda (1024MB — DuckDB + Iceberg)
        # =================================================================
        health_checker = lambda_.Function(
            self,
            "HealthCheckerFunction",
            function_name="secdash-health-checker",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="secdashboards.health.scheduled_checker.handler",
            code=lambda_.Code.from_asset(lambda_package_dir),
            memory_size=1024,
            timeout=Duration.minutes(5),
            environment={
                "SECDASH_SECURITY_LAKE_DB": security_lake_db,
                "SECDASH_ATHENA_OUTPUT": athena_output,
                "SECDASH_HEALTH_CACHE_TABLE": health_cache_table.table_name,
                "SECDASH_USE_DIRECT_QUERY": "true",
            },
        )

        # Grant DynamoDB write access
        health_cache_table.grant_write_data(health_checker)

        # Grant Glue + S3 access for DuckDB Iceberg queries
        health_checker.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "glue:GetTable",
                    "glue:GetTables",
                    "glue:GetDatabase",
                ],
                resources=["*"],
            )
        )
        health_checker.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject", "s3:ListBucket"],
                resources=[
                    "arn:aws:s3:::amazon-security-lake-*",
                    "arn:aws:s3:::amazon-security-lake-*/*",
                ],
            )
        )
        # STS for account ID auto-detection
        health_checker.add_to_role_policy(
            iam.PolicyStatement(
                actions=["sts:GetCallerIdentity"],
                resources=["*"],
            )
        )
        # Athena fallback
        health_checker.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "athena:StartQueryExecution",
                    "athena:GetQueryExecution",
                    "athena:GetQueryResults",
                ],
                resources=["*"],
            )
        )

        # =================================================================
        # EventBridge — Schedule health checks every N minutes
        # =================================================================
        events.Rule(
            self,
            "HealthCheckSchedule",
            rule_name="secdash-iris-health-check",
            description=f"Run iris health checks every {check_interval_minutes} minutes",
            schedule=events.Schedule.rate(Duration.minutes(check_interval_minutes)),
            targets=[events_targets.LambdaFunction(health_checker)],
        )

        # =================================================================
        # S3 — Static Frontend Bucket
        # =================================================================
        bucket_suffix = hashlib.sha256(
            f"iris-frontend-{self.account}-{self.region}".encode()
        ).hexdigest()[:12]

        frontend_bucket = s3.Bucket(
            self,
            "FrontendBucket",
            bucket_name=f"iris-frontend-{bucket_suffix}",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        # =================================================================
        # CloudFront Distribution
        # =================================================================
        oac = cloudfront.S3OriginAccessControl(
            self,
            "OAC",
            signing=cloudfront.Signing.SIGV4_ALWAYS,
        )

        # Security headers
        security_headers = cloudfront.ResponseHeadersPolicy(
            self,
            "SecurityHeaders",
            response_headers_policy_name="iris-security-headers",
            security_headers_behavior=cloudfront.ResponseSecurityHeadersBehavior(
                content_type_options=cloudfront.ResponseHeadersContentTypeOptions(
                    override=True,
                ),
                frame_options=cloudfront.ResponseHeadersFrameOptions(
                    frame_option=cloudfront.HeadersFrameOption.DENY,
                    override=True,
                ),
                referrer_policy=cloudfront.ResponseHeadersReferrerPolicy(
                    referrer_policy=cloudfront.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
                    override=True,
                ),
                strict_transport_security=cloudfront.ResponseHeadersStrictTransportSecurity(
                    access_control_max_age=Duration.seconds(31536000),
                    include_subdomains=True,
                    preload=True,
                    override=True,
                ),
            ),
        )

        # ACM certificate (must be in us-east-1 for CloudFront)
        certificate = None
        if certificate_arn:
            certificate = acm.Certificate.from_certificate_arn(self, "Certificate", certificate_arn)

        # Build API origin if gateway ID provided
        additional_behaviors: dict[str, cloudfront.BehaviorOptions] = {}
        if api_gateway_id:
            api_origin = origins.HttpOrigin(
                f"{api_gateway_id}.execute-api.{self.region}.amazonaws.com",
            )
            additional_behaviors["/api/*"] = cloudfront.BehaviorOptions(
                origin=api_origin,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            )
            additional_behaviors["/auth/*"] = cloudfront.BehaviorOptions(
                origin=api_origin,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            )

        distribution = cloudfront.Distribution(
            self,
            "Distribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(
                    frontend_bucket,
                    origin_access_control=oac,
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
                response_headers_policy=security_headers,
            ),
            additional_behaviors=additional_behaviors if additional_behaviors else None,
            default_root_object="index.html",
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
            domain_names=[domain_name] if domain_name and certificate else None,
            certificate=certificate,
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=403,
                    response_page_path="/index.html",
                    response_http_status=200,
                ),
                cloudfront.ErrorResponse(
                    http_status=404,
                    response_page_path="/index.html",
                    response_http_status=200,
                ),
            ],
        )

        # Route53 alias record
        if domain_name and hosted_zone_id:
            zone_name = domain_name.split(".", 1)[1] if "." in domain_name else domain_name
            hosted_zone = route53.HostedZone.from_hosted_zone_attributes(
                self,
                "HostedZone",
                hosted_zone_id=hosted_zone_id,
                zone_name=zone_name,
            )
            route53.ARecord(
                self,
                "DnsRecord",
                zone=hosted_zone,
                record_name=domain_name,
                target=route53.RecordTarget.from_alias(targets.CloudFrontTarget(distribution)),
            )

        # =================================================================
        # Outputs
        # =================================================================
        CfnOutput(
            self,
            "FrontendBucketName",
            value=frontend_bucket.bucket_name,
            description="S3 bucket for iris static frontend",
        )

        CfnOutput(
            self,
            "DistributionDomainName",
            value=distribution.distribution_domain_name,
            description="CloudFront distribution domain",
        )

        CfnOutput(
            self,
            "DistributionId",
            value=distribution.distribution_id,
            description="CloudFront distribution ID (for cache invalidation)",
        )

        CfnOutput(
            self,
            "HealthCacheTableName",
            value=health_cache_table.table_name,
            description="DynamoDB health cache table name",
        )

        CfnOutput(
            self,
            "HealthCheckerArn",
            value=health_checker.function_arn,
            description="Health checker Lambda ARN",
        )
