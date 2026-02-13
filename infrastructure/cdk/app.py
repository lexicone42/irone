#!/usr/bin/env python3
"""CDK app entry point for Security Dashboards infrastructure.

Authentication Architecture:
- SharedAuthStack: Centralized Cognito User Pool with passkey support
- HealthDashboardStack: Health monitoring dashboard (uses shared pool or embedded pool)

Passkey-Only Mode:
- Set PASSKEY_ONLY=true to enforce passkey-only authentication
- When enabled, users MUST register a passkey to authenticate
- No password or email OTP fallback allowed

Environment Variables (for multi-account deployment):
    CDK_DEFAULT_ACCOUNT     - AWS account ID (defaults to 651804262336)
    CDK_DEFAULT_REGION      - AWS region (defaults to us-west-2)
    PASSKEY_ONLY            - Enforce passkey-only auth (true/false)
    SLACK_WEBHOOK_URL       - Slack webhook for alerts (optional)
    ADMIN_EMAIL             - Admin email for alerts/user creation
    DOMAIN_NAME             - Custom domain (e.g., health.lexicone.com)
    HOSTED_ZONE_ID          - Route53 hosted zone ID
    CERTIFICATE_ARN         - ACM certificate ARN (must be in us-east-1 for CloudFront)

Deployment:
    cdk deploy --all                    # Deploy all stacks
    cdk deploy secdash-health           # Deploy health dashboard only
    cdk deploy secdash-shared-auth      # Deploy shared auth only
    PASSKEY_ONLY=true cdk deploy        # Deploy with passkey-only mode
"""

from __future__ import annotations

import os

import aws_cdk as cdk
from stacks import (
    AlertingStack,
    DetectionRulesStack,
    FastAPIStack,
    IrisStack,
    SharedAuthStack,
)

app = cdk.App()

# =============================================================================
# Environment Configuration (all from env vars for multi-account support)
# =============================================================================
account = os.environ.get("CDK_DEFAULT_ACCOUNT", "651804262336")
region = os.environ.get("CDK_DEFAULT_REGION", "us-west-2")

# Admin and alerting
admin_email = os.environ.get("ADMIN_EMAIL", "bryan.egan@gmail.com")
slack_webhook = os.environ.get("SLACK_WEBHOOK_URL", "")

# Custom domain configuration
domain_name = os.environ.get("DOMAIN_NAME", "health.lexicone.com")
hosted_zone_id = os.environ.get("HOSTED_ZONE_ID", "ZN8XM06S79WID")
certificate_arn = os.environ.get(
    "CERTIFICATE_ARN",
    f"arn:aws:acm:us-east-1:{account}:certificate/a4c08f34-2a05-4445-830b-059bb2bbe3f1",
)

# Security Lake configuration (auto-construct from account/region)
security_lake_db = os.environ.get(
    "SECURITY_LAKE_DB", f"amazon_security_lake_glue_db_{region.replace('-', '_')}"
)
athena_output = os.environ.get(
    "ATHENA_OUTPUT", f"s3://aws-athena-query-results-{account}-{region}/"
)

# Security settings
passkey_only = os.environ.get("PASSKEY_ONLY", "false").lower() == "true"

# API Gateway URL (set after first deploy, used for Cognito callback URLs)
api_gateway_url = os.environ.get("API_GATEWAY_URL", "")

env = cdk.Environment(account=account, region=region)

# =============================================================================
# Shared Authentication Stack
# =============================================================================
shared_auth = SharedAuthStack(
    app,
    "secdash-shared-auth",
    env=env,
    pool_name="secdash-shared-pool",
    require_passkey_only=passkey_only,
    additional_callback_urls=[f"{api_gateway_url}/auth/callback"] if api_gateway_url else [],
    additional_logout_urls=[f"{api_gateway_url}/auth/login"] if api_gateway_url else [],
    description="Security Dashboards - Shared Cognito Authentication",
)

# =============================================================================
# Health Dashboard Stack (RETIRED — replaced by IrisStack)
# =============================================================================
# Destroyed 2026-02-13. The iris edge-first architecture replaces this stack.
# Kept commented out for reference; delete once IrisStack is stable.
# HealthDashboardStack(
#     app,
#     "secdash-health",
#     env=env,
#     domain_name=domain_name,
#     hosted_zone_id=hosted_zone_id,
#     certificate_arn=certificate_arn,
#     allowed_email=admin_email,
#     security_lake_db=security_lake_db,
#     athena_output=athena_output,
#     description="Security Dashboards - Health Monitor with Cognito Passkey Auth",
# )

# =============================================================================
# Real-Time Alerting Stack
# =============================================================================
# Monitors Security Lake data freshness and runs detection rules on schedule.
# Sends alerts via SNS (email) and Slack.
AlertingStack(
    app,
    "secdash-alerting",
    env=env,
    alert_email=admin_email,
    slack_webhook_url=slack_webhook,
    security_lake_db=security_lake_db,
    athena_output=athena_output,
    freshness_threshold_minutes=60,  # Alert if data older than 1 hour
    check_interval_minutes=15,  # Check every 15 minutes
    description="Security Dashboards - Real-Time Alerting",
)

# =============================================================================
# Detection Rules Stack (replaces SAM template generation)
# =============================================================================
# Deploys detection rule Lambdas from pre-built packages in ./build.
# Requires: secdash deploy --rules detections/ --output ./build
DetectionRulesStack(
    app,
    "secdash-detections",
    env=env,
    build_dir="./build",
    notifications_layer_path="./build/notifications_layer",
    security_lake_db=security_lake_db,
    athena_output=athena_output,
    slack_webhook_url=slack_webhook,
    alerting_stack_name="secdash-alerting",
    description="Security Dashboards - Detection Rule Lambdas",
)

# =============================================================================
# FastAPI Web Dashboard Stack
# =============================================================================
# Deploys the FastAPI app as a Lambda behind HTTP API Gateway.
# Reports are stored in a dedicated S3 bucket.
# Pre-built Lambda package directory (built via: scripts/build_lambda.sh)
# Falls back to source tree if not set (won't include dependencies)
lambda_package_dir = os.environ.get("LAMBDA_PACKAGE_DIR", "/tmp/secdash-lambda")

FastAPIStack(
    app,
    "secdash-web",
    env=env,
    security_lake_db=security_lake_db,
    athena_output=athena_output,
    lambda_package_dir=lambda_package_dir,
    auth_enabled=True,
    cognito_user_pool_id=shared_auth.user_pool.user_pool_id,
    cognito_client_id=shared_auth.web_client.user_pool_client_id,
    cognito_client_secret=shared_auth.web_client.user_pool_client_secret.to_string(),
    cognito_domain=f"secdash-auth-{account}.auth.{region}.amazoncognito.com",
    session_secret_key=os.environ.get("SECDASH_SESSION_SECRET_KEY", "change-me-in-production"),
    description="Security Dashboards - FastAPI Web Dashboard",
)

# =============================================================================
# Iris Edge-First Stack (CloudFront + S3 + Health Checker + DynamoDB cache)
# =============================================================================
# Existing API Gateway ID for the secdash-web Lambda
iris_api_gateway_id = os.environ.get("IRIS_API_GATEWAY_ID", "udy3l282oh")
iris_certificate_arn = os.environ.get(
    "IRIS_CERTIFICATE_ARN",
    f"arn:aws:acm:us-east-1:{account}:certificate/5a84cf7f-eee1-4b5e-96e8-0347014ff674",
)

IrisStack(
    app,
    "secdash-iris",
    env=env,
    domain_name="iris.lexicone.com",
    hosted_zone_id=hosted_zone_id,
    certificate_arn=iris_certificate_arn,
    cognito_user_pool_id=shared_auth.user_pool.user_pool_id,
    cognito_client_id=shared_auth.web_client.user_pool_client_id,
    security_lake_db=security_lake_db,
    athena_output=athena_output,
    api_gateway_id=iris_api_gateway_id,
    lambda_package_dir=lambda_package_dir,
    check_interval_minutes=15,
    description="Iris - Edge-first security dashboard (CloudFront + S3 + Health Checker)",
)

app.synth()
