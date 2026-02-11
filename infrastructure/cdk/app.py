#!/usr/bin/env python3
"""CDK app entry point for Security Dashboards infrastructure.

Authentication Architecture:
- SharedAuthStack: Centralized Cognito User Pool with passkey support
- HealthDashboardStack: Health monitoring dashboard (uses shared pool or embedded pool)
- MarimoAuthStack: Notebook authentication layer (CloudFront + Cognito)

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
from stacks import AlertingStack, DetectionRulesStack, FastAPIStack, HealthDashboardStack

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

env = cdk.Environment(account=account, region=region)

# =============================================================================
# Shared Authentication Stack (Optional - for multi-service deployments)
# =============================================================================
# Uncomment to deploy a shared Cognito User Pool for all services:
#
# shared_auth = SharedAuthStack(
#     app,
#     "secdash-shared-auth",
#     env=env,
#     pool_name="secdash-shared-pool",
#     require_passkey_only=passkey_only,
#     description="Security Dashboards - Shared Cognito Authentication",
# )

# =============================================================================
# Health Dashboard Stack
# =============================================================================
# Currently uses its own embedded Cognito User Pool.
# To use shared pool instead, pass user_pool_id from shared_auth.
#
# For Marimo notebooks at /notebooks, deploy App Runner first, then uncomment:
#   app_runner_domain="xxx.us-west-2.awsapprunner.com",
HealthDashboardStack(
    app,
    "secdash-health",
    env=env,
    domain_name=domain_name,
    hosted_zone_id=hosted_zone_id,
    certificate_arn=certificate_arn,
    allowed_email=admin_email,
    security_lake_db=security_lake_db,
    athena_output=athena_output,
    # app_runner_domain="",  # Uncomment after App Runner deployment
    description="Security Dashboards - Health Monitor with Cognito Passkey Auth",
)

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
FastAPIStack(
    app,
    "secdash-web",
    env=env,
    security_lake_db=security_lake_db,
    athena_output=athena_output,
    description="Security Dashboards - FastAPI Web Dashboard",
)

# =============================================================================
# Marimo Notebooks Auth Stack (Optional - when ready for public notebook access)
# =============================================================================
# Uncomment when you have App Runner deployed and want to add CloudFront + auth:
#
# MarimoAuthStack(
#     app,
#     "secdash-marimo-auth",
#     env=env,
#     user_pool_id="us-west-2_XXXXXXXX",  # From shared auth or health dashboard
#     user_pool_arn="arn:aws:cognito-idp:us-west-2:651804262336:userpool/us-west-2_XXXXXXXX",
#     app_runner_domain="XXXXXXXX.us-west-2.awsapprunner.com",  # From App Runner deployment
#     domain_name="notebooks.lexicone.com",
#     hosted_zone_id="ZN8XM06S79WID",
#     certificate_arn="arn:aws:acm:us-east-1:651804262336:certificate/XXXXXXXX",
#     require_passkey_only=passkey_only,
#     description="Security Dashboards - Marimo Notebooks with Cognito Passkey Auth",
# )

app.synth()
