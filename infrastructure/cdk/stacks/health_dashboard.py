"""Health Dashboard Stack - Serverless health monitoring with Cognito passkey auth."""

from __future__ import annotations

import hashlib
from pathlib import Path
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
    aws_cognito as cognito,
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
from aws_cdk import (
    aws_s3_deployment as s3_deploy,
)
from aws_cdk.aws_apigatewayv2 import CfnApi, CfnAuthorizer, CfnIntegration, CfnRoute, CfnStage
from constructs import Construct


class HealthDashboardStack(Stack):
    """Stack for the security health dashboard with Cognito passkey authentication."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        domain_name: str = "",
        hosted_zone_id: str = "",
        certificate_arn: str = "",
        allowed_email: str = "bryan.egan@gmail.com",
        security_lake_db: str = "amazon_security_lake_glue_db_us_west_2",
        athena_output: str = "s3://aws-athena-query-results-651804262336-us-west-2/",
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # =====================================================================
        # Cognito User Pool with WebAuthn/Passkey Support
        # =====================================================================
        # Cognito domain prefix for passkey relying party ID
        cognito_domain_prefix = f"secdash-health-{self.account}"

        user_pool = cognito.UserPool(
            self,
            "UserPool",
            user_pool_name="secdash-health-pool",
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(email=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            mfa=cognito.Mfa.OPTIONAL,
            mfa_second_factor=cognito.MfaSecondFactor(sms=False, otp=True),
            password_policy=cognito.PasswordPolicy(
                min_length=12,
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True,
            ),
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY,
            removal_policy=RemovalPolicy.DESTROY,
            # Passkey/WebAuthn configuration
            sign_in_policy=cognito.SignInPolicy(
                allowed_first_auth_factors=cognito.AllowedFirstAuthFactors(
                    password=True,
                    passkey=True,
                    email_otp=True,
                )
            ),
            # Relying party ID must match the Cognito hosted domain
            passkey_relying_party_id=f"{cognito_domain_prefix}.auth.{self.region}.amazoncognito.com",
            passkey_user_verification=cognito.PasskeyUserVerification.PREFERRED,
        )

        # User pool domain for hosted UI (must match passkey relying party ID)
        user_pool_domain = user_pool.add_domain(
            "Domain",
            cognito_domain=cognito.CognitoDomainOptions(domain_prefix=cognito_domain_prefix),
        )

        # Determine callback/logout URLs based on domain config
        use_custom_domain = domain_name and certificate_arn
        callback_urls = ["http://localhost:3000/callback"]
        logout_urls = ["http://localhost:3000"]

        if use_custom_domain:
            callback_urls.append(f"https://{domain_name}/callback")
            logout_urls.append(f"https://{domain_name}")

        # Configure readable attributes (needed for ID token claims)
        read_attributes = cognito.ClientAttributes().with_standard_attributes(
            email=True,
            email_verified=True,
            fullname=True,
        )

        # User pool client
        user_pool_client = user_pool.add_client(
            "Client",
            user_pool_client_name="secdash-health-client",
            generate_secret=False,
            auth_flows=cognito.AuthFlow(
                user_srp=True,
                custom=True,
                user=True,  # Required for passkey/WebAuthn choice-based auth
            ),
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(authorization_code_grant=True),
                scopes=[
                    cognito.OAuthScope.OPENID,
                    cognito.OAuthScope.EMAIL,
                    cognito.OAuthScope.PROFILE,
                ],
                callback_urls=callback_urls,
                logout_urls=logout_urls,
            ),
            read_attributes=read_attributes,
            id_token_validity=Duration.hours(1),
            access_token_validity=Duration.hours(1),
            refresh_token_validity=Duration.days(365),  # 1 year for passkey convenience
            prevent_user_existence_errors=True,
        )

        # Enable Managed Login (required for /passkeys/add endpoint)
        # This activates the newer managed login experience with passkey support
        cognito.CfnManagedLoginBranding(
            self,
            "ManagedLoginBranding",
            user_pool_id=user_pool.user_pool_id,
            client_id=user_pool_client.user_pool_client_id,
            use_cognito_provided_values=True,  # Use default Cognito styling
        )

        # =====================================================================
        # S3 Bucket for Health Data Cache
        # =====================================================================
        # Stores hourly health snapshots for fast reads and historical data
        cache_bucket_suffix = hashlib.sha256(
            f"{self.stack_name}-cache-{self.account}-{self.region}".encode()
        ).hexdigest()[:12]

        cache_bucket = s3.Bucket(
            self,
            "CacheBucket",
            bucket_name=f"secdash-cache-{cache_bucket_suffix}",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="DeleteOldSnapshots",
                    expiration=Duration.days(30),  # Keep 30 days of history
                    enabled=True,
                )
            ],
        )

        # =====================================================================
        # Lambda Function for Health API
        # =====================================================================
        # Get path to Lambda code
        lambda_code_path = Path(__file__).parent.parent.parent.parent / "src/secdashboards/health"

        health_function = lambda_.Function(
            self,
            "HealthApiFunction",
            function_name="secdash-health-api",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="dashboard_handler.handler",
            code=lambda_.Code.from_asset(str(lambda_code_path)),
            memory_size=512,  # More memory = faster execution
            timeout=Duration.minutes(5),  # Security Lake queries can be slow
            environment={
                "SECURITY_LAKE_DB": security_lake_db,
                "ATHENA_OUTPUT": athena_output,
                "CACHE_BUCKET": cache_bucket.bucket_name,
            },
        )

        # Grant Lambda read/write access to cache bucket
        cache_bucket.grant_read_write(health_function)

        # Grant permissions
        health_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "athena:StartQueryExecution",
                    "athena:GetQueryExecution",
                    "athena:GetQueryResults",
                    "athena:StopQueryExecution",
                ],
                resources=["*"],
            )
        )

        health_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "glue:GetTable",
                    "glue:GetTables",
                    "glue:GetDatabase",
                    "glue:GetDatabases",
                ],
                resources=["*"],
            )
        )

        health_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:PutObject",
                ],
                resources=[
                    f"arn:aws:s3:::{athena_output.replace('s3://', '').split('/')[0]}/*",
                    "arn:aws:s3:::amazon-security-lake-*",
                ],
            )
        )

        health_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["cloudwatch:GetMetricData", "cloudwatch:ListMetrics"],
                resources=["*"],
            )
        )

        health_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["ce:GetCostAndUsage"],
                resources=["*"],
            )
        )

        # =====================================================================
        # EventBridge Rule for Hourly Cache Updates
        # =====================================================================
        # Runs every hour to collect and cache health data
        events.Rule(
            self,
            "HourlyCacheRule",
            rule_name="secdash-health-hourly-cache",
            description="Collect and cache health dashboard data every hour",
            schedule=events.Schedule.rate(Duration.hours(1)),
            targets=[events_targets.LambdaFunction(health_function)],
        )

        # =====================================================================
        # HTTP API with Cognito Authorizer
        # =====================================================================
        # Build allowed origins for CORS (tighter security than "*")
        cors_origins = ["http://localhost:3000"]
        if use_custom_domain:
            cors_origins.append(f"https://{domain_name}")

        http_api = CfnApi(
            self,
            "HealthApi",
            name="secdash-health-api",
            protocol_type="HTTP",
            cors_configuration=CfnApi.CorsProperty(
                allow_methods=["GET", "OPTIONS"],
                allow_origins=cors_origins,
                allow_headers=["Authorization", "Content-Type"],
                allow_credentials=True,
            ),
        )

        # Cognito authorizer
        authorizer = CfnAuthorizer(
            self,
            "CognitoAuthorizer",
            api_id=http_api.ref,
            authorizer_type="JWT",
            name="CognitoAuthorizer",
            identity_source=["$request.header.Authorization"],
            jwt_configuration=CfnAuthorizer.JWTConfigurationProperty(
                audience=[user_pool_client.user_pool_client_id],
                issuer=f"https://cognito-idp.{self.region}.amazonaws.com/{user_pool.user_pool_id}",
            ),
        )

        # Lambda integration
        integration = CfnIntegration(
            self,
            "LambdaIntegration",
            api_id=http_api.ref,
            integration_type="AWS_PROXY",
            integration_uri=health_function.function_arn,
            payload_format_version="2.0",
        )

        # Routes - includes historical data and cache refresh endpoints
        api_routes = [
            "/health",
            "/health/sources",
            "/health/costs",
            "/health/detections",
            "/health/history",  # Historical data for trend charts
            "/health/refresh",  # Force cache refresh
        ]
        for path in api_routes:
            route_id = path.replace("/", "").replace("-", "_") or "root"
            CfnRoute(
                self,
                f"Route_{route_id}",
                api_id=http_api.ref,
                route_key=f"GET {path}",
                authorization_type="JWT",
                authorizer_id=authorizer.ref,
                target=f"integrations/{integration.ref}",
            )

        # API Stage
        CfnStage(
            self,
            "ApiStage",
            api_id=http_api.ref,
            stage_name="prod",
            auto_deploy=True,
        )

        # Grant API Gateway permission to invoke Lambda
        health_function.add_permission(
            "ApiGatewayInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"arn:aws:execute-api:{self.region}:{self.account}:{http_api.ref}/*",
        )

        # =====================================================================
        # S3 Bucket for Static Dashboard
        # =====================================================================
        # Generate a unique suffix from stack name + account to prevent bucket enumeration
        # This creates a deterministic but non-guessable bucket name
        bucket_suffix = hashlib.sha256(
            f"{self.stack_name}-{self.account}-{self.region}".encode()
        ).hexdigest()[:12]

        dashboard_bucket = s3.Bucket(
            self,
            "DashboardBucket",
            bucket_name=f"secdash-{bucket_suffix}",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        # =====================================================================
        # CloudFront Distribution
        # =====================================================================
        # Origin Access Control for S3
        oac = cloudfront.S3OriginAccessControl(
            self,
            "OAC",
            signing=cloudfront.Signing.SIGV4_ALWAYS,
        )

        # Build CSP with custom domain support
        # Cognito hosted UI domain for passkey/OAuth flows
        cognito_auth_domain = f"{cognito_domain_prefix}.auth.{self.region}.amazoncognito.com"

        # Base connect-src endpoints
        connect_sources = [
            "'self'",
            f"https://{http_api.ref}.execute-api.{self.region}.amazonaws.com",
            f"https://cognito-idp.{self.region}.amazonaws.com",
            f"https://cognito-identity.{self.region}.amazonaws.com",
            f"https://{cognito_auth_domain}",
        ]

        csp_policy = (
            f"default-src 'self'; "
            f"script-src 'self' 'unsafe-inline' https://cognito-idp.{self.region}.amazonaws.com https://{cognito_auth_domain}; "
            f"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            f"font-src 'self' https://fonts.gstatic.com; "
            f"img-src 'self' data: https:; "
            f"connect-src {' '.join(connect_sources)}; "
            f"frame-ancestors 'none'; "
            f"form-action 'self' https://{cognito_auth_domain} https://*.amazoncognito.com;"
        )

        # Security headers policy
        security_headers = cloudfront.ResponseHeadersPolicy(
            self,
            "SecurityHeaders",
            response_headers_policy_name="secdash-security-headers",
            security_headers_behavior=cloudfront.ResponseSecurityHeadersBehavior(
                content_security_policy=cloudfront.ResponseHeadersContentSecurityPolicy(
                    content_security_policy=csp_policy,
                    override=True,
                ),
                content_type_options=cloudfront.ResponseHeadersContentTypeOptions(override=True),
                frame_options=cloudfront.ResponseHeadersFrameOptions(
                    frame_option=cloudfront.HeadersFrameOption.DENY, override=True
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
                xss_protection=cloudfront.ResponseHeadersXSSProtection(
                    protection=True, mode_block=True, override=True
                ),
            ),
        )

        # Import ACM certificate if provided (must be in us-east-1 for CloudFront)
        certificate = None
        if certificate_arn:
            certificate = acm.Certificate.from_certificate_arn(self, "Certificate", certificate_arn)

        # CloudFront distribution
        distribution = cloudfront.Distribution(
            self,
            "Distribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(
                    dashboard_bucket,
                    origin_access_control=oac,
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
                response_headers_policy=security_headers,
            ),
            default_root_object="index.html",
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
            # Custom domain configuration
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

        # Route53 A record for custom domain
        if domain_name and hosted_zone_id:
            hosted_zone = route53.HostedZone.from_hosted_zone_attributes(
                self,
                "HostedZone",
                hosted_zone_id=hosted_zone_id,
                zone_name=domain_name.split(".", 1)[1] if "." in domain_name else domain_name,
            )
            route53.ARecord(
                self,
                "DnsRecord",
                zone=hosted_zone,
                record_name=domain_name,
                target=route53.RecordTarget.from_alias(targets.CloudFrontTarget(distribution)),
            )

        # Deploy static files
        static_dir = Path(__file__).parent.parent.parent / "dashboard-static"
        if static_dir.exists():
            s3_deploy.BucketDeployment(
                self,
                "DeployDashboard",
                sources=[s3_deploy.Source.asset(str(static_dir))],
                destination_bucket=dashboard_bucket,
                distribution=distribution,
                distribution_paths=["/*"],
            )

        # =====================================================================
        # Outputs
        # =====================================================================
        CfnOutput(
            self,
            "ApiEndpoint",
            value=f"https://{http_api.ref}.execute-api.{self.region}.amazonaws.com/prod",
            description="Health API endpoint",
        )

        CfnOutput(
            self,
            "DashboardUrl",
            value=f"https://{distribution.distribution_domain_name}",
            description="Health Dashboard URL",
        )

        CfnOutput(
            self,
            "UserPoolId",
            value=user_pool.user_pool_id,
            description="Cognito User Pool ID",
        )

        CfnOutput(
            self,
            "UserPoolClientId",
            value=user_pool_client.user_pool_client_id,
            description="Cognito User Pool Client ID",
        )

        CfnOutput(
            self,
            "CognitoLoginUrl",
            value=(
                f"https://{user_pool_domain.domain_name}.auth.{self.region}.amazoncognito.com"
                f"/login?client_id={user_pool_client.user_pool_client_id}"
                f"&response_type=code&scope=openid+email+profile"
                f"&redirect_uri=https://{distribution.distribution_domain_name}/callback"
            ),
            description="Cognito Hosted UI Login URL",
        )

        CfnOutput(
            self,
            "DeploymentNotes",
            value=f"Create user: aws cognito-idp admin-create-user --user-pool-id {user_pool.user_pool_id} --username {allowed_email}",
            description="Post-deployment instructions",
        )
