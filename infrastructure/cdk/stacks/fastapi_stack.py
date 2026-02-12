"""FastAPI Stack - Serverless web dashboard via Lambda + HTTP API Gateway."""

from __future__ import annotations

from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
)
from aws_cdk import (
    aws_dynamodb as dynamodb,
)
from aws_cdk import (
    aws_iam as iam,
)
from aws_cdk import (
    aws_lambda as lambda_,
)
from aws_cdk import (
    aws_s3 as s3,
)
from aws_cdk.aws_apigatewayv2 import CfnApi, CfnIntegration, CfnRoute, CfnStage
from constructs import Construct


class FastAPIStack(Stack):
    """Stack for the FastAPI web dashboard deployed as a Lambda function."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        security_lake_db: str = "",
        athena_output: str = "",
        report_bucket_name: str = "",
        rules_dir: str = "detections/",
        memory_mb: int = 512,
        timeout_seconds: int = 30,
        # Auth configuration
        auth_enabled: bool = False,
        cognito_user_pool_id: str = "",
        cognito_client_id: str = "",
        cognito_client_secret: str = "",
        cognito_domain: str = "",
        session_secret_key: str = "",
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- Report Bucket ---
        report_bucket = s3.Bucket(
            self,
            "ReportBucket",
            bucket_name=report_bucket_name or None,
            removal_policy=RemovalPolicy.RETAIN,
            auto_delete_objects=False,
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        )

        # --- DynamoDB Session Table (conditional on auth) ---
        session_table = None
        if auth_enabled:
            session_table = dynamodb.Table(
                self,
                "SessionTable",
                table_name="secdash_sessions",
                partition_key=dynamodb.Attribute(
                    name="session_id", type=dynamodb.AttributeType.STRING
                ),
                billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
                removal_policy=RemovalPolicy.DESTROY,
                time_to_live_attribute="ttl",
            )

        # --- Lambda Function ---
        handler = lambda_.Function(
            self,
            "FastAPIHandler",
            runtime=lambda_.Runtime.PYTHON_3_13,
            code=lambda_.Code.from_asset(
                "../../",
                exclude=[
                    "*.pyc",
                    "__pycache__",
                    ".git",
                    ".venv",
                    "node_modules",
                    "infrastructure",
                    "notebooks",
                    "tests",
                    ".ruff_cache",
                    ".pytest_cache",
                ],
            ),
            handler="src.secdashboards.web.lambda_handler.handler",
            memory_size=memory_mb,
            timeout=Duration.seconds(timeout_seconds),
            environment={
                "SECDASH_IS_LAMBDA": "true",
                "SECDASH_SECURITY_LAKE_DB": security_lake_db,
                "SECDASH_ATHENA_OUTPUT": athena_output,
                "SECDASH_REPORT_BUCKET": report_bucket.bucket_name,
                "SECDASH_RULES_DIR": rules_dir,
                "SECDASH_DUCKDB_PATH": "/tmp/secdash.duckdb",
                # Auth configuration (only relevant when auth_enabled)
                **(
                    {
                        "SECDASH_AUTH_ENABLED": "true",
                        "SECDASH_COGNITO_USER_POOL_ID": cognito_user_pool_id,
                        "SECDASH_COGNITO_CLIENT_ID": cognito_client_id,
                        "SECDASH_COGNITO_CLIENT_SECRET": cognito_client_secret,
                        "SECDASH_COGNITO_DOMAIN": cognito_domain,
                        "SECDASH_SESSION_SECRET_KEY": session_secret_key,
                        "SECDASH_SESSION_BACKEND": "dynamodb",
                    }
                    if auth_enabled
                    else {}
                ),
            },
        )

        # --- IAM Permissions ---
        # Athena query access
        handler.add_to_role_policy(
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

        # Glue catalog read access (for Athena)
        handler.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "glue:GetDatabase",
                    "glue:GetTable",
                    "glue:GetTables",
                    "glue:GetPartitions",
                ],
                resources=["*"],
            )
        )

        # S3 read access for Security Lake data + Athena results
        handler.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
                resources=[
                    "arn:aws:s3:::aws-athena-query-results-*",
                    "arn:aws:s3:::aws-athena-query-results-*/*",
                    "arn:aws:s3:::aws-security-data-lake-*",
                    "arn:aws:s3:::aws-security-data-lake-*/*",
                ],
            )
        )

        # Report bucket access
        report_bucket.grant_read_write(handler)

        # Security Lake read access
        handler.add_to_role_policy(
            iam.PolicyStatement(
                actions=["securitylake:GetDataLakeSources"],
                resources=["*"],
            )
        )

        # --- DynamoDB Session Table Permissions ---
        if session_table:
            session_table.grant_read_write_data(handler)

        # --- HTTP API Gateway ---
        api = CfnApi(
            self,
            "HttpApi",
            name=f"{construct_id}-api",
            protocol_type="HTTP",
            cors_configuration=CfnApi.CorsProperty(
                allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                allow_origins=["*"],
                allow_headers=["*"],
            ),
        )

        # Lambda integration
        integration = CfnIntegration(
            self,
            "LambdaIntegration",
            api_id=api.ref,
            integration_type="AWS_PROXY",
            integration_uri=handler.function_arn,
            payload_format_version="2.0",
        )

        # Default route catches all requests
        CfnRoute(
            self,
            "DefaultRoute",
            api_id=api.ref,
            route_key="$default",
            target=f"integrations/{integration.ref}",
        )

        # Auto-deploy stage
        CfnStage(
            self,
            "DefaultStage",
            api_id=api.ref,
            stage_name="$default",
            auto_deploy=True,
        )

        # Allow API Gateway to invoke Lambda
        handler.add_permission(
            "ApiGatewayInvoke",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"arn:aws:execute-api:{self.region}:{self.account}:{api.ref}/*",
        )

        # --- Outputs ---
        CfnOutput(
            self,
            "ApiUrl",
            value=f"https://{api.ref}.execute-api.{self.region}.amazonaws.com",
            description="FastAPI dashboard URL",
        )
        CfnOutput(
            self,
            "ReportBucketName",
            value=report_bucket.bucket_name,
            description="S3 bucket for generated reports",
        )
        CfnOutput(
            self,
            "FunctionName",
            value=handler.function_name,
            description="Lambda function name",
        )
