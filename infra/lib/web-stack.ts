import * as cdk from "aws-cdk-lib";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as iam from "aws-cdk-lib/aws-iam";
import * as s3 from "aws-cdk-lib/aws-s3";
import { HttpApi } from "@aws-cdk/aws-apigatewayv2-alpha";
import { HttpLambdaIntegration } from "@aws-cdk/aws-apigatewayv2-integrations-alpha";
import { Construct } from "constructs";
import { RustLambda } from "./constructs/rust-lambda.js";

export interface WebStackProps extends cdk.StackProps {
  readonly userPoolId: string;
  readonly userPoolClientId: string;
  readonly cognitoDomain: string;
  /** Path to cargo-lambda output for iris-web (undefined = dummy placeholder). */
  readonly webLambdaCodePath?: string;
}

export class WebStack extends cdk.Stack {
  /** The HTTP API, exposed for CloudFront origin in iris-stack. */
  public readonly httpApi: HttpApi;

  constructor(scope: Construct, id: string, props: WebStackProps) {
    super(scope, id, {
      ...props,
      description: "Security Dashboards - FastAPI Web Dashboard",
    });

    // --- DynamoDB: sessions ---
    const sessionsTable = new dynamodb.Table(this, "SessionTable", {
      tableName: "secdash_sessions",
      partitionKey: { name: "session_id", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: "ttl",
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    (
      sessionsTable.node.defaultChild as dynamodb.CfnTable
    ).overrideLogicalId("SessionTableA016F679");

    // --- S3: report bucket ---
    const reportBucket = new s3.Bucket(this, "ReportBucket", {
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      autoDeleteObjects: false,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
    });
    (
      reportBucket.node.defaultChild as s3.CfnBucket
    ).overrideLogicalId("ReportBucket577F0FCD");

    // --- Lambda: web API ---
    const webLambda = new RustLambda(this, "FastAPI", {
      logicalId: "FastAPIHandlerC4831E27",
      codePath: props.webLambdaCodePath,
      description: "iris web API (Rust/axum on provided.al2023)",
      memorySize: 1024,
      timeout: 120,
      environment: {
        SECDASH_SECURITY_LAKE_DB: "amazon_security_lake_glue_db_us_west_2",
        SECDASH_REPORT_BUCKET: reportBucket.bucketName,
        SECDASH_HEALTH_CACHE_TABLE: "secdash_health_cache",
        SECDASH_SESSION_TABLE: sessionsTable.tableName,
        SECDASH_COGNITO_USER_POOL_ID: props.userPoolId,
        SECDASH_COGNITO_CLIENT_ID: props.userPoolClientId,
        SECDASH_COGNITO_DOMAIN: props.cognitoDomain,
        SECDASH_COGNITO_REDIRECT_URI:
          "https://iris.lexicone.com/auth/callback",
        SECDASH_USE_DIRECT_QUERY: "false",
        SECDASH_AUTH_ENABLED: "true",
        SECDASH_CEDAR_POLICY_DIR: "cedar",
        RUST_LOG: "info",
        // NOTE: SECDASH_COGNITO_CLIENT_SECRET and SECDASH_SESSION_SECRET_KEY
        // are currently set as plaintext env vars on the deployed Lambda.
        // TODO: Migrate to Secrets Manager and reference via secretsmanager: dynamic ref.
        // For now, they're managed out-of-band to avoid drift on initial adoption.
      },
    });

    // Override the IAM role logical ID to match existing
    const cfnRole = webLambda.function.role!.node.defaultChild as iam.CfnRole;
    cfnRole.overrideLogicalId("FastAPIHandlerServiceRole0F833ED4");

    // --- IAM policies ---

    // Athena
    webLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StopQueryExecution",
        ],
        resources: ["*"],
      })
    );

    // Glue catalog
    webLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "glue:GetCatalog",
          "glue:GetDatabase",
          "glue:GetDatabases",
          "glue:GetTable",
          "glue:GetTables",
        ],
        resources: ["*"],
      })
    );

    // Lake Formation
    webLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["lakeformation:GetDataAccess"],
        resources: ["*"],
      })
    );

    // S3: Security Lake data + Athena query results + report bucket
    webLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
        resources: [
          "arn:aws:s3:::aws-security-data-lake-*",
          "arn:aws:s3:::aws-security-data-lake-*/*",
          "arn:aws:s3:::aws-athena-query-results-*",
          "arn:aws:s3:::aws-athena-query-results-*/*",
          reportBucket.bucketArn,
          `${reportBucket.bucketArn}/*`,
        ],
      })
    );

    // DynamoDB: sessions + health cache
    sessionsTable.grantReadWriteData(webLambda.function);
    webLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan",
        ],
        resources: [
          `arn:aws:dynamodb:${this.region}:${this.account}:table/secdash_health_cache`,
        ],
      })
    );

    // STS
    webLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["sts:GetCallerIdentity"],
        resources: ["*"],
      })
    );

    // --- API Gateway v2 (HTTP API) ---
    const integration = new HttpLambdaIntegration(
      "WebIntegration",
      webLambda.function
    );

    this.httpApi = new HttpApi(this, "HttpApi", {
      defaultIntegration: integration,
    });

    // --- Outputs ---
    new cdk.CfnOutput(this, "ApiUrl", {
      value: this.httpApi.apiEndpoint,
    });
    new cdk.CfnOutput(this, "ReportBucketName", {
      value: reportBucket.bucketName,
    });
    new cdk.CfnOutput(this, "SessionsTableName", {
      value: sessionsTable.tableName,
    });
    new cdk.CfnOutput(this, "WebLambdaArn", {
      value: webLambda.function.functionArn,
    });
  }
}
