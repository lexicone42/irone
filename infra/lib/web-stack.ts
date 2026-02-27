import * as cdk from "aws-cdk-lib";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as iam from "aws-cdk-lib/aws-iam";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import { HttpApi } from "@aws-cdk/aws-apigatewayv2-alpha";
import { HttpLambdaIntegration } from "@aws-cdk/aws-apigatewayv2-integrations-alpha";
import { Construct } from "constructs";
import { RustLambda } from "./constructs/rust-lambda.js";

export interface WebStackProps extends cdk.StackProps {
  readonly userPoolId: string;
  readonly userPoolClientId: string;
  /** Public passkey client ID (no secret, ALLOW_USER_AUTH). */
  readonly passkeyClientId: string;
  readonly cognitoDomain: string;
  /** Path to cargo-lambda output for irone-web (undefined = dummy placeholder). */
  readonly webLambdaCodePath?: string;
}

export class WebStack extends cdk.Stack {
  /** The HTTP API, exposed for CloudFront origin in irone-stack. */
  public readonly httpApi: HttpApi;
  /** Report bucket name, exposed for pipeline stack. */
  public readonly reportBucketName: string;

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

    // --- Secrets Manager: session secret key (kept to avoid CDK deletion) ---
    // eslint-disable-next-line @typescript-eslint/no-unused-vars -- resource must stay to prevent CDK deletion
    const _sessionSecret = new secretsmanager.Secret(this, "SessionSecretKey", {
      secretName: "secdash/session-secret-key",
      description: "irone session encryption key",
      generateSecretString: {
        excludePunctuation: true,
        passwordLength: 64,
      },
    });

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
    this.reportBucketName = reportBucket.bucketName;

    // --- Lambda: web API ---
    const webLambda = new RustLambda(this, "FastAPI", {
      logicalId: "FastAPIHandlerC4831E27",
      codePath: props.webLambdaCodePath,
      description: "irone web API (Rust/axum on provided.al2023)",
      memorySize: 1024,
      timeout: 120,
      environment: {
        SECDASH_SECURITY_LAKE_DB: "amazon_security_lake_glue_db_us_west_2",
        SECDASH_REPORT_BUCKET: reportBucket.bucketName,
        SECDASH_HEALTH_CACHE_TABLE: "secdash_health_cache",
        SECDASH_SESSION_BACKEND: "dynamodb",
        SECDASH_SESSION_TABLE: sessionsTable.tableName,
        SECDASH_COGNITO_USER_POOL_ID: props.userPoolId,
        SECDASH_COGNITO_CLIENT_ID: props.userPoolClientId,
        SECDASH_COGNITO_DOMAIN: props.cognitoDomain,
        SECDASH_FRONTEND_URL: "https://irone.lexicone.com",
        SECDASH_COGNITO_REDIRECT_URI:
          "https://irone.lexicone.com/auth/callback",
        SECDASH_COGNITO_PASSKEY_CLIENT_ID: props.passkeyClientId,
        SECDASH_USE_DIRECT_QUERY: "true",
        SECDASH_AUTH_ENABLED: "true",
        SECDASH_CEDAR_POLICY_DIR: "cedar",
        SECDASH_RULES_DIR: "rules",
        RUST_LOG: "info",
        SECDASH_COGNITO_CLIENT_SECRET_SSM: "/secdash/cognito-client-secret",
        SECDASH_SESSION_SECRET_SSM: "/secdash/session-secret-key",
        SECDASH_SERVICE_TOKEN_SSM: "/secdash/service-token",
        // Investigation pipeline — names match pipeline-stack.ts hardcoded values
        SECDASH_INVESTIGATION_STATE_MACHINE_ARN:
          `arn:aws:states:${this.region}:${this.account}:stateMachine:secdash-investigation-pipeline`,
        SECDASH_INVESTIGATIONS_TABLE: "secdash_investigations",
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

    // SSM Parameter Store: read SecureString secrets
    webLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["ssm:GetParameter"],
        resources: [
          `arn:aws:ssm:${this.region}:${this.account}:parameter/secdash/*`,
        ],
      })
    );
    webLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["kms:Decrypt"],
        resources: ["*"],
        conditions: {
          StringEquals: {
            "kms:ViaService": `ssm.${this.region}.amazonaws.com`,
          },
        },
      })
    );

    // STS
    webLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["sts:GetCallerIdentity"],
        resources: ["*"],
      })
    );

    // Step Functions: start investigation pipeline executions
    webLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["states:StartExecution"],
        resources: [
          `arn:aws:states:${this.region}:${this.account}:stateMachine:secdash-investigation-pipeline`,
        ],
      })
    );

    // DynamoDB: investigations table
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
          `arn:aws:dynamodb:${this.region}:${this.account}:table/secdash_investigations`,
          `arn:aws:dynamodb:${this.region}:${this.account}:table/secdash_investigations/index/*`,
        ],
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
