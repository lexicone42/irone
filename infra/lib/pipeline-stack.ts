import * as cdk from "aws-cdk-lib";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as iam from "aws-cdk-lib/aws-iam";
import * as sfn from "aws-cdk-lib/aws-stepfunctions";
import * as tasks from "aws-cdk-lib/aws-stepfunctions-tasks";
import { Construct } from "constructs";
import { RustLambda } from "./constructs/rust-lambda.js";

export interface PipelineStackProps extends cdk.StackProps {
  /** S3 bucket name used by web stack (for reports and investigation artifacts). */
  readonly reportBucketName: string;
  /** Path to cargo-lambda output for irone-worker (undefined = dummy). */
  readonly workerCodePath?: string;
}

export class PipelineStack extends cdk.Stack {
  /** Exported for web stack to reference. */
  public readonly stateMachineArn: string;
  public readonly investigationsTableName: string;

  constructor(scope: Construct, id: string, props: PipelineStackProps) {
    super(scope, id, {
      ...props,
      description: "Irone - Investigation pipeline (DynamoDB + Worker + Step Functions)",
    });

    // --- DynamoDB: investigations metadata ---
    const investigationsTable = new dynamodb.Table(this, "InvestigationsTable", {
      tableName: "secdash_investigations",
      partitionKey: { name: "id", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: "ttl",
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // GSI: list by status, sorted by created_at
    investigationsTable.addGlobalSecondaryIndex({
      indexName: "status-created_at-index",
      partitionKey: { name: "status", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "created_at", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // --- Worker Lambda ---
    const worker = new RustLambda(this, "Worker", {
      codePath: props.workerCodePath,
      functionName: "secdash-worker",
      description: "irone investigation enrichment worker (Rust, Step Functions invoked)",
      memorySize: 1024,
      timeout: 300,
      environment: {
        SECDASH_SECURITY_LAKE_DB: "amazon_security_lake_glue_db_us_west_2",
        SECDASH_REPORT_BUCKET: props.reportBucketName,
        SECDASH_USE_DIRECT_QUERY: "true",
        RUST_LOG: "info",
      },
    });

    // Worker needs same data-access IAM as web Lambda
    worker.function.addToRolePolicy(
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
    worker.function.addToRolePolicy(
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
    worker.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["lakeformation:GetDataAccess"],
        resources: ["*"],
      })
    );
    worker.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"],
        resources: [
          "arn:aws:s3:::aws-security-data-lake-*",
          "arn:aws:s3:::aws-security-data-lake-*/*",
          "arn:aws:s3:::aws-athena-query-results-*",
          "arn:aws:s3:::aws-athena-query-results-*/*",
          `arn:aws:s3:::${props.reportBucketName}`,
          `arn:aws:s3:::${props.reportBucketName}/*`,
        ],
      })
    );
    worker.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["sts:GetCallerIdentity"],
        resources: ["*"],
      })
    );

    // IAM context enrichment: look up policies and trust for investigation principals
    worker.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "iam:GetUser",
          "iam:ListAttachedUserPolicies",
          "iam:ListUserPolicies",
          "iam:ListMFADevices",
          "iam:GetRole",
          "iam:ListAttachedRolePolicies",
          "iam:ListRolePolicies",
        ],
        resources: ["*"],
      })
    );

    // --- Step Function: investigation pipeline ---

    // State: Enrich (invoke worker Lambda)
    const enrichState = new tasks.LambdaInvoke(this, "Enrich", {
      lambdaFunction: worker.function,
      outputPath: "$.Payload",
      taskTimeout: sfn.Timeout.duration(cdk.Duration.seconds(290)),
      retryOnServiceExceptions: true,
    });
    enrichState.addRetry({
      errors: ["Lambda.ServiceException", "Lambda.TooManyRequestsException"],
      interval: cdk.Duration.seconds(5),
      maxAttempts: 2,
      backoffRate: 2,
    });

    // State: MarkActive — DynamoDB UpdateItem (direct integration, no Lambda)
    const markActiveState = new sfn.CustomState(this, "MarkActiveState", {
      stateJson: {
        Type: "Task",
        Resource: "arn:aws:states:::dynamodb:updateItem",
        Parameters: {
          TableName: investigationsTable.tableName,
          Key: {
            "id": { "S.$": "$.investigation_id" },
          },
          UpdateExpression: "SET #status = :active, node_count = :nc, edge_count = :ec, updated_at = :now",
          ExpressionAttributeNames: {
            "#status": "status",
          },
          ExpressionAttributeValues: {
            ":active": { "S": "active" },
            ":nc": { "N.$": "States.Format('{}', $.node_count)" },
            ":ec": { "N.$": "States.Format('{}', $.edge_count)" },
            ":now": { "S.$": "$$.State.EnteredTime" },
          },
        },
        ResultPath: "$.dynamoResult",
      },
    });

    // State: MarkFailed (DynamoDB direct integration)
    const markFailedState = new sfn.CustomState(this, "MarkFailedState", {
      stateJson: {
        Type: "Task",
        Resource: "arn:aws:states:::dynamodb:updateItem",
        Parameters: {
          TableName: investigationsTable.tableName,
          Key: {
            "id": { "S.$": "$.investigation_id" },
          },
          UpdateExpression: "SET #status = :failed, error_message = :err, updated_at = :now",
          ExpressionAttributeNames: {
            "#status": "status",
          },
          ExpressionAttributeValues: {
            ":failed": { "S": "failed" },
            ":err": { "S.$": "$.Error" },
            ":now": { "S.$": "$$.State.EnteredTime" },
          },
        },
        ResultPath: "$.dynamoResult",
        End: true,
      },
    });

    // Wire up: Enrich → MarkActive, with Catch → MarkFailed
    enrichState.addCatch(markFailedState, {
      resultPath: "$",
    });
    const definition = enrichState.next(markActiveState);

    const stateMachine = new sfn.StateMachine(this, "InvestigationPipeline", {
      stateMachineName: "secdash-investigation-pipeline",
      definitionBody: sfn.DefinitionBody.fromChainable(definition),
      timeout: cdk.Duration.minutes(10),
      tracingEnabled: true,
    });

    // Grant the state machine permission to invoke the worker Lambda and update DynamoDB
    worker.function.grantInvoke(stateMachine);
    investigationsTable.grantReadWriteData(stateMachine);

    this.stateMachineArn = stateMachine.stateMachineArn;
    this.investigationsTableName = investigationsTable.tableName;

    // --- Outputs ---
    new cdk.CfnOutput(this, "StateMachineArn", {
      description: "Investigation pipeline Step Function ARN",
      value: stateMachine.stateMachineArn,
    });
    new cdk.CfnOutput(this, "InvestigationsTableName", {
      description: "DynamoDB investigations table name",
      value: investigationsTable.tableName,
    });
    new cdk.CfnOutput(this, "WorkerLambdaArn", {
      description: "Worker Lambda ARN",
      value: worker.function.functionArn,
    });
  }
}
