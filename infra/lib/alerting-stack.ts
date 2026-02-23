import * as cdk from "aws-cdk-lib";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as iam from "aws-cdk-lib/aws-iam";
import * as sns from "aws-cdk-lib/aws-sns";
import * as subscriptions from "aws-cdk-lib/aws-sns-subscriptions";
import { Construct } from "constructs";
import { RustLambda } from "./constructs/rust-lambda.js";

export interface AlertingStackProps extends cdk.StackProps {
  readonly healthCacheTableName: string;
  /** Path to cargo-lambda output for irone-alerting (undefined = dummy). */
  readonly alertingLambdaCodePath?: string;
  /** S3 bucket for investigation artifacts. */
  readonly reportBucket?: string;
  /** Step Functions state machine ARN for investigation enrichment. */
  readonly investigationStateMachineArn?: string;
  /** DynamoDB table for investigation metadata. */
  readonly investigationsTableName?: string;
}

export class AlertingStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: AlertingStackProps) {
    super(scope, id, {
      ...props,
      description: "Security Dashboards - Real-Time Alerting",
    });

    // --- SNS Topics ---
    const alertsTopic = new sns.Topic(this, "AlertsTopic", {
      topicName: "secdash-alerts",
      displayName: "Security Dashboards Alerts",
    });
    (
      alertsTopic.node.defaultChild as sns.CfnTopic
    ).overrideLogicalId("AlertsTopic3414BE91");

    const criticalAlertsTopic = new sns.Topic(this, "CriticalAlertsTopic", {
      topicName: "secdash-critical-alerts",
      displayName: "Security Dashboards Critical Alerts",
    });
    (
      criticalAlertsTopic.node.defaultChild as sns.CfnTopic
    ).overrideLogicalId("CriticalAlertsTopicF16F2E77");

    // Email subscriptions (matching deployed)
    alertsTopic.addSubscription(
      new subscriptions.EmailSubscription("bryan.egan@gmail.com")
    );
    criticalAlertsTopic.addSubscription(
      new subscriptions.EmailSubscription("bryan.egan@gmail.com")
    );

    // --- Alerting Lambda ---
    const alertingLambda = new RustLambda(this, "Alerting", {
      logicalId: "AlertingFunction020026F9",
      codePath: props.alertingLambdaCodePath,
      functionName: "secdash-alerting",
      description: "irone alerting (Rust, EventBridge scheduled)",
      memorySize: 1024,
      timeout: 900,
      environment: {
        SECDASH_ALERTS_TOPIC_ARN: alertsTopic.topicArn,
        SECDASH_CRITICAL_ALERTS_TOPIC_ARN: criticalAlertsTopic.topicArn,
        SECDASH_HEALTH_CACHE_TABLE: props.healthCacheTableName,
        SECDASH_SECURITY_LAKE_DB: "amazon_security_lake_glue_db_us_west_2",
        SECDASH_USE_DIRECT_QUERY: "true",
        SECDASH_REGION: this.region,
        SECDASH_REPORT_BUCKET: props.reportBucket ?? "",
        SECDASH_INVESTIGATION_STATE_MACHINE_ARN: props.investigationStateMachineArn ?? "",
        SECDASH_INVESTIGATIONS_TABLE: props.investigationsTableName ?? "secdash_investigations",
        SECDASH_SECURITY_HUB_ENABLED: "true",
        SECDASH_ACCOUNT_ID: this.account,
        RUST_LOG: "info",
      },
    });

    // SNS publish permissions
    alertsTopic.grantPublish(alertingLambda.function);
    criticalAlertsTopic.grantPublish(alertingLambda.function);

    // DynamoDB read for health cache
    alertingLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"],
        resources: [
          `arn:aws:dynamodb:${this.region}:${this.account}:table/secdash_health_cache`,
        ],
      })
    );

    // DynamoDB write for investigation records
    alertingLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["dynamodb:PutItem", "dynamodb:GetItem"],
        resources: [
          `arn:aws:dynamodb:${this.region}:${this.account}:table/${props.investigationsTableName ?? "secdash_investigations"}`,
        ],
      })
    );

    // Security Lake: Athena, Glue, LakeFormation, S3 (same as health-checker)
    alertingLambda.function.addToRolePolicy(
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
    alertingLambda.function.addToRolePolicy(
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
    alertingLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["lakeformation:GetDataAccess"],
        resources: ["*"],
      })
    );
    alertingLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"],
        resources: [
          "arn:aws:s3:::aws-security-data-lake-*",
          "arn:aws:s3:::aws-security-data-lake-*/*",
          "arn:aws:s3:::aws-athena-query-results-*",
          "arn:aws:s3:::aws-athena-query-results-*/*",
        ],
      })
    );
    alertingLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["sts:GetCallerIdentity"],
        resources: ["*"],
      })
    );

    // S3 write for investigation artifacts (detection_result.json, graph.json)
    if (props.reportBucket) {
      alertingLambda.function.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["s3:PutObject"],
          resources: [`arn:aws:s3:::${props.reportBucket}/investigations/*`],
        })
      );
    }

    // Step Functions: start enrichment execution
    if (props.investigationStateMachineArn) {
      alertingLambda.function.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["states:StartExecution"],
          resources: [props.investigationStateMachineArn],
        })
      );
    }

    // Security Hub: push detection findings
    alertingLambda.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["securityhub:BatchImportFindings"],
        resources: [
          `arn:aws:securityhub:${this.region}:${this.account}:product/${this.account}/default`,
          `arn:aws:securityhub:${this.region}::product/*/default`,
        ],
      })
    );

    // --- EventBridge Rules ---
    const detectionRule = new events.Rule(this, "DetectionCheckRule", {
      ruleName: "secdash-detection-check",
      schedule: events.Schedule.rate(cdk.Duration.minutes(15)),
      description: "Run detection rules against Security Lake",
    });
    detectionRule.addTarget(
      new targets.LambdaFunction(alertingLambda.function, {
        event: events.RuleTargetInput.fromObject({
          check_type: "detections",
        }),
      })
    );
    (
      detectionRule.node.defaultChild as events.CfnRule
    ).overrideLogicalId("DetectionCheckRule5E5D5D75");

    const freshnessRule = new events.Rule(this, "FreshnessCheckRule", {
      ruleName: "secdash-freshness-check",
      schedule: events.Schedule.rate(cdk.Duration.minutes(15)),
      description: "Check Security Lake data source freshness",
    });
    freshnessRule.addTarget(
      new targets.LambdaFunction(alertingLambda.function, {
        event: events.RuleTargetInput.fromObject({
          check_type: "freshness",
          sources: [
            "cloud_trail_mgmt",
            "vpc_flow",
            "route53",
            "sh_findings",
            "lambda_execution",
          ],
        }),
      })
    );
    (
      freshnessRule.node.defaultChild as events.CfnRule
    ).overrideLogicalId("FreshnessCheckRule29BBB3A3");

    // --- Outputs ---
    new cdk.CfnOutput(this, "AlertsTopicArn", {
      description: "SNS Topic ARN for all alerts",
      value: alertsTopic.topicArn,
      exportName: "secdash-alerting-AlertsTopicArn",
    });
    new cdk.CfnOutput(this, "CriticalTopicArn", {
      description: "SNS Topic ARN for critical alerts only",
      value: criticalAlertsTopic.topicArn,
      exportName: "secdash-alerting-CriticalTopicArn",
    });
    new cdk.CfnOutput(this, "AlertingFunctionArn", {
      description: "Alerting Lambda function ARN",
      value: alertingLambda.function.functionArn,
    });
  }
}
