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
      functionName: "secdash-alerting",
      description: "iris alerting (Rust, EventBridge scheduled)",
      memorySize: 512,
      timeout: 300,
      environment: {
        SECDASH_ALERTS_TOPIC_ARN: alertsTopic.topicArn,
        SECDASH_CRITICAL_ALERTS_TOPIC_ARN: criticalAlertsTopic.topicArn,
        SECDASH_HEALTH_CACHE_TABLE: props.healthCacheTableName,
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
