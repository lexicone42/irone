#!/usr/bin/env node
import * as fs from "node:fs";
import * as path from "node:path";
import "source-map-support/register.js";
import * as cdk from "aws-cdk-lib";
import { AuthStack } from "../lib/auth-stack.js";
import { WebStack } from "../lib/web-stack.js";
import { PipelineStack } from "../lib/pipeline-stack.js";
import { IroneStack } from "../lib/irone-stack.js";
import { AlertingStack } from "../lib/alerting-stack.js";

const app = new cdk.App();

const env: cdk.Environment = {
  account: "651804262336",
  region: "us-west-2",
};

// --- Resolve cargo-lambda build output paths ---
// Falls back to dummy bootstrap if build hasn't run (allows `cdk synth` without building).
const projectRoot = path.resolve(__dirname, "../..");
const lambdaOutputDir = path.join(projectRoot, "irone-rs/target/lambda");

function lambdaCodePath(crate: string): string | undefined {
  const dir = path.join(lambdaOutputDir, crate);
  if (fs.existsSync(path.join(dir, "bootstrap"))) {
    return dir;
  }
  return undefined; // falls back to dummy in RustLambda construct
}

// --- 1. Auth ---
const auth = new AuthStack(app, "secdash-shared-auth", { env });

// --- 2. Web API ---
const web = new WebStack(app, "secdash-web", {
  env,
  userPoolId: auth.userPool.userPoolId,
  userPoolClientId: auth.userPoolClient.userPoolClientId,
  userPoolClientSecret: auth.userPoolClient.userPoolClientSecret,
  cognitoDomain: `secdash-auth-${env.account}.auth.${env.region}.amazoncognito.com`,
  webLambdaCodePath: lambdaCodePath("irone-web"),
  // Pipeline props wired after pipeline stack is created (see below)
});
web.addDependency(auth);

// --- 2b. Investigation Pipeline (DynamoDB + Worker + Step Functions) ---
const pipeline = new PipelineStack(app, "secdash-pipeline", {
  env,
  reportBucketName: web.reportBucketName,
  workerCodePath: lambdaCodePath("irone-worker"),
});
pipeline.addDependency(web);
// Note: web Lambda env vars for SFN ARN and investigations table are set
// out-of-band after first CDK deploy (to avoid circular dependency).
// Use: aws lambda update-function-configuration --environment to add:
//   SECDASH_INVESTIGATION_STATE_MACHINE_ARN=<pipeline.stateMachineArn>
//   SECDASH_INVESTIGATIONS_TABLE=<pipeline.investigationsTableName>

// --- 3. Irone (CloudFront + frontend + health checker) ---
const irone = new IroneStack(app, "secdash-iris", {
  env,
  httpApi: web.httpApi,
  certificateArn:
    "arn:aws:acm:us-east-1:651804262336:certificate/62917863-b802-4ea6-bccf-be5df8df4828",
  domainName: "irone.lexicone.com",
  hostedZoneId: "ZN8XM06S79WID",
  healthCheckerCodePath: lambdaCodePath("irone-health-checker"),
});
irone.addDependency(web);

// --- 4. Alerting ---
const alerting = new AlertingStack(app, "secdash-alerting", {
  env,
  healthCacheTableName: "secdash_health_cache",
  alertingLambdaCodePath: lambdaCodePath("irone-alerting"),
  reportBucket: web.reportBucketName,
  investigationStateMachineArn: pipeline.stateMachineArn,
  investigationsTableName: pipeline.investigationsTableName,
});
alerting.addDependency(pipeline);
