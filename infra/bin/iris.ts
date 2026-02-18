#!/usr/bin/env node
import * as fs from "node:fs";
import * as path from "node:path";
import "source-map-support/register.js";
import * as cdk from "aws-cdk-lib";
import { AuthStack } from "../lib/auth-stack.js";
import { WebStack } from "../lib/web-stack.js";
import { IrisStack } from "../lib/iris-stack.js";
import { AlertingStack } from "../lib/alerting-stack.js";

const app = new cdk.App();

const env: cdk.Environment = {
  account: "651804262336",
  region: "us-west-2",
};

// --- Resolve cargo-lambda build output paths ---
// Falls back to dummy bootstrap if build hasn't run (allows `cdk synth` without building).
const projectRoot = path.resolve(__dirname, "../..");
const lambdaOutputDir = path.join(projectRoot, "iris-rs/target/lambda");

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
  cognitoDomain: `secdash-auth-${env.account}.auth.${env.region}.amazoncognito.com`,
  webLambdaCodePath: lambdaCodePath("iris-web"),
});
web.addDependency(auth);

// --- 3. Iris (CloudFront + frontend + health checker) ---
const iris = new IrisStack(app, "secdash-iris", {
  env,
  httpApi: web.httpApi,
  certificateArn:
    "arn:aws:acm:us-east-1:651804262336:certificate/5a84cf7f-eee1-4b5e-96e8-0347014ff674",
  domainName: "iris.lexicone.com",
  hostedZoneId: "ZN8XM06S79WID",
  healthCheckerCodePath: lambdaCodePath("iris-health-checker"),
});
iris.addDependency(web);

// --- 4. Alerting ---
const alerting = new AlertingStack(app, "secdash-alerting", {
  env,
  healthCacheTableName: "secdash_health_cache",
  alertingLambdaCodePath: lambdaCodePath("iris-alerting"),
});
alerting.addDependency(iris);
