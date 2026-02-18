#!/usr/bin/env node
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

// --- 1. Auth ---
const auth = new AuthStack(app, "secdash-shared-auth", { env });

// --- 2. Web API ---
const web = new WebStack(app, "secdash-web", {
  env,
  userPoolId: auth.userPool.userPoolId,
  userPoolClientId: auth.userPoolClient.userPoolClientId,
  cognitoDomain: `secdash-auth-${env.account}.auth.${env.region}.amazoncognito.com`,
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
});
iris.addDependency(web);

// --- 4. Alerting ---
const alerting = new AlertingStack(app, "secdash-alerting", {
  env,
  healthCacheTableName: "secdash_health_cache",
});
alerting.addDependency(iris);
