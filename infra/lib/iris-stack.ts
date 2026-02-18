import * as cdk from "aws-cdk-lib";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as iam from "aws-cdk-lib/aws-iam";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as route53targets from "aws-cdk-lib/aws-route53-targets";
import * as s3 from "aws-cdk-lib/aws-s3";
import { HttpApi } from "@aws-cdk/aws-apigatewayv2-alpha";
import { Construct } from "constructs";
import { RustLambda } from "./constructs/rust-lambda.js";

export interface IrisStackProps extends cdk.StackProps {
  readonly httpApi: HttpApi;
  readonly certificateArn: string;
  readonly domainName: string;
  readonly hostedZoneId: string;
  /** Path to cargo-lambda output for iris-health-checker (undefined = dummy). */
  readonly healthCheckerCodePath?: string;
}

export class IrisStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: IrisStackProps) {
    super(scope, id, {
      ...props,
      description:
        "Iris - Edge-first security dashboard (CloudFront + S3 + Health Checker)",
    });

    // --- S3: static frontend ---
    const frontendBucket = new s3.Bucket(this, "FrontendBucket", {
      bucketName: "iris-frontend-415aeeaed7a5",
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      autoDeleteObjects: false,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    });
    (
      frontendBucket.node.defaultChild as s3.CfnBucket
    ).overrideLogicalId("FrontendBucketEFE2E19C");

    // --- DynamoDB: health cache ---
    const healthCacheTable = new dynamodb.Table(this, "HealthCacheTable", {
      tableName: "secdash_health_cache",
      partitionKey: {
        name: "source_name",
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: { name: "checked_at", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: "ttl",
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    (
      healthCacheTable.node.defaultChild as dynamodb.CfnTable
    ).overrideLogicalId("HealthCacheTableDD33BA83");

    // --- Health checker Lambda ---
    const healthChecker = new RustLambda(this, "HealthChecker", {
      logicalId: "HealthCheckerFunction0C7E0A62",
      codePath: props.healthCheckerCodePath,
      functionName: "secdash-health-checker",
      description: "iris health checker (Rust, EventBridge scheduled)",
      memorySize: 1024,
      timeout: 300,
      environment: {
        SECDASH_SECURITY_LAKE_DB: "amazon_security_lake_glue_db_us_west_2",
        SECDASH_HEALTH_CACHE_TABLE: healthCacheTable.tableName,
        SECDASH_USE_DIRECT_QUERY: "false",
        RUST_LOG: "info",
      },
    });

    // Health checker needs Athena, Glue, LakeFormation, S3, DynamoDB
    healthCacheTable.grantReadWriteData(healthChecker.function);
    healthChecker.function.addToRolePolicy(
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
    healthChecker.function.addToRolePolicy(
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
    healthChecker.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["lakeformation:GetDataAccess"],
        resources: ["*"],
      })
    );
    healthChecker.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["s3:GetObject", "s3:ListBucket"],
        resources: [
          "arn:aws:s3:::aws-security-data-lake-*",
          "arn:aws:s3:::aws-security-data-lake-*/*",
          "arn:aws:s3:::aws-athena-query-results-*",
          "arn:aws:s3:::aws-athena-query-results-*/*",
        ],
      })
    );
    healthChecker.function.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["sts:GetCallerIdentity"],
        resources: ["*"],
      })
    );

    // --- EventBridge: schedule health checks every 15 min ---
    const healthSchedule = new events.Rule(this, "HealthCheckSchedule", {
      ruleName: "secdash-iris-health-check",
      schedule: events.Schedule.rate(cdk.Duration.minutes(15)),
      description: "Run iris health checks every 15 minutes",
    });
    healthSchedule.addTarget(
      new targets.LambdaFunction(healthChecker.function)
    );
    (
      healthSchedule.node.defaultChild as events.CfnRule
    ).overrideLogicalId("HealthCheckSchedule9843A4E1");

    // --- CloudFront ---

    const certificate = acm.Certificate.fromCertificateArn(
      this,
      "Cert",
      props.certificateArn
    );

    // Origin Access Control for S3
    const oac = new cloudfront.CfnOriginAccessControl(this, "OAC", {
      originAccessControlConfig: {
        name: "secdashirisOACE7EAC12A",
        originAccessControlOriginType: "s3",
        signingBehavior: "always",
        signingProtocol: "sigv4",
      },
    });
    oac.overrideLogicalId("OAC5B452445");

    // Security headers policy (matching deployed config)
    const securityHeaders = new cloudfront.ResponseHeadersPolicy(
      this,
      "SecurityHeaders",
      {
        responseHeadersPolicyName: "iris-security-headers",
        securityHeadersBehavior: {
          contentTypeOptions: { override: true },
          frameOptions: {
            frameOption: cloudfront.HeadersFrameOption.DENY,
            override: true,
          },
          referrerPolicy: {
            referrerPolicy:
              cloudfront.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
            override: true,
          },
          strictTransportSecurity: {
            accessControlMaxAge: cdk.Duration.seconds(31536000),
            includeSubdomains: true,
            preload: true,
            override: true,
          },
        },
      }
    );
    (
      securityHeaders.node.defaultChild as cloudfront.CfnResponseHeadersPolicy
    ).overrideLogicalId("SecurityHeadersE66B69D3");

    // API Gateway origin (for /api/* and /auth/*)
    const apiOriginDomain = `${props.httpApi.apiId}.execute-api.${this.region}.amazonaws.com`;

    // S3 origin (for static frontend)
    const s3Origin = origins.S3BucketOrigin.withOriginAccessControl(
      frontendBucket,
      {
        originAccessControl:
          cloudfront.S3OriginAccessControl.fromOriginAccessControlId(
            this,
            "ImportedOAC",
            oac.attrId
          ),
      }
    );

    const apiOrigin = new origins.HttpOrigin(apiOriginDomain, {
      protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
    });

    const distribution = new cloudfront.Distribution(this, "Distribution", {
      defaultBehavior: {
        origin: s3Origin,
        viewerProtocolPolicy:
          cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        responseHeadersPolicy: securityHeaders,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
      },
      additionalBehaviors: {
        "/api/*": {
          origin: apiOrigin,
          viewerProtocolPolicy:
            cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          originRequestPolicy:
            cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
        },
        "/auth/*": {
          origin: apiOrigin,
          viewerProtocolPolicy:
            cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          originRequestPolicy:
            cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
        },
      },
      domainNames: [props.domainName],
      certificate,
      defaultRootObject: "index.html",
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      errorResponses: [
        {
          httpStatus: 403,
          responseHttpStatus: 200,
          responsePagePath: "/index.html",
        },
        {
          httpStatus: 404,
          responseHttpStatus: 200,
          responsePagePath: "/index.html",
        },
      ],
    });
    (
      distribution.node.defaultChild as cloudfront.CfnDistribution
    ).overrideLogicalId("Distribution830FAC52");

    // --- Route53: A record alias to CloudFront ---
    const hostedZone = route53.HostedZone.fromHostedZoneAttributes(
      this,
      "Zone",
      {
        hostedZoneId: props.hostedZoneId,
        zoneName: props.domainName,
      }
    );

    const dnsRecord = new route53.ARecord(this, "DnsRecord", {
      zone: hostedZone,
      recordName: props.domainName,
      target: route53.RecordTarget.fromAlias(
        new route53targets.CloudFrontTarget(distribution)
      ),
    });
    (
      dnsRecord.node.defaultChild as route53.CfnRecordSet
    ).overrideLogicalId("DnsRecord68F7FB14");

    // --- Outputs ---
    new cdk.CfnOutput(this, "DistributionId", {
      description: "CloudFront distribution ID (for cache invalidation)",
      value: distribution.distributionId,
    });
    new cdk.CfnOutput(this, "DistributionDomainName", {
      description: "CloudFront distribution domain",
      value: distribution.distributionDomainName,
    });
    new cdk.CfnOutput(this, "FrontendBucketName", {
      description: "S3 bucket for iris static frontend",
      value: frontendBucket.bucketName,
    });
    new cdk.CfnOutput(this, "HealthCacheTableName", {
      description: "DynamoDB health cache table name",
      value: healthCacheTable.tableName,
    });
    new cdk.CfnOutput(this, "HealthCheckerArn", {
      description: "Health checker Lambda ARN",
      value: healthChecker.function.functionArn,
    });
  }
}
