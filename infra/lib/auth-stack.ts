import * as cdk from "aws-cdk-lib";
import * as cognito from "aws-cdk-lib/aws-cognito";
import { Construct } from "constructs";

export class AuthStack extends cdk.Stack {
  public readonly userPool: cognito.UserPool;
  public readonly userPoolClient: cognito.UserPoolClient;
  public readonly passkeyClient: cognito.UserPoolClient;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, {
      ...props,
      description: "Security Dashboards - Shared Cognito Authentication",
    });

    // --- Cognito User Pool ---
    this.userPool = new cognito.UserPool(this, "UserPool", {
      userPoolName: "secdash-shared-pool",
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      autoVerify: { email: true },
      mfa: cognito.Mfa.OPTIONAL,
      mfaSecondFactor: { sms: false, otp: true },
      passwordPolicy: {
        minLength: 16,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const cfnUserPool =
      this.userPool.node.defaultChild as cognito.CfnUserPool;
    cfnUserPool.overrideLogicalId("UserPool6BA7E5F2");
    // Sign-in policy: password + passkey (WebAuthn)
    cfnUserPool.addPropertyOverride("Policies.SignInPolicy", {
      AllowedFirstAuthFactors: ["PASSWORD", "WEB_AUTHN", "EMAIL_OTP"],
    });

    // --- User Pool Domain ---
    const domain = this.userPool.addDomain("UserPoolDomain", {
      cognitoDomain: {
        domainPrefix: `secdash-auth-${this.account}`,
      },
    });
    (
      domain.node.defaultChild as cognito.CfnUserPoolDomain
    ).overrideLogicalId("UserPoolDomainD0EA232A");

    // --- User Pool Client (server-side OAuth, confidential) ---
    this.userPoolClient = this.userPool.addClient("WebDashboardClient", {
      userPoolClientName: "secdash-web-dashboard",
      generateSecret: true,
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.PROFILE,
          cognito.OAuthScope.COGNITO_ADMIN,
        ],
        callbackUrls: [
          "https://irone.lexicone.com/auth/callback",
          "https://localhost:8000/auth/callback",
        ],
        logoutUrls: [
          "https://irone.lexicone.com/login.html",
          "https://localhost:8000/login.html",
        ],
      },
      authFlows: {
        userPassword: true,
        userSrp: true,
      },
      accessTokenValidity: cdk.Duration.minutes(60),
      idTokenValidity: cdk.Duration.minutes(60),
      refreshTokenValidity: cdk.Duration.minutes(43200),
    });
    (
      this.userPoolClient.node.defaultChild as cognito.CfnUserPoolClient
    ).overrideLogicalId("UserPoolWebDashboardClient1022FBB9");

    // --- Passkey Client (public, browser-side WebAuthn) ---
    // Passkeys require ALLOW_USER_AUTH + no client secret (browser can't compute SECRET_HASH).
    // aws.cognito.signin.user.admin scope is required for passkey management (list/delete).
    this.passkeyClient = this.userPool.addClient("PasskeyClient", {
      userPoolClientName: "secdash-passkey",
      generateSecret: false,
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.COGNITO_ADMIN,
        ],
        callbackUrls: [
          "https://irone.lexicone.com/callback.html",
          "http://localhost:8000/callback.html",
        ],
        logoutUrls: [
          "https://irone.lexicone.com/",
          "http://localhost:8000/",
        ],
      },
      authFlows: {
        userPassword: true,
        userSrp: true,
      },
      accessTokenValidity: cdk.Duration.minutes(60),
      idTokenValidity: cdk.Duration.minutes(60),
      refreshTokenValidity: cdk.Duration.minutes(43200),
    });
    // CDK escape hatch: add ALLOW_USER_AUTH + ALLOW_CUSTOM_AUTH (not exposed in L2)
    const cfnPasskeyClient =
      this.passkeyClient.node.defaultChild as cognito.CfnUserPoolClient;
    cfnPasskeyClient.addPropertyOverride("ExplicitAuthFlows", [
      "ALLOW_USER_PASSWORD_AUTH",
      "ALLOW_USER_SRP_AUTH",
      "ALLOW_CUSTOM_AUTH",
      "ALLOW_USER_AUTH",
      "ALLOW_REFRESH_TOKEN_AUTH",
    ]);

    // --- 5 RBAC Groups (matching deployed names) ---
    const groups = [
      {
        id: "AdminGroup",
        name: "admin",
        description: "Full administrative access to all secdashboards features",
        precedence: 1,
      },
      {
        id: "DetectionEngineerGroup",
        name: "detection-engineer",
        description: "Create and manage detection rules, perform investigations",
        precedence: 10,
      },
      {
        id: "SocAnalystGroup",
        name: "soc-analyst",
        description:
          "Investigate alerts, view dashboards, read detection rules",
        precedence: 20,
      },
      {
        id: "IncidentResponderGroup",
        name: "incident-responder",
        description:
          "Full investigation access with report generation capabilities",
        precedence: 15,
      },
      {
        id: "ReadOnlyGroup",
        name: "read-only",
        description: "View dashboards and reports only",
        precedence: 100,
      },
    ];

    for (const g of groups) {
      const group = new cognito.CfnUserPoolGroup(this, g.id, {
        userPoolId: this.userPool.userPoolId,
        groupName: g.name,
        description: g.description,
        precedence: g.precedence,
      });
      group.overrideLogicalId(g.id);
    }

    // --- Outputs (matching deployed exports) ---
    new cdk.CfnOutput(this, "UserPoolId", {
      description: "Shared Cognito User Pool ID",
      value: this.userPool.userPoolId,
      exportName: "secdash-shared-auth-UserPoolId",
    });
    new cdk.CfnOutput(this, "UserPoolArn", {
      description: "Shared Cognito User Pool ARN",
      value: this.userPool.userPoolArn,
      exportName: "secdash-shared-auth-UserPoolArn",
    });
    new cdk.CfnOutput(this, "WebClientId", {
      description: "Web Dashboard Cognito Client ID",
      value: this.userPoolClient.userPoolClientId,
      exportName: "secdash-shared-auth-WebClientId",
    });
    new cdk.CfnOutput(this, "PasskeyClientId", {
      description: "Passkey (public) Cognito Client ID for browser WebAuthn",
      value: this.passkeyClient.userPoolClientId,
      exportName: "secdash-shared-auth-PasskeyClientId",
    });
    new cdk.CfnOutput(this, "UserPoolDomain", {
      description: "Cognito Hosted UI Domain",
      value: `secdash-auth-${this.account}.auth.${this.region}.amazoncognito.com`,
      exportName: "secdash-shared-auth-UserPoolDomain",
    });
    new cdk.CfnOutput(this, "AuthMode", {
      description: "Authentication mode (PASSKEY_ONLY = no password fallback)",
      value: "PASSKEY_FIRST",
    });
    new cdk.CfnOutput(this, "CreateUserCommand", {
      description: "Command to create a new user",
      value: `aws cognito-idp admin-create-user --user-pool-id ${this.userPool.userPoolId} --username USER_EMAIL`,
    });
    new cdk.CfnOutput(this, "AddToAdminGroupCommand", {
      description: "Command to add user to admin group",
      value: `aws cognito-idp admin-add-user-to-group --user-pool-id ${this.userPool.userPoolId} --username USER_EMAIL --group-name admin`,
    });
  }
}
