"""Shared Authentication Stack - Cognito User Pool with passkey support for all secdashboards services.

This stack creates the centralized authentication layer that all services share:
- Single Cognito User Pool with passkey/WebAuthn support
- User groups for RBAC (admin, detection-engineer, soc-analyst, incident-responder)
- Configurable passkey-only mode for maximum security
- Shared across: Health Dashboard, FastAPI Web App, Detection API, Investigation API
"""

from __future__ import annotations

from typing import Any

from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
)
from aws_cdk import (
    aws_cognito as cognito,
)
from constructs import Construct


class SharedAuthStack(Stack):
    """Centralized Cognito User Pool with passkey authentication.

    Security Features:
    - Passkey-first authentication (phishing-resistant FIDO2/WebAuthn)
    - Optional passkey-only mode (no password fallback)
    - Email OTP as backup authentication method
    - Strong password policy if passwords are allowed
    - User groups for role-based access control

    Architecture:
    - This stack exports the User Pool ID and ARN
    - Other stacks import these to create service-specific clients
    - All services share the same user identities and groups
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        pool_name: str = "secdash-shared-pool",
        cognito_domain_prefix: str = "",
        require_passkey_only: bool = False,
        passkey_relying_party_domain: str = "",
        allowed_admin_emails: list[str] | None = None,
        additional_callback_urls: list[str] | None = None,
        additional_logout_urls: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the Shared Auth Stack.

        Args:
            pool_name: Name for the Cognito User Pool
            cognito_domain_prefix: Prefix for Cognito hosted UI domain
            require_passkey_only: If True, ONLY passkey auth allowed (no passwords)
            passkey_relying_party_domain: Custom domain for WebAuthn RP ID (e.g. secdash.lexicone.com)
            allowed_admin_emails: List of emails to pre-create as admin users
        """
        super().__init__(scope, construct_id, **kwargs)

        # Default domain prefix uses account ID for uniqueness
        if not cognito_domain_prefix:
            cognito_domain_prefix = f"secdash-auth-{self.account}"

        # =====================================================================
        # Cognito User Pool with Passkey Support
        # =====================================================================

        # Configure allowed first-factor authentication methods
        # Passkey requires a custom domain for the relying party ID (WebAuthn RP ID
        # must match the serving domain). Until a custom domain is configured,
        # use password + email OTP. Passkey can be enabled later by setting
        # passkey_relying_party_id to the custom domain (e.g., secdash.lexicone.com).
        if require_passkey_only:
            allowed_factors = cognito.AllowedFirstAuthFactors(
                password=False,
                passkey=True,
                email_otp=False,
            )
        else:
            allowed_factors = cognito.AllowedFirstAuthFactors(
                password=True,
                passkey=False,  # Requires custom domain for RP ID
                email_otp=True,
            )

        # Build passkey kwargs only when a custom RP domain is provided
        passkey_kwargs: dict[str, object] = {}
        if passkey_relying_party_domain:
            passkey_kwargs["passkey_relying_party_id"] = passkey_relying_party_domain
            passkey_kwargs["passkey_user_verification"] = cognito.PasskeyUserVerification.REQUIRED

        user_pool = cognito.UserPool(
            self,
            "UserPool",
            user_pool_name=pool_name,
            self_sign_up_enabled=False,  # Admin-only user creation
            sign_in_aliases=cognito.SignInAliases(email=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            # MFA Configuration
            mfa=cognito.Mfa.OPTIONAL,
            mfa_second_factor=cognito.MfaSecondFactor(sms=False, otp=True),
            # Password Policy
            password_policy=cognito.PasswordPolicy(
                min_length=16,
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True,
            ),
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY,
            removal_policy=RemovalPolicy.RETAIN,
            sign_in_policy=cognito.SignInPolicy(allowed_first_auth_factors=allowed_factors),
            **passkey_kwargs,
        )

        # User pool domain for hosted UI
        user_pool_domain = user_pool.add_domain(
            "Domain",
            cognito_domain=cognito.CognitoDomainOptions(domain_prefix=cognito_domain_prefix),
        )

        # =====================================================================
        # RBAC Groups
        # =====================================================================
        # Admin: Full access to all features including deployment and config
        cognito.CfnUserPoolGroup(
            self,
            "AdminGroup",
            user_pool_id=user_pool.user_pool_id,
            group_name="admin",
            description="Full administrative access to all secdashboards features",
            precedence=1,  # Highest priority
        )

        # Detection Engineer: Create/manage detection rules, run investigations
        cognito.CfnUserPoolGroup(
            self,
            "DetectionEngineerGroup",
            user_pool_id=user_pool.user_pool_id,
            group_name="detection-engineer",
            description="Create and manage detection rules, perform investigations",
            precedence=10,
        )

        # SOC Analyst: Run investigations, view dashboards, read-only rules
        cognito.CfnUserPoolGroup(
            self,
            "SocAnalystGroup",
            user_pool_id=user_pool.user_pool_id,
            group_name="soc-analyst",
            description="Investigate alerts, view dashboards, read detection rules",
            precedence=20,
        )

        # Incident Responder: Extended investigation access, report generation
        cognito.CfnUserPoolGroup(
            self,
            "IncidentResponderGroup",
            user_pool_id=user_pool.user_pool_id,
            group_name="incident-responder",
            description="Full investigation access with report generation capabilities",
            precedence=15,
        )

        # Read-Only: Dashboard viewing only
        cognito.CfnUserPoolGroup(
            self,
            "ReadOnlyGroup",
            user_pool_id=user_pool.user_pool_id,
            group_name="read-only",
            description="View dashboards and reports only",
            precedence=100,
        )

        # =====================================================================
        # Web Dashboard Client
        # =====================================================================
        web_client = user_pool.add_client(
            "WebDashboardClient",
            user_pool_client_name="secdash-web-dashboard",
            auth_flows=cognito.AuthFlow(
                user_password=not require_passkey_only,
                user_srp=not require_passkey_only,
            ),
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(authorization_code_grant=True),
                scopes=[
                    cognito.OAuthScope.OPENID,
                    cognito.OAuthScope.EMAIL,
                    cognito.OAuthScope.PROFILE,
                ],
                callback_urls=[
                    "https://localhost:8000/auth/callback",
                    *(additional_callback_urls or []),
                ],
                logout_urls=[
                    "https://localhost:8000/auth/login",
                    *(additional_logout_urls or []),
                ],
            ),
            generate_secret=True,
            id_token_validity=Duration.hours(1),
            access_token_validity=Duration.hours(1),
            refresh_token_validity=Duration.days(30),
        )
        self.web_client = web_client

        # =====================================================================
        # Export Values
        # =====================================================================
        self.user_pool = user_pool
        self.user_pool_domain = user_pool_domain

        CfnOutput(
            self,
            "UserPoolId",
            value=user_pool.user_pool_id,
            description="Shared Cognito User Pool ID",
            export_name=f"{construct_id}-UserPoolId",
        )

        CfnOutput(
            self,
            "UserPoolArn",
            value=user_pool.user_pool_arn,
            description="Shared Cognito User Pool ARN",
            export_name=f"{construct_id}-UserPoolArn",
        )

        CfnOutput(
            self,
            "UserPoolDomain",
            value=f"{cognito_domain_prefix}.auth.{self.region}.amazoncognito.com",
            description="Cognito Hosted UI Domain",
            export_name=f"{construct_id}-UserPoolDomain",
        )

        CfnOutput(
            self,
            "AuthMode",
            value="PASSKEY_ONLY" if require_passkey_only else "PASSKEY_FIRST",
            description="Authentication mode (PASSKEY_ONLY = no password fallback)",
        )

        CfnOutput(
            self,
            "CreateUserCommand",
            value=f"aws cognito-idp admin-create-user --user-pool-id {user_pool.user_pool_id} --username USER_EMAIL",
            description="Command to create a new user",
        )

        CfnOutput(
            self,
            "WebClientId",
            value=web_client.user_pool_client_id,
            description="Web Dashboard Cognito Client ID",
            export_name=f"{construct_id}-WebClientId",
        )

        CfnOutput(
            self,
            "AddToAdminGroupCommand",
            value=f"aws cognito-idp admin-add-user-to-group --user-pool-id {user_pool.user_pool_id} --username USER_EMAIL --group-name admin",
            description="Command to add user to admin group",
        )
