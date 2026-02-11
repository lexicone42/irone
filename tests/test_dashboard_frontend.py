"""Tests for dashboard frontend configuration.

These tests validate:
1. Content Security Policy includes all required domains for OAuth
2. JavaScript configuration is correct
3. OAuth endpoints are properly configured
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# Path to the dashboard HTML file
DASHBOARD_HTML_PATH = (
    Path(__file__).parent.parent / "infrastructure" / "dashboard-static" / "index.html"
)


class TestContentSecurityPolicy:
    """Tests for Content Security Policy configuration."""

    @pytest.fixture
    def html_content(self) -> str:
        """Load the dashboard HTML content."""
        return DASHBOARD_HTML_PATH.read_text()

    @pytest.fixture
    def csp_value(self, html_content: str) -> str:
        """Extract CSP meta tag value from HTML."""
        match = re.search(
            r'<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"',
            html_content,
        )
        assert match, "CSP meta tag not found in dashboard HTML"
        return match.group(1)

    @pytest.fixture
    def csp_directives(self, csp_value: str) -> dict[str, str]:
        """Parse CSP directives into a dictionary."""
        directives = {}
        for directive in csp_value.split(";"):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split(None, 1)
            if len(parts) == 2:
                directives[parts[0]] = parts[1]
            elif len(parts) == 1:
                directives[parts[0]] = ""
        return directives

    def test_csp_meta_tag_exists(self, html_content: str) -> None:
        """CSP meta tag must exist in dashboard HTML."""
        assert 'http-equiv="Content-Security-Policy"' in html_content

    def test_csp_connect_src_includes_api_gateway(self, csp_directives: dict[str, str]) -> None:
        """CSP connect-src must allow API Gateway endpoints."""
        connect_src = csp_directives.get("connect-src", "")
        # Must use specific region, not wildcards like *.execute-api.*.amazonaws.com
        assert "execute-api" in connect_src and "us-west-2" in connect_src, (
            "CSP connect-src missing API Gateway domain with specific region. "
            "API calls will be blocked by browser. "
            "Note: Wildcards like *.region.* are invalid in CSP."
        )

    def test_csp_connect_src_includes_cognito_idp(self, csp_directives: dict[str, str]) -> None:
        """CSP connect-src must allow Cognito IDP endpoints."""
        connect_src = csp_directives.get("connect-src", "")
        # Must use specific region, not wildcards
        assert (
            "cognito-idp.us-west-2" in connect_src
        ), "CSP connect-src missing Cognito IDP domain with region. Token validation will fail."

    def test_csp_connect_src_includes_cognito_oauth(self, csp_directives: dict[str, str]) -> None:
        """CSP connect-src must allow Cognito OAuth endpoints for token exchange.

        This is the critical test that would have caught the bug where
        token exchange was blocked by CSP because amazoncognito.com
        was not in the allowed domains.
        """
        connect_src = csp_directives.get("connect-src", "")
        assert "amazoncognito.com" in connect_src, (
            "CSP connect-src missing amazoncognito.com domain. "
            "OAuth token exchange will be blocked by browser CSP! "
            "The user will authenticate successfully but tokens will not be received."
        )

    def test_csp_has_self(self, csp_directives: dict[str, str]) -> None:
        """CSP connect-src must include 'self' for same-origin requests."""
        connect_src = csp_directives.get("connect-src", "")
        assert "'self'" in connect_src


class TestOAuthConfiguration:
    """Tests for OAuth configuration in dashboard JavaScript."""

    @pytest.fixture
    def html_content(self) -> str:
        """Load the dashboard HTML content."""
        return DASHBOARD_HTML_PATH.read_text()

    @pytest.fixture
    def config_block(self, html_content: str) -> str:
        """Extract the CONFIG object from JavaScript."""
        match = re.search(r"const CONFIG\s*=\s*\{([^}]+)\}", html_content, re.DOTALL)
        assert match, "CONFIG object not found in dashboard JavaScript"
        return match.group(1)

    def test_config_has_cognito_domain(self, config_block: str) -> None:
        """Config must have cognitoDomain for OAuth."""
        assert "cognitoDomain" in config_block

    def test_config_has_client_id(self, config_block: str) -> None:
        """Config must have clientId for OAuth."""
        assert "clientId" in config_block

    def test_config_has_api_endpoint(self, config_block: str) -> None:
        """Config must have apiEndpoint for data fetching."""
        assert "apiEndpoint" in config_block

    def test_config_has_redirect_uri(self, config_block: str) -> None:
        """Config must have redirectUri for OAuth callback."""
        assert "redirectUri" in config_block

    def test_redirect_uri_uses_https(self, html_content: str) -> None:
        """Redirect URI must use HTTPS for security."""
        match = re.search(r"redirectUri:\s*['\"]([^'\"]+)['\"]", html_content)
        assert match, "redirectUri not found"
        redirect_uri = match.group(1)
        assert redirect_uri.startswith(
            "https://"
        ), f"redirectUri must use HTTPS, got: {redirect_uri}"


class TestAuthenticationFlow:
    """Tests for authentication flow JavaScript functions."""

    @pytest.fixture
    def html_content(self) -> str:
        """Load the dashboard HTML content."""
        return DASHBOARD_HTML_PATH.read_text()

    def test_login_function_exists(self, html_content: str) -> None:
        """Login function must exist."""
        assert "function login()" in html_content

    def test_logout_function_exists(self, html_content: str) -> None:
        """Logout function must exist."""
        assert "function logout()" in html_content

    def test_token_exchange_function_exists(self, html_content: str) -> None:
        """Token exchange function must exist."""
        assert "function exchangeCodeForTokens" in html_content

    def test_handle_callback_function_exists(self, html_content: str) -> None:
        """Callback handler function must exist."""
        assert "function handleCallback()" in html_content

    def test_fetch_with_auth_uses_bearer_token(self, html_content: str) -> None:
        """API calls must use Bearer token authentication."""
        assert "Bearer" in html_content, "Authorization header should use Bearer scheme"

    def test_tokens_stored_in_session_storage(self, html_content: str) -> None:
        """Tokens should be stored in sessionStorage (not localStorage)."""
        assert "sessionStorage" in html_content, "Tokens should use sessionStorage for security"


class TestSecurityHeaders:
    """Tests for security headers in HTML."""

    @pytest.fixture
    def html_content(self) -> str:
        """Load the dashboard HTML content."""
        return DASHBOARD_HTML_PATH.read_text()

    def test_csp_prevents_inline_script_execution(self, html_content: str) -> None:
        """CSP should be present to prevent XSS attacks."""
        assert "Content-Security-Policy" in html_content

    def test_no_external_scripts_without_integrity(self, html_content: str) -> None:
        """External scripts should have integrity attributes (SRI)."""
        # Find all script tags with src attributes
        external_scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', html_content)
        # Currently we don't use external scripts, which is safest
        assert (
            len(external_scripts) == 0
        ), f"External scripts found: {external_scripts}. Consider using SRI integrity attributes."


class TestCORSConfiguration:
    """Tests for CORS configuration in CDK stack."""

    def test_cors_origins_match_domain(self) -> None:
        """CORS origins in CDK should include the dashboard domain."""
        cdk_path = (
            Path(__file__).parent.parent
            / "infrastructure"
            / "cdk"
            / "stacks"
            / "health_dashboard.py"
        )
        content = cdk_path.read_text()

        # Check that CORS is configured
        assert "cors" in content.lower(), "CORS configuration not found in CDK stack"

        # Check that allowed origins includes the domain
        assert "domain_name" in content, "Domain name should be used for CORS origins"


class TestRequiredDomains:
    """Comprehensive test for all required AWS domains in CSP.

    This test documents all AWS domains that must be in CSP connect-src
    for a Cognito-authenticated application to work properly.
    """

    REQUIRED_DOMAINS = [
        ("execute-api.us-west-2", "API Gateway endpoints for data fetching"),
        ("cognito-idp.us-west-2", "Cognito Identity Provider for token validation"),
        ("amazoncognito.com", "Cognito OAuth endpoints for token exchange"),
    ]

    @pytest.fixture
    def csp_connect_src(self) -> str:
        """Extract connect-src from CSP."""
        content = DASHBOARD_HTML_PATH.read_text()
        match = re.search(r"connect-src\s+([^;]+)", content)
        assert match, "connect-src directive not found in CSP"
        return match.group(1)

    @pytest.mark.parametrize("domain,reason", REQUIRED_DOMAINS)
    def test_required_domain_in_csp(self, csp_connect_src: str, domain: str, reason: str) -> None:
        """Each required domain must be in CSP connect-src."""
        assert domain in csp_connect_src, f"CSP connect-src missing '{domain}'. Reason: {reason}"
