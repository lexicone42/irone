"""End-to-end tests against the live iris.lexicone.com deployment.

These tests authenticate against the real Cognito User Pool and exercise
the live API behind CloudFront. They are skipped by default and gated
behind the RUN_E2E_TESTS environment variable.

Usage:
    RUN_E2E_TESTS=1 \
    SECDASH_E2E_PASSWORD='...' \
    SECDASH_E2E_CLIENT_SECRET='...' \
    SECDASH_E2E_CLIENT_ID='...' \
    uv run pytest tests/test_e2e.py -v

Environment variables:
    RUN_E2E_TESTS:              Set to "1" to enable tests
    SECDASH_E2E_PASSWORD:       Password for e2e-test@iris.lexicone.com
    SECDASH_E2E_CLIENT_SECRET:  Cognito web client secret
    SECDASH_E2E_CLIENT_ID:      Cognito web client ID
    SECDASH_E2E_BASE_URL:       Optional, defaults to https://iris.lexicone.com
"""

import base64
import hashlib
import hmac
import os

import httpx
import pytest

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BASE_URL = os.environ.get("SECDASH_E2E_BASE_URL", "https://iris.lexicone.com")
E2E_USERNAME = "e2e-test@iris.lexicone.com"
E2E_PASSWORD = os.environ.get("SECDASH_E2E_PASSWORD", "")
CLIENT_ID = os.environ.get("SECDASH_E2E_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("SECDASH_E2E_CLIENT_SECRET", "")
COGNITO_REGION = "us-west-2"
COGNITO_IDP_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com"

TIMEOUT = 30.0  # Lambda cold starts can be slow

# ---------------------------------------------------------------------------
# Skip all tests unless gated env var is set
# ---------------------------------------------------------------------------

pytestmark = [
    pytest.mark.skipif(
        not os.environ.get("RUN_E2E_TESTS"),
        reason="E2E tests disabled. Set RUN_E2E_TESTS=1 to enable.",
    ),
    pytest.mark.e2e,
]


# ---------------------------------------------------------------------------
# Cognito auth helpers
# ---------------------------------------------------------------------------


def _compute_secret_hash(username: str, client_id: str, client_secret: str) -> str:
    """Compute Cognito SECRET_HASH = Base64(HMAC_SHA256(client_secret, username + client_id))."""
    message = username + client_id
    dig = hmac.new(
        client_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.b64encode(dig).decode("utf-8")


def _cognito_initiate_auth() -> dict:
    """Authenticate via Cognito USER_PASSWORD_AUTH and return tokens."""
    secret_hash = _compute_secret_hash(E2E_USERNAME, CLIENT_ID, CLIENT_SECRET)

    resp = httpx.post(
        COGNITO_IDP_URL,
        headers={
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
        },
        json={
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": CLIENT_ID,
            "AuthParameters": {
                "USERNAME": E2E_USERNAME,
                "PASSWORD": E2E_PASSWORD,
                "SECRET_HASH": secret_hash,
            },
        },
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    result = resp.json()["AuthenticationResult"]
    return {
        "access_token": result["AccessToken"],
        "id_token": result["IdToken"],
        "refresh_token": result.get("RefreshToken", ""),
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def cognito_tokens() -> dict:
    """Authenticate once against Cognito and return tokens for the module."""
    return _cognito_initiate_auth()


@pytest.fixture(scope="module")
def authed_client(cognito_tokens: dict) -> httpx.Client:
    """Return an httpx.Client with a valid session cookie.

    Establishes the session by posting tokens to /auth/session (the same
    path the frontend uses), then reuses that session cookie for all
    subsequent requests in the module.
    """
    client = httpx.Client(base_url=BASE_URL, timeout=TIMEOUT, follow_redirects=False)

    resp = client.post(
        "/auth/session",
        json={
            "access_token": cognito_tokens["access_token"],
            "id_token": cognito_tokens["id_token"],
            "refresh_token": cognito_tokens.get("refresh_token"),
            "auth_method": "direct",
        },
        headers={"X-L42-CSRF": "1"},
    )
    assert resp.status_code == 200, f"Session creation failed: {resp.text}"
    assert resp.json().get("success") is True

    return client


# ---------------------------------------------------------------------------
# Public endpoints (no auth required)
# ---------------------------------------------------------------------------


class TestPublicEndpoints:
    def test_health(self):
        """GET /api/health returns status: ok (exempt from auth)."""
        resp = httpx.get(f"{BASE_URL}/api/health", timeout=TIMEOUT)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_auth_config(self):
        """GET /api/auth/config returns Cognito config (exempt from auth)."""
        resp = httpx.get(f"{BASE_URL}/api/auth/config", timeout=TIMEOUT)
        assert resp.status_code == 200
        data = resp.json()
        assert "auth_enabled" in data
        assert "cognito_domain" in data
        assert "cognito_client_id" in data

    def test_unauthenticated_api_returns_401(self):
        """GET /api/sources without auth returns 401 JSON."""
        resp = httpx.get(
            f"{BASE_URL}/api/sources",
            timeout=TIMEOUT,
            headers={"Accept": "application/json"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class TestAuthentication:
    def test_session_created(self, authed_client: httpx.Client):
        """After login, the session cookie should be present."""
        assert any("secdash_session" in str(c) for c in authed_client.cookies.jar)

    def test_auth_me(self, authed_client: httpx.Client):
        """GET /auth/me returns user info from the session."""
        resp = authed_client.get("/auth/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == E2E_USERNAME
        assert "sub" in data
        assert isinstance(data.get("groups"), list)


# ---------------------------------------------------------------------------
# Dashboard API
# ---------------------------------------------------------------------------


class TestDashboardAPI:
    def test_dashboard_summary(self, authed_client: httpx.Client):
        """GET /api/dashboard returns summary stats."""
        resp = authed_client.get("/api/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert "source_count" in data
        assert "rule_count" in data
        assert "health" in data


# ---------------------------------------------------------------------------
# Sources API
# ---------------------------------------------------------------------------


class TestSourcesAPI:
    def test_list_sources(self, authed_client: httpx.Client):
        """GET /api/sources returns a list."""
        resp = authed_client.get("/api/sources")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_sources_health(self, authed_client: httpx.Client):
        """GET /api/sources/health returns health data."""
        resp = authed_client.get("/api/sources/health")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)


# ---------------------------------------------------------------------------
# Rules API
# ---------------------------------------------------------------------------


class TestRulesAPI:
    def test_list_rules(self, authed_client: httpx.Client):
        """GET /api/rules returns a list of detection rules."""
        resp = authed_client.get("/api/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)


# ---------------------------------------------------------------------------
# Investigations API
# ---------------------------------------------------------------------------


class TestInvestigationsAPI:
    def test_list_investigations(self, authed_client: httpx.Client):
        """GET /api/investigations returns a list."""
        resp = authed_client.get("/api/investigations")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_create_and_delete(self, authed_client: httpx.Client):
        """POST + DELETE investigation round-trip with cleanup."""
        inv_id = None
        try:
            # Create
            resp = authed_client.post(
                "/api/investigations",
                json={"name": "e2e-test-investigation", "users": [], "ips": []},
                headers={"X-L42-CSRF": "1"},
            )
            assert resp.status_code == 200
            data = resp.json()
            inv_id = data.get("id")
            assert inv_id is not None
            assert inv_id.startswith("inv-")

            # Verify it appears in the list
            resp = authed_client.get("/api/investigations")
            assert resp.status_code == 200
            ids = [inv["id"] for inv in resp.json()]
            assert inv_id in ids
        finally:
            # Always clean up
            if inv_id:
                resp = authed_client.delete(
                    f"/api/investigations/{inv_id}",
                    headers={"X-L42-CSRF": "1"},
                )
                assert resp.status_code == 200
