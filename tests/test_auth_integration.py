"""End-to-end integration tests: login -> route -> Cedar -> logout."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from secdashboards.web.app import create_app
from secdashboards.web.auth.cedar_engine import init_cedar_engine, reset_for_testing
from secdashboards.web.auth.cognito import reset_jwks_cache
from secdashboards.web.auth.session import InMemoryBackend
from secdashboards.web.config import WebConfig

CEDAR_DIR = Path(__file__).parent.parent / "src" / "secdashboards" / "web" / "cedar"


@pytest.fixture
def full_auth_app():
    """App with auth + Cedar both enabled."""
    reset_jwks_cache()
    reset_for_testing()

    # Manually initialize Cedar (TestClient doesn't trigger lifespan)
    init_cedar_engine(
        schema_path=str(CEDAR_DIR / "schema.cedarschema.json"),
        policy_dir=str(CEDAR_DIR / "policies"),
    )

    config = WebConfig(
        duckdb_path=":memory:",
        auth_enabled=True,
        cognito_client_id="test-client-id",
        cognito_client_secret="",
        cognito_user_pool_id="us-west-2_test123",
        cognito_domain="test.auth.us-west-2.amazoncognito.com",
        cognito_region="us-west-2",
        session_secret_key="test-secret-key-for-sessions",
        cedar_enabled=True,
    )

    backend = InMemoryBackend()
    with patch(
        "secdashboards.web.app._build_session_backend",
        return_value=backend,
    ):
        app = create_app(config)

    return app


@pytest.fixture
def full_client(full_auth_app):
    return TestClient(full_auth_app, cookies={})


def test_unauthenticated_html_redirects_to_login(full_client):
    """Unauthenticated HTML request → /auth/login → Cognito."""
    resp = full_client.get("/", headers={"accept": "text/html"}, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/auth/login"


def test_unauthenticated_api_returns_401(full_client):
    """Unauthenticated API request → 401 JSON."""
    resp = full_client.get("/api/health")
    # Health is exempt
    assert resp.status_code == 200

    resp = full_client.get("/", headers={"accept": "application/json"})
    assert resp.status_code == 401


def test_full_login_flow(full_client, valid_id_token, valid_access_token, jwks_response):
    """Complete flow: create session → access protected route → logout."""
    # Step 1: Create session (simulating passkey login)
    with patch(
        "secdashboards.web.auth.cognito._fetch_jwks",
        new_callable=AsyncMock,
        return_value=jwks_response,
    ):
        resp = full_client.post(
            "/auth/session",
            json={
                "access_token": valid_access_token,
                "id_token": valid_id_token,
                "refresh_token": "test-refresh",
                "auth_method": "direct",
            },
            headers={"X-L42-CSRF": "1"},
        )
        assert resp.status_code == 200

    # Step 2: Access protected route
    resp = full_client.get("/", headers={"accept": "text/html"})
    assert resp.status_code == 200

    # Step 3: Check user info
    resp = full_client.get("/auth/me")
    assert resp.status_code == 200
    assert resp.json()["email"] == "test@example.com"

    # Step 4: Authorize action via Cedar
    resp = full_client.post(
        "/auth/authorize",
        json={"action": "view:dashboard"},
        headers={"X-L42-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert resp.json()["authorized"] is True

    # Step 5: Logout
    resp = full_client.post("/auth/logout", headers={"X-L42-CSRF": "1"})
    assert resp.status_code == 200

    # Step 6: Verify logged out
    resp = full_client.get("/", headers={"accept": "text/html"}, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/auth/login"


def test_readonly_user_cedar_denied(full_client, make_jwt, make_access_token, jwks_response):
    """Read-only user can view dashboard but cannot deploy."""
    id_token = make_jwt(groups=["read-only"])
    access_token = make_access_token(groups=["read-only"])

    with patch(
        "secdashboards.web.auth.cognito._fetch_jwks",
        new_callable=AsyncMock,
        return_value=jwks_response,
    ):
        resp = full_client.post(
            "/auth/session",
            json={
                "access_token": access_token,
                "id_token": id_token,
                "auth_method": "direct",
            },
            headers={"X-L42-CSRF": "1"},
        )
        assert resp.status_code == 200

    # Can view dashboard
    resp = full_client.post(
        "/auth/authorize",
        json={"action": "view:dashboard"},
        headers={"X-L42-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert resp.json()["authorized"] is True

    # Cannot deploy
    resp = full_client.post(
        "/auth/authorize",
        json={"action": "deploy:lambda"},
        headers={"X-L42-CSRF": "1"},
    )
    assert resp.status_code == 403
    assert resp.json()["authorized"] is False
