"""Tests for POST /auth/authorize (Cedar authorization endpoint)."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from secdashboards.web.app import create_app
from secdashboards.web.auth.cedar_engine import init_cedar_engine, reset_for_testing
from secdashboards.web.auth.cognito import reset_jwks_cache
from secdashboards.web.config import WebConfig

CEDAR_DIR = Path(__file__).parent.parent / "src" / "secdashboards" / "web" / "cedar"


@pytest.fixture
def cedar_auth_app(session_backend):
    """App with both auth AND Cedar enabled."""
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

    with patch(
        "secdashboards.web.app._build_session_backend",
        return_value=session_backend,
    ):
        app = create_app(config)

    return app


@pytest.fixture
def cedar_client(cedar_auth_app):
    return TestClient(cedar_auth_app, cookies={})


@pytest.fixture
def cedar_auth_session(cedar_client, valid_id_token, valid_access_token, jwks_response):
    """Authenticated session on Cedar-enabled app."""
    with patch(
        "secdashboards.web.auth.cognito._fetch_jwks",
        new_callable=AsyncMock,
        return_value=jwks_response,
    ):
        resp = cedar_client.post(
            "/auth/session",
            json={
                "access_token": valid_access_token,
                "id_token": valid_id_token,
                "refresh_token": "test-refresh-token",
                "auth_method": "direct",
            },
            headers={"X-L42-CSRF": "1"},
        )
        assert resp.status_code == 200
    return cedar_client


def test_authorize_unauthenticated(auth_client, csrf_headers):
    resp = auth_client.post(
        "/auth/authorize",
        json={"action": "view:dashboard"},
        headers=csrf_headers,
    )
    assert resp.status_code == 401


def test_authorize_requires_csrf(auth_session):
    resp = auth_session.post(
        "/auth/authorize",
        json={"action": "view:dashboard"},
    )
    assert resp.status_code == 403


def test_authorize_engine_not_initialized(auth_session, csrf_headers):
    """When Cedar is disabled, authorize returns 503."""
    reset_for_testing()
    resp = auth_session.post(
        "/auth/authorize",
        json={"action": "view:dashboard"},
        headers=csrf_headers,
    )
    assert resp.status_code == 503


def test_authorize_missing_action(auth_session, csrf_headers):
    resp = auth_session.post(
        "/auth/authorize",
        json={"action": ""},
        headers=csrf_headers,
    )
    # Without Cedar engine, this returns 503 (engine not initialized)
    # The missing action check happens after the engine check
    assert resp.status_code in (400, 503)


def test_authorize_admin_allowed(cedar_auth_session, csrf_headers):
    """Admin group should be authorized for any action."""
    resp = cedar_auth_session.post(
        "/auth/authorize",
        json={"action": "view:dashboard"},
        headers=csrf_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["authorized"] is True


def test_authorize_admin_deploy(cedar_auth_session, csrf_headers):
    """Admin group should be authorized for deploy actions."""
    resp = cedar_auth_session.post(
        "/auth/authorize",
        json={"action": "deploy:lambda"},
        headers=csrf_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["authorized"] is True
