"""Shared fixtures for the secdashboards auth test suite."""

from __future__ import annotations

import base64
import time
from typing import Any
from unittest.mock import AsyncMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from secdashboards.web.app import create_app
from secdashboards.web.auth.cognito import reset_jwks_cache
from secdashboards.web.auth.session import InMemoryBackend
from secdashboards.web.config import WebConfig

# ── RSA Key Pair (generated once per test session) ────────────────────────


@pytest.fixture(scope="session")
def rsa_private_key():
    """Generate a test RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def rsa_public_key(rsa_private_key):
    return rsa_private_key.public_key()


@pytest.fixture(scope="session")
def jwk_dict(rsa_public_key) -> dict[str, Any]:
    """Build a JWK dict from the test RSA public key."""
    public_numbers = rsa_public_key.public_numbers()

    def _int_to_b64(n: int, length: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(length, byteorder="big")).decode().rstrip("=")

    return {
        "kty": "RSA",
        "kid": "test-key-1",
        "use": "sig",
        "alg": "RS256",
        "n": _int_to_b64(public_numbers.n, 256),
        "e": _int_to_b64(public_numbers.e, 3),
    }


@pytest.fixture(scope="session")
def jwks_response(jwk_dict) -> dict[str, Any]:
    """JWKS response with the test key."""
    return {"keys": [jwk_dict]}


# ── JWT Factory ───────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def rsa_private_key_pem(rsa_private_key) -> bytes:
    return rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture
def make_jwt(rsa_private_key_pem):
    """Factory for creating signed JWTs for testing."""

    def _make(
        sub: str = "user-123",
        email: str = "test@example.com",
        groups: list[str] | None = None,
        exp: int | None = None,
        iss: str = "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_test123",
        aud: str = "test-client-id",
        token_use: str = "id",
        extra_claims: dict | None = None,
    ) -> str:
        now = int(time.time())
        payload = {
            "sub": sub,
            "email": email,
            "iss": iss,
            "aud": aud,
            "iat": now,
            "exp": exp or (now + 3600),
            "token_use": token_use,
        }
        if groups is not None:
            payload["cognito:groups"] = groups
        if extra_claims:
            payload.update(extra_claims)

        return jwt.encode(
            payload,
            rsa_private_key_pem,
            algorithm="RS256",
            headers={"kid": "test-key-1"},
        )

    return _make


@pytest.fixture
def make_access_token(make_jwt):
    """Factory for access tokens."""

    def _make(sub: str = "user-123", groups: list[str] | None = None, **kwargs):
        return make_jwt(sub=sub, groups=groups, token_use="access", aud="test-client-id", **kwargs)

    return _make


@pytest.fixture
def valid_id_token(make_jwt) -> str:
    """A valid, signed ID token for the default test user."""
    return make_jwt(groups=["admin"])


@pytest.fixture
def valid_access_token(make_access_token) -> str:
    return make_access_token(groups=["admin"])


@pytest.fixture
def expired_id_token(make_jwt) -> str:
    return make_jwt(exp=int(time.time()) - 100)


@pytest.fixture
def expired_access_token(make_access_token) -> str:
    return make_access_token(exp=int(time.time()) - 100)


# ── Auth-Enabled App & Client ─────────────────────────────────────────────


@pytest.fixture
def auth_config() -> WebConfig:
    """WebConfig with auth enabled and test values."""
    return WebConfig(
        duckdb_path=":memory:",
        auth_enabled=True,
        cognito_client_id="test-client-id",
        cognito_client_secret="",
        cognito_user_pool_id="us-west-2_test123",
        cognito_domain="test.auth.us-west-2.amazoncognito.com",
        cognito_region="us-west-2",
        session_secret_key="test-secret-key-for-sessions",
        cedar_enabled=False,  # Disabled by default in tests
    )


@pytest.fixture
def session_backend() -> InMemoryBackend:
    return InMemoryBackend()


@pytest.fixture
def auth_app(auth_config, session_backend):
    """Create a secdashboards app with auth enabled (Cedar disabled)."""
    reset_jwks_cache()

    # We need to configure cognito before creating the app since create_app
    # calls configure_cognito internally, but we also want to control it.
    # The app factory handles this, so we just create the app.
    # However, we need to inject the session_backend.
    # We'll patch _build_session_backend to return our backend.
    with patch(
        "secdashboards.web.app._build_session_backend",
        return_value=session_backend,
    ):
        app = create_app(auth_config)

    return app


@pytest.fixture
def auth_client(auth_app) -> TestClient:
    """TestClient with cookie persistence for auth-enabled app."""
    return TestClient(auth_app, cookies={})


# ── Helper: Authenticated Client ──────────────────────────────────────────


@pytest.fixture
def auth_session(auth_client, valid_id_token, valid_access_token, jwks_response):
    """Set up an authenticated session and return the client.

    POSTs to /auth/session with valid tokens, mock-verified via JWKS.
    """
    with patch(
        "secdashboards.web.auth.cognito._fetch_jwks",
        new_callable=AsyncMock,
        return_value=jwks_response,
    ):
        resp = auth_client.post(
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
    return auth_client


@pytest.fixture
def csrf_headers() -> dict[str, str]:
    """Standard CSRF headers for POST requests."""
    return {"X-L42-CSRF": "1"}
