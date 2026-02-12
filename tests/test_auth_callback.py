"""Tests for GET /auth/callback."""

from unittest.mock import AsyncMock, patch


def test_callback_success(auth_client, valid_id_token, valid_access_token):
    """Successful OAuth callback stores tokens and redirects to /."""
    with patch(
        "secdashboards.web.auth.routes.callback.exchange_code_for_tokens",
        new_callable=AsyncMock,
        return_value={
            "access_token": valid_access_token,
            "id_token": valid_id_token,
            "refresh_token": "oauth-refresh",
        },
    ):
        resp = auth_client.get(
            "/auth/callback?code=test-code&state=test-state",
            follow_redirects=False,
        )
    assert resp.status_code == 307
    assert resp.headers["location"] == "/"


def test_callback_error_param_redirects(auth_client):
    """OAuth error from Cognito redirects with error message."""
    resp = auth_client.get(
        "/auth/callback?error=access_denied&error_description=User+cancelled",
        follow_redirects=False,
    )
    assert resp.status_code == 307
    assert "error=" in resp.headers["location"]


def test_callback_missing_code_redirects(auth_client):
    resp = auth_client.get("/auth/callback", follow_redirects=False)
    assert resp.status_code == 307
    assert "Missing" in resp.headers["location"]


def test_callback_exchange_failure(auth_client):
    with patch(
        "secdashboards.web.auth.routes.callback.exchange_code_for_tokens",
        new_callable=AsyncMock,
        side_effect=RuntimeError("Token exchange failed"),
    ):
        resp = auth_client.get(
            "/auth/callback?code=bad-code",
            follow_redirects=False,
        )
    assert resp.status_code == 307
    assert "error=" in resp.headers["location"]
