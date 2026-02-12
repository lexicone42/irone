"""Tests for POST /auth/refresh."""

from unittest.mock import AsyncMock, patch


def test_refresh_unauthenticated(auth_client, csrf_headers):
    resp = auth_client.post("/auth/refresh", headers=csrf_headers)
    assert resp.status_code == 401


def test_refresh_no_refresh_token(
    auth_client, valid_id_token, valid_access_token, jwks_response, csrf_headers
):
    """Session with no refresh_token returns 401."""
    with patch(
        "secdashboards.web.auth.cognito._fetch_jwks",
        new_callable=AsyncMock,
        return_value=jwks_response,
    ):
        auth_client.post(
            "/auth/session",
            json={
                "access_token": valid_access_token,
                "id_token": valid_id_token,
                "auth_method": "direct",
            },
            headers=csrf_headers,
        )

    resp = auth_client.post("/auth/refresh", headers=csrf_headers)
    assert resp.status_code == 401
    assert resp.json()["error"] == "No refresh token"


def test_refresh_success(auth_session, csrf_headers, valid_id_token, valid_access_token):
    with patch(
        "secdashboards.web.auth.routes.refresh.cognito_request",
        new_callable=AsyncMock,
        return_value={
            "AuthenticationResult": {
                "AccessToken": "new-access-token",
                "IdToken": valid_id_token,
            }
        },
    ):
        resp = auth_session.post("/auth/refresh", headers=csrf_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["access_token"] == "new-access-token"
    assert data["id_token"] == valid_id_token


def test_refresh_failure_destroys_session(auth_session, csrf_headers):
    with patch(
        "secdashboards.web.auth.routes.refresh.cognito_request",
        new_callable=AsyncMock,
        side_effect=RuntimeError("Cognito error"),
    ):
        resp = auth_session.post("/auth/refresh", headers=csrf_headers)
    assert resp.status_code == 401

    # Session should be destroyed — token endpoint returns 401
    resp = auth_session.get("/auth/token")
    assert resp.status_code == 401
