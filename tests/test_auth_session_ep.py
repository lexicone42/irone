"""Tests for POST /auth/session."""

from unittest.mock import AsyncMock, patch


def test_create_session_stores_tokens(
    auth_client, valid_id_token, valid_access_token, jwks_response, csrf_headers
):
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
                "refresh_token": "test-refresh",
                "auth_method": "direct",
            },
            headers=csrf_headers,
        )
    assert resp.status_code == 200
    assert resp.json() == {"success": True}


def test_create_session_rejects_invalid_token(auth_client, csrf_headers):
    with patch(
        "secdashboards.web.auth.cognito._fetch_jwks",
        new_callable=AsyncMock,
        side_effect=Exception("JWKS fetch failed"),
    ):
        resp = auth_client.post(
            "/auth/session",
            json={
                "access_token": "bad-token",
                "id_token": "bad-token",
                "auth_method": "direct",
            },
            headers=csrf_headers,
        )
    assert resp.status_code == 403
    assert resp.json()["error"] == "Token verification failed"


def test_create_session_requires_csrf(auth_client, valid_id_token, valid_access_token):
    resp = auth_client.post(
        "/auth/session",
        json={
            "access_token": valid_access_token,
            "id_token": valid_id_token,
        },
    )
    assert resp.status_code == 403


def test_create_session_missing_tokens(auth_client, csrf_headers):
    resp = auth_client.post(
        "/auth/session",
        json={"access_token": "", "id_token": ""},
        headers=csrf_headers,
    )
    assert resp.status_code == 400
