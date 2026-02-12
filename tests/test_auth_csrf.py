"""Tests for CSRF protection."""


def test_csrf_required_on_session(auth_client, valid_id_token, valid_access_token):
    """POST /auth/session requires X-L42-CSRF header."""
    resp = auth_client.post(
        "/auth/session",
        json={
            "access_token": valid_access_token,
            "id_token": valid_id_token,
        },
    )
    assert resp.status_code == 403
    assert "CSRF" in resp.json()["detail"]["error"]


def test_csrf_required_on_logout(auth_session):
    resp = auth_session.post("/auth/logout")
    assert resp.status_code == 403


def test_csrf_required_on_refresh(auth_session):
    resp = auth_session.post("/auth/refresh")
    assert resp.status_code == 403


def test_csrf_wrong_value(auth_client, valid_id_token, valid_access_token):
    """CSRF header with wrong value should fail."""
    resp = auth_client.post(
        "/auth/session",
        json={
            "access_token": valid_access_token,
            "id_token": valid_id_token,
        },
        headers={"X-L42-CSRF": "0"},
    )
    assert resp.status_code == 403


def test_csrf_correct_value_passes(auth_client, valid_id_token, valid_access_token, jwks_response):
    """X-L42-CSRF: 1 should pass."""
    from unittest.mock import AsyncMock, patch

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
                "auth_method": "direct",
            },
            headers={"X-L42-CSRF": "1"},
        )
    assert resp.status_code == 200
