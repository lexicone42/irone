"""Tests for GET /auth/me."""


def test_me_unauthenticated(auth_client):
    resp = auth_client.get("/auth/me")
    assert resp.status_code == 401


def test_me_returns_user_info(auth_session):
    resp = auth_session.get("/auth/me")
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "test@example.com"
    assert data["sub"] == "user-123"
    assert "admin" in data["groups"]
