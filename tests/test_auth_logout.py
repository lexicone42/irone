"""Tests for GET /auth/logout."""


def test_logout_destroys_session(auth_session):
    resp = auth_session.get("/auth/logout", follow_redirects=False)
    assert resp.status_code == 302

    # Session should be destroyed — token endpoint returns 401
    resp = auth_session.get("/auth/token")
    assert resp.status_code == 401


def test_logout_without_session(auth_client):
    """Logout without a session still redirects (idempotent)."""
    resp = auth_client.get("/auth/logout", follow_redirects=False)
    assert resp.status_code == 302


def test_logout_redirects_to_cognito(auth_session):
    """With Cognito config, logout redirects to Cognito's /logout endpoint."""
    resp = auth_session.get("/auth/logout", follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "amazoncognito.com/logout" in location
    assert "client_id=" in location
    assert "logout_uri=" in location
