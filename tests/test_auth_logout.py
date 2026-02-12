"""Tests for POST /auth/logout."""


def test_logout_destroys_session(auth_session, csrf_headers):
    resp = auth_session.post("/auth/logout", headers=csrf_headers)
    assert resp.status_code == 200
    assert resp.json() == {"success": True}

    # Session should be destroyed
    resp = auth_session.get("/auth/token")
    assert resp.status_code == 401


def test_logout_requires_csrf(auth_session):
    resp = auth_session.post("/auth/logout")
    assert resp.status_code == 403


def test_logout_without_session(auth_client, csrf_headers):
    """Logout without a session still succeeds (idempotent)."""
    resp = auth_client.post("/auth/logout", headers=csrf_headers)
    assert resp.status_code == 200
