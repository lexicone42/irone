"""Tests for auth enforcement middleware: exempt paths, redirect vs 401."""


def test_health_endpoint_exempt(auth_client):
    """Health endpoint should be accessible without auth."""
    resp = auth_client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_auth_routes_exempt(auth_client):
    """Auth routes should be accessible without auth."""
    resp = auth_client.get("/auth/login", follow_redirects=False)
    # Login redirects to Cognito — should not be blocked by middleware
    assert resp.status_code in (307, 302)


def test_api_request_returns_401(auth_client):
    """API request without session should return 401 JSON."""
    resp = auth_client.get(
        "/",
        headers={"accept": "application/json"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "Not authenticated"


def test_html_request_redirects_to_login(auth_client):
    """HTML request without session should redirect to /auth/login."""
    resp = auth_client.get(
        "/",
        headers={"accept": "text/html"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/auth/login"


def test_authenticated_request_passes(auth_session):
    """Authenticated request should reach the dashboard."""
    resp = auth_session.get(
        "/",
        headers={"accept": "text/html"},
    )
    assert resp.status_code == 200


def test_static_exempt(auth_client):
    """Static files should be exempt from auth.

    Note: actual static file serving may 404 in tests, but the middleware
    should not block it.
    """
    resp = auth_client.get("/static/css/terminal.css")
    # 200 if file exists, 404 if not, but NOT 401/302
    assert resp.status_code != 401
    assert resp.status_code != 302


def test_auth_me_requires_session(auth_client):
    """Auth routes that need tokens still return 401 from the Depends()."""
    resp = auth_client.get("/auth/me")
    assert resp.status_code == 401
