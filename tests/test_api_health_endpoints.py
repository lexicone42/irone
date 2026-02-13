"""Tests for the JSON API health and dashboard endpoints."""

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from secdashboards.web.app import create_app
from secdashboards.web.config import WebConfig


@pytest.fixture
def app():
    config = WebConfig(duckdb_path=":memory:")
    return create_app(config)


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def mock_cache():
    """Create a mock HealthCacheClient."""
    cache = MagicMock()
    cache.get_latest.return_value = None
    cache.get_all_latest.return_value = []
    cache.get_history.return_value = []
    cache.put_many = MagicMock()
    return cache


@pytest.fixture
def app_with_cache(app, mock_cache):
    """Attach a mock health cache to the app state."""
    app.state.secdash.health_cache = mock_cache
    return app


@pytest.fixture
def client_with_cache(app_with_cache):
    return TestClient(app_with_cache)


# Sample cached health data
CACHED_HEALTH = [
    {
        "source_name": "cloudtrail",
        "checked_at": "2026-02-13T12:00:00+00:00",
        "healthy": True,
        "record_count": 1500,
        "latency_seconds": 0.3,
        "last_data_time": "2026-02-13T11:55:00+00:00",
        "data_age_minutes": 5.0,
        "error": None,
        "details": {},
    },
    {
        "source_name": "vpc-flow",
        "checked_at": "2026-02-13T12:00:00+00:00",
        "healthy": False,
        "record_count": 0,
        "latency_seconds": 5.0,
        "last_data_time": None,
        "data_age_minutes": None,
        "error": "Timeout",
        "details": {},
    },
]


class TestAllSourcesHealth:
    def test_returns_live_check_when_no_cache(self, client) -> None:
        resp = client.get("/api/sources/health")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        # Should have at least duckdb-local from live check
        assert any(r["source_name"] == "duckdb-local" for r in data)

    def test_returns_cached_data(self, client_with_cache, mock_cache) -> None:
        mock_cache.get_all_latest.return_value = CACHED_HEALTH
        resp = client_with_cache.get("/api/sources/health")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        assert data[0]["source_name"] == "cloudtrail"
        assert data[1]["source_name"] == "vpc-flow"
        mock_cache.get_all_latest.assert_called_once()

    def test_live_bypasses_cache(self, client_with_cache, mock_cache) -> None:
        mock_cache.get_all_latest.return_value = CACHED_HEALTH
        resp = client_with_cache.get("/api/sources/health?live=true")
        assert resp.status_code == 200
        data = resp.json()
        # Should get live results (duckdb-local), not cached
        assert any(r["source_name"] == "duckdb-local" for r in data)

    def test_falls_back_to_live_when_cache_empty(self, client_with_cache, mock_cache) -> None:
        mock_cache.get_all_latest.return_value = []
        resp = client_with_cache.get("/api/sources/health")
        assert resp.status_code == 200
        data = resp.json()
        # Live fallback should return duckdb-local
        assert any(r["source_name"] == "duckdb-local" for r in data)


class TestSingleSourceHealth:
    def test_live_check(self, client) -> None:
        resp = client.get("/api/sources/duckdb-local/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["source_name"] == "duckdb-local"
        assert data["healthy"] is True

    def test_cached_single_source(self, client_with_cache, mock_cache) -> None:
        mock_cache.get_latest.return_value = CACHED_HEALTH[0]
        resp = client_with_cache.get("/api/sources/cloudtrail/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["source_name"] == "cloudtrail"
        assert data["healthy"] is True

    def test_unknown_source_returns_error(self, client) -> None:
        resp = client.get("/api/sources/nonexistent/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["healthy"] is False
        assert "error" in data

    def test_live_override(self, client_with_cache, mock_cache) -> None:
        mock_cache.get_latest.return_value = CACHED_HEALTH[0]
        resp = client_with_cache.get("/api/sources/duckdb-local/health?live=true")
        assert resp.status_code == 200
        data = resp.json()
        assert data["source_name"] == "duckdb-local"
        mock_cache.get_latest.assert_not_called()


class TestHealthHistory:
    def test_no_cache_returns_empty(self, client) -> None:
        resp = client.get("/api/sources/test/health/history")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_returns_history(self, client_with_cache, mock_cache) -> None:
        history = [
            {
                "source_name": "test",
                "checked_at": f"2026-02-13T{12 - i:02d}:00:00+00:00",
                "healthy": True,
                "record_count": 100,
                "latency_seconds": 0.5,
                "data_age_minutes": None,
                "last_data_time": None,
                "error": None,
                "details": {},
            }
            for i in range(5)
        ]
        mock_cache.get_history.return_value = history
        resp = client_with_cache.get("/api/sources/test/health/history?limit=5")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 5


class TestRefreshHealth:
    def test_refresh_returns_results(self, client) -> None:
        resp = client.post("/api/sources/refresh")
        assert resp.status_code == 200
        data = resp.json()
        assert "refreshed" in data
        assert "results" in data
        assert data["refreshed"] >= 1  # at least duckdb-local

    def test_refresh_writes_to_cache(self, client_with_cache, mock_cache) -> None:
        resp = client_with_cache.post("/api/sources/refresh")
        assert resp.status_code == 200
        # Cache should have been written to
        mock_cache.put_many.assert_called_once()


class TestDashboardSummary:
    def test_basic_summary(self, client) -> None:
        resp = client.get("/api/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert "source_count" in data
        assert "rule_count" in data
        assert "region" in data
        assert "investigation_count" in data
        assert data["source_count"] >= 1
        assert data["region"] == "us-west-2"

    def test_summary_without_cache(self, client) -> None:
        resp = client.get("/api/dashboard")
        data = resp.json()
        assert data["health"]["available"] is False

    def test_summary_with_cache(self, client_with_cache, mock_cache) -> None:
        mock_cache.get_all_latest.return_value = CACHED_HEALTH
        resp = client_with_cache.get("/api/dashboard")
        data = resp.json()
        assert data["health"]["available"] is True
        assert data["health"]["total"] == 2
        assert data["health"]["healthy"] == 1
        assert data["health"]["unhealthy"] == 1


class TestAuthConfig:
    """Tests for GET /api/auth/config."""

    def test_default_auth_disabled(self, client) -> None:
        resp = client.get("/api/auth/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_enabled"] is False
        assert data["cognito_domain"] == ""
        assert data["cognito_client_id"] == ""

    def test_auth_enabled_returns_config(self) -> None:
        config = WebConfig(
            duckdb_path=":memory:",
            auth_enabled=True,
            cognito_domain="iris.auth.us-west-2.amazoncognito.com",
            cognito_client_id="test-client-id-123",
            cognito_region="us-west-2",
            cognito_redirect_uri="https://iris.lexicone.com/callback.html",
        )
        app = create_app(config)
        client = TestClient(app)
        resp = client.get("/api/auth/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_enabled"] is True
        assert data["cognito_domain"] == "iris.auth.us-west-2.amazoncognito.com"
        assert data["cognito_client_id"] == "test-client-id-123"
        assert data["cognito_region"] == "us-west-2"
        assert data["redirect_uri"] == "https://iris.lexicone.com/callback.html"

    def test_no_secret_exposed(self, client) -> None:
        """Ensure client_secret is NOT returned by the config endpoint."""
        resp = client.get("/api/auth/config")
        data = resp.json()
        assert "cognito_client_secret" not in data
        assert "secret" not in str(data).lower()
