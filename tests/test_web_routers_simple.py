"""Tests for dashboard, monitoring, and security lake routers."""

import pytest
from fastapi.testclient import TestClient

from secdashboards.web.app import create_app
from secdashboards.web.config import WebConfig


@pytest.fixture()
def client() -> TestClient:
    """Create a test client with in-memory DuckDB."""
    config = WebConfig(duckdb_path=":memory:")
    app = create_app(config)
    return TestClient(app)


class TestDashboardRoutes:
    """Tests for the main dashboard."""

    def test_get_dashboard(self, client: TestClient) -> None:
        response = client.get("/")
        assert response.status_code == 200
        assert "Dashboard" in response.text

    def test_dashboard_has_nav(self, client: TestClient) -> None:
        response = client.get("/")
        assert "secdash_" in response.text
        assert "Health Monitor" in response.text

    def test_dashboard_shows_source_count(self, client: TestClient) -> None:
        response = client.get("/")
        # At minimum, the duckdb-local source is registered
        assert "Data Sources" in response.text

    def test_dashboard_shows_region(self, client: TestClient) -> None:
        response = client.get("/")
        assert "us-west-2" in response.text


class TestMonitoringRoutes:
    """Tests for the health monitoring pages."""

    def test_get_monitoring(self, client: TestClient) -> None:
        response = client.get("/monitoring/")
        assert response.status_code == 200
        assert "Health Monitor" in response.text

    def test_post_health_check(self, client: TestClient) -> None:
        response = client.post("/monitoring/check")
        assert response.status_code == 200
        # Should contain health results table
        assert "duckdb-local" in response.text

    def test_health_check_shows_status(self, client: TestClient) -> None:
        response = client.post("/monitoring/check")
        assert response.status_code == 200
        # DuckDB in-memory should be healthy
        assert "OK" in response.text

    def test_get_catalog_page(self, client: TestClient) -> None:
        response = client.get("/monitoring/catalog")
        assert response.status_code == 200
        assert "Data Catalog" in response.text
        assert "duckdb-local" in response.text


class TestSecurityLakeRoutes:
    """Tests for Security Lake connectivity pages."""

    def test_get_security_lake(self, client: TestClient) -> None:
        response = client.get("/security-lake/")
        assert response.status_code == 200
        assert "Security Lake" in response.text

    def test_post_test_connections(self, client: TestClient) -> None:
        # No security-lake sources registered by default, so should return empty results
        response = client.post("/security-lake/test")
        assert response.status_code == 200

    def test_security_lake_shows_region(self, client: TestClient) -> None:
        response = client.get("/security-lake/")
        assert "us-west-2" in response.text


class TestHealthEndpoint:
    """Tests for the API health endpoint (still works with routers)."""

    def test_api_health(self, client: TestClient) -> None:
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
