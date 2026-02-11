"""Tests for the FastAPI web application."""

from fastapi.testclient import TestClient

from secdashboards.catalog.models import DataSourceType
from secdashboards.connectors.duckdb import DuckDBConnector
from secdashboards.web.app import create_app
from secdashboards.web.config import WebConfig
from secdashboards.web.state import AppState, create_app_state


class TestWebConfig:
    """Tests for WebConfig defaults and env override."""

    def test_default_values(self) -> None:
        config = WebConfig()
        assert config.region == "us-west-2"
        assert config.duckdb_path == ":memory:"
        assert config.port == 8000
        assert config.is_lambda is False
        assert config.debug is False

    def test_custom_values(self) -> None:
        config = WebConfig(
            region="eu-west-1",
            duckdb_path="/tmp/test.duckdb",
            port=9000,
            is_lambda=True,
        )
        assert config.region == "eu-west-1"
        assert config.duckdb_path == "/tmp/test.duckdb"
        assert config.port == 9000
        assert config.is_lambda is True


class TestAppState:
    """Tests for AppState creation and lifecycle."""

    def test_create_app_state_defaults(self) -> None:
        config = WebConfig(duckdb_path=":memory:")
        state = create_app_state(config)
        assert isinstance(state, AppState)
        assert state.config is config
        assert state.catalog is not None
        assert state.runner is not None
        assert isinstance(state.duckdb, DuckDBConnector)
        state.duckdb.close()

    def test_state_has_duckdb_source(self) -> None:
        state = create_app_state(WebConfig(duckdb_path=":memory:"))
        source = state.catalog.get_source("duckdb-local")
        assert source is not None
        assert source.type == DataSourceType.DUCKDB
        state.duckdb.close()

    def test_state_duckdb_is_queryable(self) -> None:
        state = create_app_state(WebConfig(duckdb_path=":memory:"))
        df = state.duckdb.query("SELECT 1 AS x")
        assert df["x"][0] == 1
        state.duckdb.close()

    def test_state_investigations_dict(self) -> None:
        state = create_app_state(WebConfig(duckdb_path=":memory:"))
        assert state.investigations == {}
        assert state.operations == {}
        state.duckdb.close()


class TestAppCreation:
    """Tests for the FastAPI app factory."""

    def test_create_app_returns_fastapi(self) -> None:
        config = WebConfig(duckdb_path=":memory:")
        app = create_app(config)
        assert app.title == "secdashboards"

    def test_health_endpoint(self) -> None:
        config = WebConfig(duckdb_path=":memory:")
        app = create_app(config)
        client = TestClient(app)
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "0.1.0"

    def test_app_state_accessible(self) -> None:
        config = WebConfig(duckdb_path=":memory:")
        app = create_app(config)
        assert hasattr(app.state, "secdash")
        assert isinstance(app.state.secdash, AppState)

    def test_shutdown_closes_duckdb(self) -> None:
        config = WebConfig(duckdb_path=":memory:")
        app = create_app(config)
        duckdb_conn = app.state.secdash.duckdb

        # Verify connection works before shutdown
        df = duckdb_conn.query("SELECT 1 AS x")
        assert df["x"][0] == 1

        # Use TestClient as context manager — triggers lifespan shutdown
        with TestClient(app):
            pass

        # After shutdown, connection should be closed
        health = duckdb_conn.check_health()
        assert health.healthy is False

    def test_multiple_apps_are_isolated(self) -> None:
        """Each create_app call gets its own state."""
        app1 = create_app(WebConfig(duckdb_path=":memory:"))
        app2 = create_app(WebConfig(duckdb_path=":memory:"))

        # Load data into app1's DuckDB
        app1.state.secdash.duckdb.connection.execute("CREATE TABLE t1 (x INT)")

        # app2 should not see it
        tables = app2.state.secdash.duckdb.list_tables()
        assert "t1" not in tables
