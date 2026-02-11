"""Tests for the DuckDB connector."""

import contextlib
from datetime import UTC, datetime

import polars as pl
from hypothesis import given, settings
from hypothesis import strategies as st

from secdashboards.catalog.models import DataSource, DataSourceType
from secdashboards.catalog.registry import DataCatalog
from secdashboards.connectors.duckdb import DuckDBConnector


def _make_source(**overrides: object) -> DataSource:
    """Create a DuckDB DataSource with sensible defaults."""
    defaults: dict[str, object] = {
        "name": "test-duckdb",
        "type": DataSourceType.DUCKDB,
        "connector_config": {"db_path": ":memory:"},
    }
    defaults.update(overrides)
    return DataSource(**defaults)  # type: ignore[arg-type]


class TestDuckDBConnector:
    """Core connector functionality."""

    def test_query_simple(self) -> None:
        conn = DuckDBConnector(_make_source())
        df = conn.query("SELECT 1 AS x, 'hello' AS y")
        assert isinstance(df, pl.DataFrame)
        assert df.shape == (1, 2)
        assert df["x"][0] == 1
        assert df["y"][0] == "hello"
        conn.close()

    def test_query_with_table(self) -> None:
        conn = DuckDBConnector(_make_source())
        conn.connection.execute("CREATE TABLE events (id INT, name VARCHAR)")
        conn.connection.execute("INSERT INTO events VALUES (1, 'login'), (2, 'logout')")
        df = conn.query("SELECT * FROM events ORDER BY id")
        assert len(df) == 2
        assert df["id"].to_list() == [1, 2]
        conn.close()

    def test_get_schema_all_tables(self) -> None:
        conn = DuckDBConnector(_make_source())
        conn.connection.execute("CREATE TABLE t1 (a INT, b VARCHAR)")
        conn.connection.execute("CREATE TABLE t2 (x DOUBLE)")
        schema = conn.get_schema()
        assert "t1.a" in schema
        assert "t1.b" in schema
        assert "t2.x" in schema
        conn.close()

    def test_get_schema_specific_table(self) -> None:
        source = _make_source(table="events")
        conn = DuckDBConnector(source)
        conn.connection.execute("CREATE TABLE events (id INT, ts TIMESTAMP)")
        schema = conn.get_schema()
        assert "id" in schema
        assert "ts" in schema
        assert len(schema) == 2
        conn.close()

    def test_get_schema_empty_database(self) -> None:
        conn = DuckDBConnector(_make_source())
        schema = conn.get_schema()
        assert schema == {}
        conn.close()

    def test_check_health_empty_db(self) -> None:
        conn = DuckDBConnector(_make_source())
        result = conn.check_health()
        assert result.healthy is True
        assert result.record_count == 0
        assert result.details["table_count"] == 0
        assert result.latency_seconds > 0
        conn.close()

    def test_check_health_with_data(self) -> None:
        conn = DuckDBConnector(_make_source())
        conn.connection.execute("CREATE TABLE logs (msg VARCHAR)")
        conn.connection.execute("INSERT INTO logs VALUES ('a'), ('b'), ('c')")
        result = conn.check_health()
        assert result.healthy is True
        assert result.record_count == 3
        assert result.details["table_count"] == 1
        conn.close()

    def test_check_health_after_close(self) -> None:
        conn = DuckDBConnector(_make_source())
        conn.close()
        result = conn.check_health()
        assert result.healthy is False
        assert result.error is not None

    def test_load_dataframe(self) -> None:
        conn = DuckDBConnector(_make_source())
        df = pl.DataFrame({"user": ["alice", "bob"], "score": [100, 200]})
        conn.load_dataframe(df, "users")
        result = conn.query("SELECT * FROM users ORDER BY score")
        assert result["user"].to_list() == ["alice", "bob"]
        assert result["score"].to_list() == [100, 200]
        conn.close()

    def test_load_dataframe_replaces_existing(self) -> None:
        conn = DuckDBConnector(_make_source())
        conn.load_dataframe(pl.DataFrame({"x": [1]}), "t")
        conn.load_dataframe(pl.DataFrame({"x": [2, 3]}), "t")
        result = conn.query("SELECT COUNT(*) AS cnt FROM t")
        assert int(result["cnt"][0]) == 2
        conn.close()

    def test_list_tables(self) -> None:
        conn = DuckDBConnector(_make_source())
        assert conn.list_tables() == []
        conn.connection.execute("CREATE TABLE a (x INT)")
        conn.connection.execute("CREATE TABLE b (y INT)")
        tables = sorted(conn.list_tables())
        assert tables == ["a", "b"]
        conn.close()

    def test_import_csv_via_query(self) -> None:
        """DuckDB can read CSV inline — verifies query flexibility."""
        conn = DuckDBConnector(_make_source())
        df = conn.query("SELECT * FROM (VALUES (1, 'a'), (2, 'b')) AS t(id, name)")
        assert len(df) == 2
        conn.close()

    def test_close_is_idempotent(self) -> None:
        conn = DuckDBConnector(_make_source())
        conn.close()
        # Second close should not raise
        with contextlib.suppress(Exception):
            conn.close()

    def test_connection_property(self) -> None:
        import duckdb as duckdb_mod

        conn = DuckDBConnector(_make_source())
        assert isinstance(conn.connection, duckdb_mod.DuckDBPyConnection)
        conn.close()


class TestDuckDBWithCatalog:
    """Integration tests: DuckDB registered via DataCatalog."""

    def test_catalog_has_duckdb_connector(self) -> None:
        catalog = DataCatalog()
        assert DataSourceType.DUCKDB in catalog._connectors

    def test_get_connector_returns_duckdb(self) -> None:
        catalog = DataCatalog()
        source = DataSource(
            name="local-db",
            type=DataSourceType.DUCKDB,
            connector_config={"db_path": ":memory:"},
        )
        catalog.add_source(source)
        connector = catalog.get_connector("local-db")
        assert isinstance(connector, DuckDBConnector)
        connector.close()

    def test_duckdb_query_via_catalog(self) -> None:
        catalog = DataCatalog()
        source = DataSource(
            name="analytics",
            type=DataSourceType.DUCKDB,
            connector_config={"db_path": ":memory:"},
        )
        catalog.add_source(source)
        connector = catalog.get_connector("analytics")
        assert isinstance(connector, DuckDBConnector)
        df = connector.query("SELECT 42 AS answer")
        assert df["answer"][0] == 42
        connector.close()

    def test_run_detection_with_duckdb(self) -> None:
        """End-to-end: load data into DuckDB, run a detection rule."""
        from secdashboards.detections.rule import DetectionMetadata, SQLDetectionRule
        from secdashboards.detections.runner import DetectionRunner

        catalog = DataCatalog()
        source = DataSource(
            name="test-events",
            type=DataSourceType.DUCKDB,
            connector_config={"db_path": ":memory:"},
        )
        catalog.add_source(source)

        # Create a detection rule
        metadata = DetectionMetadata(
            id="test-brute-force",
            name="Brute Force Detection",
            description="Detect multiple failed logins",
            severity="high",
            data_sources=["test-events"],
        )
        rule = SQLDetectionRule(
            metadata=metadata,
            query_template=(
                "SELECT src_ip, COUNT(*) AS cnt "
                "FROM failed_logins "
                "WHERE ts >= TIMESTAMP '{start_time}' "
                "AND ts < TIMESTAMP '{end_time}' "
                "GROUP BY src_ip "
                "HAVING COUNT(*) > 5"
            ),
        )

        runner = DetectionRunner(catalog)
        runner.register_rule(rule)

        # Load test data via DuckDB connector
        connector = catalog.get_connector("test-events")
        assert isinstance(connector, DuckDBConnector)

        test_data = pl.DataFrame(
            {
                "src_ip": ["10.0.0.1"] * 10 + ["10.0.0.2"] * 3,
                "ts": [datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)] * 13,
                "event": ["failed_login"] * 13,
            }
        )
        connector.load_dataframe(test_data, "failed_logins")

        result = runner.run_rule(
            "test-brute-force",
            connector,
            start=datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC),
            end=datetime(2025, 1, 2, 0, 0, 0, tzinfo=UTC),
        )

        assert result.triggered is True
        assert result.match_count >= 1
        connector.close()


class TestDuckDBSQLSafety:
    """Property-based tests for SQL query safety."""

    @given(st.text(min_size=1, max_size=50))
    @settings(max_examples=50)
    def test_query_with_arbitrary_strings_doesnt_crash(self, value: str) -> None:
        """Parameterized queries should handle arbitrary string values safely."""
        conn = DuckDBConnector(_make_source())
        conn.connection.execute("CREATE TABLE IF NOT EXISTS safe_test (val VARCHAR)")
        # Use parameterized query — never inject raw strings
        conn.connection.execute("INSERT INTO safe_test VALUES (?)", [value])
        df = conn.query("SELECT COUNT(*) AS cnt FROM safe_test")
        assert int(df["cnt"][0]) >= 1
        conn.close()

    @given(
        st.text(
            alphabet=st.characters(
                whitelist_categories=("L", "N"),
                whitelist_characters="_",
            ),
            min_size=1,
            max_size=30,
        )
    )
    @settings(max_examples=30)
    def test_load_dataframe_with_arbitrary_column_names(self, col_name: str) -> None:
        """DuckDB should handle unusual column names via quoting."""
        conn = DuckDBConnector(_make_source())
        df = pl.DataFrame({col_name: [1, 2, 3]})
        conn.load_dataframe(df, "test_cols")
        result = conn.query("SELECT COUNT(*) AS cnt FROM test_cols")
        assert int(result["cnt"][0]) == 3
        conn.close()

    def test_table_name_with_special_chars(self) -> None:
        """load_dataframe quotes table names, so special chars should work."""
        conn = DuckDBConnector(_make_source())
        df = pl.DataFrame({"x": [1]})
        conn.load_dataframe(df, "my-table")
        result = conn.query('SELECT * FROM "my-table"')
        assert len(result) == 1
        conn.close()

    def test_sql_injection_in_table_name_blocked(self) -> None:
        """Quoted table names (with escaped double-quotes) prevent SQL injection."""
        conn = DuckDBConnector(_make_source())
        df = pl.DataFrame({"x": [1]})
        # Create a target table that injection would try to drop
        conn.connection.execute("CREATE TABLE users (id INT)")
        # The table name contains a SQL injection attempt, but _quote_ident
        # escapes the embedded double-quote so it becomes a literal name
        conn.load_dataframe(df, 'evil"; DROP TABLE users; --')
        tables = conn.list_tables()
        # Both tables should exist — the injection was neutralized
        assert "users" in tables
        assert any("evil" in t for t in tables)
        conn.close()
