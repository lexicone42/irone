"""Tests for the SecurityLakeDirectConnector (DuckDB + Iceberg/Glue)."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from secdashboards.catalog.models import DataSource, DataSourceType
from secdashboards.catalog.registry import DataCatalog
from secdashboards.connectors.security_lake_direct import (
    SecurityLakeDirectConnector,
    _result_to_query_result,
    _SharedConnection,
)


@pytest.fixture(autouse=True)
def _reset_shared_connections():
    """Reset _SharedConnection singleton pool between tests."""
    _SharedConnection._reset()
    yield
    _SharedConnection._reset()


def _make_source(**overrides: object) -> DataSource:
    """Create a SecurityLakeDirectConnector DataSource with sensible defaults."""
    defaults: dict[str, object] = {
        "name": "cloudtrail-direct",
        "type": DataSourceType.SECURITY_LAKE_DIRECT,
        "database": "amazon_security_lake_glue_db_us_west_2",
        "table": "amazon_security_lake_table_us_west_2_cloud_trail_mgmt_2_0",
        "region": "us-west-2",
        "connector_config": {"account_id": "651804262336"},
    }
    defaults.update(overrides)
    return DataSource(**defaults)  # type: ignore[arg-type]


class TestResultConversion:
    """Test the _result_to_query_result helper."""

    def test_none_description_returns_empty(self) -> None:
        mock_result = MagicMock()
        mock_result.description = None
        qr = _result_to_query_result(mock_result)
        assert qr.is_empty()
        assert qr.columns == []

    def test_normal_result(self) -> None:
        mock_result = MagicMock()
        mock_result.description = [("cnt",), ("latest_time",)]
        mock_result.fetchall.return_value = [(42, "2025-01-01T00:00:00")]
        qr = _result_to_query_result(mock_result)
        assert len(qr) == 1
        assert qr["cnt"][0] == 42
        assert qr.columns == ["cnt", "latest_time"]


class TestSharedConnection:
    """Tests for the _SharedConnection singleton."""

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_installs_extensions(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn
        shared = _SharedConnection.get("123", "us-west-2", "sl")

        shared.ensure_ready()

        execute_calls = [c[0][0] for c in mock_conn.execute.call_args_list]
        assert any("INSTALL iceberg" in c for c in execute_calls)
        assert any("INSTALL httpfs" in c for c in execute_calls)
        assert any("INSTALL aws" in c for c in execute_calls)
        assert any("INSTALL avro" in c for c in execute_calls)
        assert any("LOAD avro" in c for c in execute_calls)
        # avro must be installed before iceberg is loaded
        avro_idx = next(i for i, c in enumerate(execute_calls) if "INSTALL avro" in c)
        load_ice = next(i for i, c in enumerate(execute_calls) if "LOAD iceberg" in c)
        assert avro_idx < load_ice
        # avro must be loaded before iceberg is loaded
        load_avro = next(i for i, c in enumerate(execute_calls) if "LOAD avro" in c)
        assert load_avro < load_ice

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_attaches_glue_catalog(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn
        shared = _SharedConnection.get("651804262336", "us-west-2", "sl")

        shared.ensure_ready()

        execute_calls = [c[0][0] for c in mock_conn.execute.call_args_list]
        attach_calls = [c for c in execute_calls if "ATTACH" in c]
        assert len(attach_calls) == 1
        assert "651804262336" in attach_calls[0]
        assert "TYPE iceberg" in attach_calls[0]
        assert "ENDPOINT_TYPE 'glue'" in attach_calls[0]

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_connection_reused(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn
        shared = _SharedConnection.get("123", "us-west-2", "sl")

        conn1 = shared.ensure_ready()
        conn2 = shared.ensure_ready()

        assert conn1 is conn2
        mock_duckdb.connect.assert_called_once()

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_same_key_returns_same_instance(self, mock_duckdb: MagicMock) -> None:
        shared1 = _SharedConnection.get("123", "us-west-2", "sl")
        shared2 = _SharedConnection.get("123", "us-west-2", "sl")
        assert shared1 is shared2

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_different_key_returns_different_instance(self, mock_duckdb: MagicMock) -> None:
        shared1 = _SharedConnection.get("123", "us-west-2", "sl")
        shared2 = _SharedConnection.get("456", "us-west-2", "sl")
        assert shared1 is not shared2

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_sets_home_directory(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn
        shared = _SharedConnection.get("123", "us-west-2", "sl")

        shared.ensure_ready()

        execute_calls = [c[0][0] for c in mock_conn.execute.call_args_list]
        assert any("home_directory" in c and "/tmp" in c for c in execute_calls)

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_s3_region_configured(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn
        shared = _SharedConnection.get("123", "eu-west-1", "sl")

        shared.ensure_ready()

        execute_calls = [c[0][0] for c in mock_conn.execute.call_args_list]
        secret_calls = [c for c in execute_calls if "CREATE" in c and "SECRET" in c]
        assert len(secret_calls) == 1
        assert "eu-west-1" in secret_calls[0]

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_creates_s3_credential_chain_secret(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn
        shared = _SharedConnection.get("123", "us-west-2", "sl")

        shared.ensure_ready()

        execute_calls = [c[0][0] for c in mock_conn.execute.call_args_list]
        secret_calls = [c for c in execute_calls if "CREATE" in c and "SECRET" in c]
        assert len(secret_calls) == 1
        assert "TYPE s3" in secret_calls[0]
        assert "credential_chain" in secret_calls[0]
        # Secret must be created before ATTACH (catalog needs S3 access)
        secret_idx = next(i for i, c in enumerate(execute_calls) if "SECRET" in c)
        attach_idx = next(i for i, c in enumerate(execute_calls) if "ATTACH" in c)
        assert secret_idx < attach_idx


class TestSecurityLakeDirectConnector:
    """Core connector tests with mocked DuckDB."""

    def test_no_account_id_raises(self) -> None:
        source = _make_source(connector_config={})
        connector = SecurityLakeDirectConnector(source)
        with pytest.raises(ValueError, match="account_id is required"):
            connector.query("SELECT 1")

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_query_delegates_to_duckdb(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn

        mock_result = MagicMock()
        mock_result.description = [("x",)]
        mock_result.fetchall.return_value = [(1,)]
        mock_conn.execute.return_value = mock_result

        connector = SecurityLakeDirectConnector(_make_source())
        qr = connector.query("SELECT 1 AS x")

        assert len(qr) == 1
        assert qr["x"][0] == 1

    def test_qualified_table_format(self) -> None:
        connector = SecurityLakeDirectConnector(_make_source())

        table = connector._qualified_table()
        assert table == (
            'sl."amazon_security_lake_glue_db_us_west_2"'
            '."amazon_security_lake_table_us_west_2_cloud_trail_mgmt_2_0"'
        )

    def test_custom_catalog_alias(self) -> None:
        source = _make_source(
            connector_config={"account_id": "123456789012", "catalog_alias": "lake"}
        )
        connector = SecurityLakeDirectConnector(source)

        table = connector._qualified_table()
        assert table.startswith("lake.")

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_custom_alias_attaches_correctly(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn
        source = _make_source(
            connector_config={"account_id": "123456789012", "catalog_alias": "lake"}
        )
        connector = SecurityLakeDirectConnector(source)
        connector.query("SELECT 1")

        execute_calls = [c[0][0] for c in mock_conn.execute.call_args_list]
        attach_calls = [c for c in execute_calls if "ATTACH" in c]
        assert "AS lake" in attach_calls[0]

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_multiple_connectors_share_connection(self, mock_duckdb: MagicMock) -> None:
        """5 connectors with same account/region should use 1 DuckDB connection."""
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn
        mock_conn.execute.return_value = MagicMock(description=[("x",)], fetchall=lambda: [(1,)])

        connectors = [
            SecurityLakeDirectConnector(_make_source(name=f"source-{i}")) for i in range(5)
        ]
        for c in connectors:
            c.query("SELECT 1")

        # Only one DuckDB connection should have been created
        mock_duckdb.connect.assert_called_once()


class TestHealthCheck:
    """Health check result parsing and error handling."""

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_healthy_result(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn

        now = datetime.now(UTC)
        mock_result = MagicMock()
        mock_result.description = [("cnt",), ("latest_time",), ("class_count",)]
        mock_result.fetchall.return_value = [(150, now - timedelta(minutes=5), 3)]
        mock_conn.execute.return_value = mock_result

        connector = SecurityLakeDirectConnector(_make_source())
        health = connector.check_health()

        assert health.healthy is True
        assert health.record_count == 150
        assert health.details["event_class_count"] == 3
        assert health.details["connector"] == "direct_iceberg"
        assert health.latency_seconds > 0

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_stale_data_unhealthy(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn

        old_time = datetime.now(UTC) - timedelta(hours=3)
        mock_result = MagicMock()
        mock_result.description = [("cnt",), ("latest_time",), ("class_count",)]
        mock_result.fetchall.return_value = [(10, old_time, 1)]
        mock_conn.execute.return_value = mock_result

        connector = SecurityLakeDirectConnector(_make_source())
        health = connector.check_health()

        assert health.healthy is False
        assert health.record_count == 10

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_no_data_unhealthy(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn

        mock_result = MagicMock()
        mock_result.description = [("cnt",), ("latest_time",), ("class_count",)]
        mock_result.fetchall.return_value = [(0, None, 0)]
        mock_conn.execute.return_value = mock_result

        connector = SecurityLakeDirectConnector(_make_source())
        health = connector.check_health()

        assert health.healthy is False
        assert health.record_count == 0
        assert health.last_data_time is None

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_connection_error_returns_unhealthy(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn
        mock_conn.execute.side_effect = RuntimeError("Glue access denied")

        connector = SecurityLakeDirectConnector(_make_source())
        health = connector.check_health()

        assert health.healthy is False
        assert "Glue access denied" in health.error
        assert health.details["connector"] == "direct_iceberg"

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_string_timestamp_parsed(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn

        mock_result = MagicMock()
        mock_result.description = [("cnt",), ("latest_time",), ("class_count",)]
        mock_result.fetchall.return_value = [(5, "2025-06-15T10:30:00Z", 2)]
        mock_conn.execute.return_value = mock_result

        connector = SecurityLakeDirectConnector(_make_source(expected_freshness_minutes=999999))
        health = connector.check_health()

        assert health.last_data_time is not None
        assert health.last_data_time.tzinfo is not None
        assert health.last_data_time.year == 2025

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_naive_datetime_gets_utc(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn

        naive_dt = datetime(2025, 6, 15, 10, 0, 0)
        mock_result = MagicMock()
        mock_result.description = [("cnt",), ("latest_time",), ("class_count",)]
        mock_result.fetchall.return_value = [(5, naive_dt, 1)]
        mock_conn.execute.return_value = mock_result

        connector = SecurityLakeDirectConnector(_make_source(expected_freshness_minutes=999999))
        health = connector.check_health()

        assert health.last_data_time is not None
        assert health.last_data_time.tzinfo == UTC


class TestParseTimestamp:
    """Unit tests for the static _parse_timestamp method."""

    def test_none_returns_none(self) -> None:
        assert SecurityLakeDirectConnector._parse_timestamp(None) is None

    def test_aware_datetime_passthrough(self) -> None:
        dt = datetime(2025, 1, 1, tzinfo=UTC)
        assert SecurityLakeDirectConnector._parse_timestamp(dt) is dt

    def test_naive_datetime_gets_utc(self) -> None:
        dt = datetime(2025, 1, 1)
        result = SecurityLakeDirectConnector._parse_timestamp(dt)
        assert result is not None
        assert result.tzinfo == UTC

    def test_iso_string_with_z(self) -> None:
        result = SecurityLakeDirectConnector._parse_timestamp("2025-06-15T10:30:00Z")
        assert result is not None
        assert result.year == 2025
        assert result.month == 6
        assert result.tzinfo is not None

    def test_iso_string_with_offset(self) -> None:
        result = SecurityLakeDirectConnector._parse_timestamp("2025-06-15T10:30:00+00:00")
        assert result is not None
        assert result.tzinfo is not None

    def test_unsupported_type_returns_none(self) -> None:
        assert SecurityLakeDirectConnector._parse_timestamp(12345) is None


class TestGetSchema:
    """Schema retrieval tests."""

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_describe_returns_schema(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn

        mock_result = MagicMock()
        mock_result.description = [
            ("column_name",),
            ("column_type",),
            ("null",),
            ("key",),
            ("default",),
            ("extra",),
        ]
        mock_result.fetchall.return_value = [
            ("time_dt", "TIMESTAMP", "YES", None, None, None),
            ("class_uid", "BIGINT", "YES", None, None, None),
        ]
        mock_conn.execute.return_value = mock_result

        connector = SecurityLakeDirectConnector(_make_source())
        schema = connector.get_schema()

        assert schema == {"time_dt": "TIMESTAMP", "class_uid": "BIGINT"}

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_describe_failure_returns_empty(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn

        def side_effect(*args, **kwargs):
            sql = args[0] if args else ""
            if "DESCRIBE" in sql:
                raise RuntimeError("table not found")
            return MagicMock(description=None, fetchall=lambda: [])

        mock_conn.execute.side_effect = side_effect

        connector = SecurityLakeDirectConnector(_make_source())
        schema = connector.get_schema()
        assert schema == {}


class TestClose:
    """Connection lifecycle tests."""

    @patch("secdashboards.connectors.security_lake_direct.duckdb")
    def test_close_cleans_up(self, mock_duckdb: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_duckdb.connect.return_value = mock_conn

        connector = SecurityLakeDirectConnector(_make_source())
        # Trigger connection creation via query
        mock_conn.execute.return_value = MagicMock(description=[("x",)], fetchall=lambda: [(1,)])
        connector.query("SELECT 1")

        connector.close()
        mock_conn.close.assert_called_once()

    def test_close_without_connection_is_safe(self) -> None:
        # No account_id means _get_shared raises, but close should handle gracefully
        connector = SecurityLakeDirectConnector(_make_source(connector_config={}))
        connector.close()  # should not raise


class TestCatalogIntegration:
    """Verify the connector integrates with DataCatalog."""

    def test_catalog_has_direct_connector_registered(self) -> None:
        catalog = DataCatalog()
        assert DataSourceType.SECURITY_LAKE_DIRECT in catalog._connectors

    def test_catalog_returns_direct_connector(self) -> None:
        catalog = DataCatalog()
        source = _make_source()
        catalog.add_source(source)
        connector = catalog.get_connector("cloudtrail-direct")
        assert isinstance(connector, SecurityLakeDirectConnector)

    def test_enum_value(self) -> None:
        assert DataSourceType.SECURITY_LAKE_DIRECT == "security_lake_direct"
        assert DataSourceType.SECURITY_LAKE_DIRECT.value == "security_lake_direct"


class TestStateAutoRegistration:
    """Verify state.py routes to direct connector when configured."""

    @patch("secdashboards.web.state._resolve_account_id", return_value="651804262336")
    def test_direct_sources_registered(self, mock_resolve: MagicMock) -> None:
        from secdashboards.web.config import WebConfig
        from secdashboards.web.state import create_app_state

        config = WebConfig(
            security_lake_db="amazon_security_lake_glue_db_us_west_2",
            use_direct_query=True,
        )
        state = create_app_state(config)
        sources = state.catalog.list_sources(tag="security-lake")

        assert len(sources) == 5
        for s in sources:
            assert s.type == DataSourceType.SECURITY_LAKE_DIRECT
            assert s.connector_config["account_id"] == "651804262336"

    @patch("secdashboards.web.state._resolve_account_id", return_value="")
    def test_fallback_to_athena_when_no_account_id(self, mock_resolve: MagicMock) -> None:
        from secdashboards.web.config import WebConfig
        from secdashboards.web.state import create_app_state

        config = WebConfig(
            security_lake_db="amazon_security_lake_glue_db_us_west_2",
            use_direct_query=True,
            athena_output="s3://my-bucket/results/",
        )
        state = create_app_state(config)
        sources = state.catalog.list_sources(tag="security-lake")

        assert len(sources) == 5
        for s in sources:
            assert s.type == DataSourceType.SECURITY_LAKE
            assert s.connector_config.get("output_location") == "s3://my-bucket/results/"

    @patch("secdashboards.web.state._resolve_account_id", return_value="651804262336")
    def test_explicit_athena_fallback(self, mock_resolve: MagicMock) -> None:
        from secdashboards.web.config import WebConfig
        from secdashboards.web.state import create_app_state

        config = WebConfig(
            security_lake_db="amazon_security_lake_glue_db_us_west_2",
            use_direct_query=False,
        )
        state = create_app_state(config)
        sources = state.catalog.list_sources(tag="security-lake")

        assert len(sources) == 5
        for s in sources:
            assert s.type == DataSourceType.SECURITY_LAKE

    def test_no_security_lake_db_no_sources(self) -> None:
        from secdashboards.web.config import WebConfig
        from secdashboards.web.state import create_app_state

        config = WebConfig(security_lake_db="")
        state = create_app_state(config)
        sources = state.catalog.list_sources(tag="security-lake")
        assert len(sources) == 0
