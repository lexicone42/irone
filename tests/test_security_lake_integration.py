"""Integration tests for Security Lake connector.

These tests require AWS credentials and access to Security Lake.
They are skipped by default and can be enabled with:
    RUN_INTEGRATION_TESTS=1 pytest tests/test_security_lake_integration.py -v

Environment variables:
    RUN_INTEGRATION_TESTS: Set to "1" to enable tests
    ATHENA_OUTPUT_BUCKET: S3 bucket for Athena query results (optional)
    SECURITY_LAKE_DATABASE: Override default database name (optional)
    SECURITY_LAKE_TABLE: Override default table name (optional)
"""

import os
from datetime import UTC, datetime, timedelta

import pytest

from secdashboards.catalog.models import DataSource, DataSourceType
from secdashboards.connectors.security_lake import OCSFEventClass, SecurityLakeConnector

# Skip all tests unless RUN_INTEGRATION_TESTS env var is set
pytestmark = pytest.mark.skipif(
    not os.environ.get("RUN_INTEGRATION_TESTS"),
    reason="Integration tests disabled. Set RUN_INTEGRATION_TESTS=1 to enable.",
)


def get_athena_output_location() -> str:
    """Get Athena output location from environment or auto-detect."""
    if bucket := os.environ.get("ATHENA_OUTPUT_BUCKET"):
        return f"s3://{bucket}/"
    # Try to auto-detect using AWS account ID
    try:
        import boto3

        sts = boto3.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        return f"s3://aws-athena-query-results-{account_id}-us-west-2/"
    except Exception:
        return "s3://aws-athena-query-results-us-west-2/"


@pytest.fixture
def security_lake_source() -> DataSource:
    """Create a Security Lake data source for CloudTrail."""
    database = os.environ.get("SECURITY_LAKE_DATABASE", "amazon_security_lake_glue_db_us_west_2")
    table = os.environ.get(
        "SECURITY_LAKE_TABLE", "amazon_security_lake_table_us_west_2_cloud_trail_mgmt_2_0"
    )
    output_location = get_athena_output_location()

    return DataSource(
        name="test-cloudtrail",
        type=DataSourceType.SECURITY_LAKE,
        database=database,
        table=table,
        region="us-west-2",
        expected_freshness_minutes=120,
        connector_config={"output_location": output_location},
    )


@pytest.fixture
def connector(security_lake_source: DataSource) -> SecurityLakeConnector:
    """Create a Security Lake connector."""
    return SecurityLakeConnector(security_lake_source)


class TestSecurityLakeConnection:
    """Tests for basic Security Lake connectivity."""

    def test_basic_query(self, connector: SecurityLakeConnector) -> None:
        """Test basic query execution."""
        df = connector.query(
            f"""
            SELECT class_uid, class_name, COUNT(*) as cnt
            FROM "{connector.source.database}"."{connector.source.table}"
            WHERE time_dt >= CURRENT_TIMESTAMP - INTERVAL '1' HOUR
            GROUP BY class_uid, class_name
            LIMIT 10
            """
        )
        assert df is not None
        assert len(df) >= 0

    def test_health_check(self, connector: SecurityLakeConnector) -> None:
        """Test health check returns valid result."""
        result = connector.check_health()
        assert result is not None
        assert result.source_name == "test-cloudtrail"
        assert result.latency_seconds > 0


class TestOCSFEventClassQueries:
    """Tests for OCSF event class ID queries."""

    def test_class_uid_is_integer(self, connector: SecurityLakeConnector) -> None:
        """Verify class_uid is stored as integer, not string."""
        df = connector.query(
            f"""
            SELECT DISTINCT class_uid, typeof(class_uid) as type_info
            FROM "{connector.source.database}"."{connector.source.table}"
            WHERE time_dt >= CURRENT_TIMESTAMP - INTERVAL '1' HOUR
            LIMIT 5
            """
        )
        assert len(df) > 0
        # class_uid should be a numeric type (bigint in Athena)
        for row in df.iter_rows(named=True):
            assert isinstance(row["class_uid"], int)

    def test_query_by_event_class_api_activity(self, connector: SecurityLakeConnector) -> None:
        """Test querying API Activity events (class_uid 6003)."""
        end = datetime.now(UTC)
        start = end - timedelta(hours=1)
        df = connector.query_by_event_class(
            OCSFEventClass.API_ACTIVITY,
            start=start,
            end=end,
            limit=10,
        )
        assert df is not None
        # If we have results, verify class_uid is correct
        if len(df) > 0:
            for class_uid in df["class_uid"].to_list():
                assert class_uid == 6003

    def test_query_by_event_class_authentication(self, connector: SecurityLakeConnector) -> None:
        """Test querying Authentication events (class_uid 3002)."""
        end = datetime.now(UTC)
        start = end - timedelta(hours=24)
        df = connector.query_by_event_class(
            OCSFEventClass.AUTHENTICATION,
            start=start,
            end=end,
            limit=10,
        )
        assert df is not None
        # If we have results, verify class_uid is correct
        if len(df) > 0:
            for class_uid in df["class_uid"].to_list():
                assert class_uid == 3002


class TestTimestampFields:
    """Tests for timestamp field handling."""

    def test_time_dt_is_timestamp(self, connector: SecurityLakeConnector) -> None:
        """Verify time_dt is a proper timestamp column and time is epoch ms."""
        df = connector.query(
            f"""
            SELECT time_dt, time, typeof(time_dt) as dt_type, typeof(time) as t_type
            FROM "{connector.source.database}"."{connector.source.table}"
            WHERE time_dt >= CURRENT_TIMESTAMP - INTERVAL '1' HOUR
            LIMIT 1
            """
        )
        if len(df) > 0:
            # In Athena, time_dt is a timestamp and time is bigint
            # Polars reads CSV results as strings, so check the Athena type
            dt_type = df["dt_type"][0]
            t_type = df["t_type"][0]
            assert "timestamp" in dt_type.lower()
            assert "bigint" in t_type.lower()

    def test_time_range_filtering(self, connector: SecurityLakeConnector) -> None:
        """Test that time_dt filtering works correctly."""
        end = datetime.now(UTC)
        start = end - timedelta(hours=1)

        # Use connector's timestamp formatter for Athena compatibility
        start_str = connector._format_timestamp(start)
        end_str = connector._format_timestamp(end)

        df = connector.query(
            f"""
            SELECT time_dt
            FROM "{connector.source.database}"."{connector.source.table}"
            WHERE time_dt >= TIMESTAMP '{start_str}'
              AND time_dt < TIMESTAMP '{end_str}'
            LIMIT 10
            """
        )
        assert df is not None
        # Verify we got results (if data exists in the time range)
        # The timestamps are returned as strings from Athena CSV output
        if len(df) > 0:
            for ts_str in df["time_dt"].to_list():
                # Parse the timestamp string and verify it's within range
                ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
                start_naive = start.replace(tzinfo=None)
                end_naive = end.replace(tzinfo=None)
                assert ts >= start_naive
                assert ts < end_naive


class TestEventSummary:
    """Tests for event summary functionality."""

    def test_get_event_summary(self, connector: SecurityLakeConnector) -> None:
        """Test getting event summary by class."""
        end = datetime.now(UTC)
        start = end - timedelta(hours=24)
        df = connector.get_event_summary(start=start, end=end)
        assert df is not None
        assert "class_uid" in df.columns
        assert "class_name" in df.columns
        assert "event_count" in df.columns


class TestSchemaDiscovery:
    """Tests for schema discovery."""

    def test_get_schema(self, connector: SecurityLakeConnector) -> None:
        """Test schema retrieval."""
        schema = connector.get_schema()
        assert schema is not None
        # OCSF standard fields should exist
        assert "class_uid" in schema
        assert "time" in schema
        assert "time_dt" in schema

    def test_list_available_tables(self, connector: SecurityLakeConnector) -> None:
        """Test listing available Security Lake tables."""
        tables = connector.list_available_tables()
        assert isinstance(tables, list)
        assert len(tables) > 0
