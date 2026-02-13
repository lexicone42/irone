"""Tests for the DynamoDB health cache client."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from secdashboards.connectors.base import HealthCheckResult
from secdashboards.health.cache import HealthCacheClient


@pytest.fixture
def mock_table():
    """Create a mock DynamoDB table."""
    table = MagicMock()
    table.put_item = MagicMock()
    table.query = MagicMock(return_value={"Items": []})
    table.scan = MagicMock(return_value={"Items": []})
    batch_writer = MagicMock()
    batch_writer.__enter__ = MagicMock(return_value=batch_writer)
    batch_writer.__exit__ = MagicMock(return_value=False)
    table.batch_writer = MagicMock(return_value=batch_writer)
    return table


@pytest.fixture
def cache(mock_table):
    """Create a HealthCacheClient with mocked DynamoDB."""
    with patch("secdashboards.health.cache.boto3") as mock_boto:
        mock_resource = MagicMock()
        mock_resource.Table.return_value = mock_table
        mock_boto.resource.return_value = mock_resource
        client = HealthCacheClient(
            table_name="test-health-cache",
            region_name="us-west-2",
        )
    return client


def _make_health_result(
    name: str = "test-source",
    healthy: bool = True,
    record_count: int = 100,
    latency: float = 0.5,
) -> HealthCheckResult:
    return HealthCheckResult(
        source_name=name,
        healthy=healthy,
        record_count=record_count,
        latency_seconds=latency,
        last_data_time=datetime(2026, 2, 13, 12, 0, 0, tzinfo=UTC),
    )


class TestHealthCachePut:
    def test_put_single_result(self, cache, mock_table) -> None:
        result = _make_health_result()
        cache.put(result)
        mock_table.put_item.assert_called_once()
        item = mock_table.put_item.call_args[1]["Item"]
        assert item["source_name"] == "test-source"
        assert item["healthy"] is True
        assert item["record_count"] == 100
        assert "ttl" in item

    def test_put_with_error(self, cache, mock_table) -> None:
        result = HealthCheckResult(
            source_name="bad-source",
            healthy=False,
            error="Connection refused",
        )
        cache.put(result)
        item = mock_table.put_item.call_args[1]["Item"]
        assert item["healthy"] is False
        assert item["error"] == "Connection refused"

    def test_put_with_details(self, cache, mock_table) -> None:
        result = HealthCheckResult(
            source_name="detail-source",
            healthy=True,
            details={"tables_checked": 3, "region": "us-west-2"},
        )
        cache.put(result)
        item = mock_table.put_item.call_args[1]["Item"]
        assert "details" in item
        import json

        assert json.loads(item["details"]) == {"tables_checked": 3, "region": "us-west-2"}

    def test_put_omits_none_fields(self, cache, mock_table) -> None:
        result = HealthCheckResult(source_name="minimal", healthy=True)
        cache.put(result)
        item = mock_table.put_item.call_args[1]["Item"]
        assert "last_data_time" not in item
        assert "error" not in item
        assert "details" not in item

    def test_put_many(self, cache, mock_table) -> None:
        results = [
            _make_health_result("source-a"),
            _make_health_result("source-b", healthy=False),
        ]
        cache.put_many(results)
        mock_table.batch_writer.assert_called_once()
        batch = mock_table.batch_writer().__enter__()
        assert batch.put_item.call_count == 2


class TestHealthCacheRead:
    def test_get_latest_returns_none_when_empty(self, cache, mock_table) -> None:
        mock_table.query.return_value = {"Items": []}
        result = cache.get_latest("nonexistent")
        assert result is None

    def test_get_latest_returns_deserialized(self, cache, mock_table) -> None:
        mock_table.query.return_value = {
            "Items": [
                {
                    "source_name": "test-source",
                    "checked_at": "2026-02-13T12:00:00+00:00",
                    "healthy": True,
                    "record_count": 100,
                    "latency_seconds": "0.5",
                    "last_data_time": "2026-02-13T11:55:00+00:00",
                }
            ]
        }
        result = cache.get_latest("test-source")
        assert result is not None
        assert result["source_name"] == "test-source"
        assert result["healthy"] is True
        assert result["record_count"] == 100
        assert result["latency_seconds"] == 0.5
        assert result["data_age_minutes"] is not None

    def test_get_all_latest_empty(self, cache, mock_table) -> None:
        mock_table.scan.return_value = {"Items": []}
        result = cache.get_all_latest()
        assert result == []

    def test_get_all_latest_deduplicates(self, cache, mock_table) -> None:
        mock_table.scan.return_value = {
            "Items": [
                {
                    "source_name": "src-a",
                    "checked_at": "2026-02-13T11:00:00+00:00",
                    "healthy": True,
                    "record_count": 50,
                    "latency_seconds": "0.3",
                },
                {
                    "source_name": "src-a",
                    "checked_at": "2026-02-13T12:00:00+00:00",
                    "healthy": False,
                    "record_count": 0,
                    "latency_seconds": "5.0",
                },
                {
                    "source_name": "src-b",
                    "checked_at": "2026-02-13T12:00:00+00:00",
                    "healthy": True,
                    "record_count": 200,
                    "latency_seconds": "0.1",
                },
            ]
        }
        results = cache.get_all_latest()
        assert len(results) == 2
        by_name = {r["source_name"]: r for r in results}
        # Should keep the latest for src-a (12:00, unhealthy)
        assert by_name["src-a"]["healthy"] is False
        assert by_name["src-b"]["healthy"] is True

    def test_get_history(self, cache, mock_table) -> None:
        mock_table.query.return_value = {
            "Items": [
                {
                    "source_name": "src-a",
                    "checked_at": f"2026-02-13T{12 - i:02d}:00:00+00:00",
                    "healthy": True,
                    "record_count": 100 + i,
                    "latency_seconds": "0.5",
                }
                for i in range(5)
            ]
        }
        results = cache.get_history("src-a", limit=5)
        assert len(results) == 5
        assert results[0]["checked_at"] == "2026-02-13T12:00:00+00:00"


class TestDeserialize:
    def test_deserialize_with_details(self) -> None:
        import json

        item = {
            "source_name": "test",
            "checked_at": "2026-02-13T12:00:00+00:00",
            "healthy": True,
            "record_count": 42,
            "latency_seconds": "1.23",
            "details": json.dumps({"key": "value"}),
        }
        result = HealthCacheClient._deserialize(item)
        assert result["details"] == {"key": "value"}
        assert result["latency_seconds"] == 1.23
        assert result["record_count"] == 42

    def test_deserialize_missing_optional_fields(self) -> None:
        item = {
            "source_name": "test",
            "checked_at": "2026-02-13T12:00:00+00:00",
            "healthy": False,
        }
        result = HealthCacheClient._deserialize(item)
        assert result["record_count"] == 0
        assert result["latency_seconds"] == 0.0
        assert result["last_data_time"] is None
        assert result["error"] is None
        assert result["data_age_minutes"] is None
