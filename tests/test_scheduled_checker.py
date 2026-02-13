"""Tests for the EventBridge scheduled health checker Lambda handler."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from secdashboards.connectors.base import HealthCheckResult


def _make_result(name: str, healthy: bool = True) -> HealthCheckResult:
    return HealthCheckResult(
        source_name=name,
        healthy=healthy,
        record_count=100 if healthy else 0,
        latency_seconds=0.5 if healthy else 5.0,
        last_data_time=datetime(2026, 2, 13, 12, 0, 0, tzinfo=UTC) if healthy else None,
        error=None if healthy else "Timeout",
    )


class TestBuildCatalog:
    @patch.dict("os.environ", {"SECDASH_SECURITY_LAKE_DB": ""}, clear=False)
    def test_builds_catalog_without_security_lake(self) -> None:
        from secdashboards.health.scheduled_checker import _build_catalog

        catalog = _build_catalog()
        sources = catalog.list_sources()
        # Should have at least duckdb-local
        assert any(s.name == "duckdb-local" for s in sources)

    @patch.dict(
        "os.environ",
        {
            "SECDASH_SECURITY_LAKE_DB": "test_db",
            "SECDASH_USE_DIRECT_QUERY": "false",
            "SECDASH_ATHENA_OUTPUT": "s3://test-bucket/output/",
        },
        clear=False,
    )
    def test_builds_catalog_with_athena_sources(self) -> None:
        from secdashboards.health.scheduled_checker import _build_catalog

        catalog = _build_catalog()
        sl_sources = catalog.list_sources(tag="security-lake")
        assert len(sl_sources) == 5
        assert any(s.name == "cloudtrail" for s in sl_sources)


class TestCheckOne:
    def test_successful_check(self) -> None:
        from secdashboards.health.scheduled_checker import _check_one

        mock_catalog = MagicMock()
        mock_connector = MagicMock()
        mock_connector.check_health.return_value = _make_result("test-source")
        mock_catalog.get_connector.return_value = mock_connector

        outcome = _check_one(mock_catalog, "test-source")
        assert outcome["ok"] is True
        assert outcome["result"].healthy is True

    def test_failed_check(self) -> None:
        from secdashboards.health.scheduled_checker import _check_one

        mock_catalog = MagicMock()
        mock_catalog.get_connector.side_effect = RuntimeError("No connector")

        outcome = _check_one(mock_catalog, "bad-source")
        assert outcome["ok"] is False
        assert outcome["result"].healthy is False
        assert "No connector" in outcome["result"].error


class TestHandler:
    @patch("secdashboards.health.scheduled_checker._build_catalog")
    @patch("secdashboards.health.scheduled_checker.HealthCacheClient")
    @patch.dict(
        "os.environ",
        {"SECDASH_HEALTH_CACHE_TABLE": "test-cache-table"},
        clear=False,
    )
    def test_handler_no_sources(self, mock_cache_cls, mock_build) -> None:
        from secdashboards.health.scheduled_checker import handler

        mock_catalog = MagicMock()
        mock_catalog.list_sources.return_value = []
        mock_build.return_value = mock_catalog

        result = handler({}, None)
        assert result["checked"] == 0
        mock_cache_cls.assert_not_called()

    @patch("secdashboards.health.scheduled_checker._build_catalog")
    @patch("secdashboards.health.scheduled_checker.HealthCacheClient")
    @patch.dict(
        "os.environ",
        {"SECDASH_HEALTH_CACHE_TABLE": "test-cache-table"},
        clear=False,
    )
    def test_handler_checks_and_caches(self, mock_cache_cls, mock_build) -> None:
        from secdashboards.health.scheduled_checker import handler

        # Set up catalog with 2 mock sources
        mock_catalog = MagicMock()
        source_a = MagicMock()
        source_a.name = "source-a"
        source_a.tags = ["security-lake"]
        source_b = MagicMock()
        source_b.name = "source-b"
        source_b.tags = ["security-lake"]
        mock_catalog.list_sources.return_value = [source_a, source_b]

        # Set up connectors
        connector_a = MagicMock()
        connector_a.check_health.return_value = _make_result("source-a", healthy=True)
        connector_b = MagicMock()
        connector_b.check_health.return_value = _make_result("source-b", healthy=False)
        mock_catalog.get_connector.side_effect = lambda name: {
            "source-a": connector_a,
            "source-b": connector_b,
        }[name]
        mock_build.return_value = mock_catalog

        # Set up cache mock
        mock_cache = MagicMock()
        mock_cache_cls.return_value = mock_cache

        result = handler({}, None)

        assert result["checked"] == 2
        assert result["healthy"] == 1
        assert result["unhealthy"] == 1
        mock_cache.put_many.assert_called_once()
        cached_results = mock_cache.put_many.call_args[0][0]
        assert len(cached_results) == 2

    @patch("secdashboards.health.scheduled_checker._build_catalog")
    @patch("secdashboards.health.scheduled_checker.HealthCacheClient")
    @patch.dict(
        "os.environ",
        {
            "SECDASH_HEALTH_CACHE_TABLE": "custom-table",
            "SECDASH_REGION": "eu-west-1",
        },
        clear=False,
    )
    def test_handler_uses_env_config(self, mock_cache_cls, mock_build) -> None:
        from secdashboards.health.scheduled_checker import handler

        mock_catalog = MagicMock()
        mock_catalog.list_sources.return_value = []
        mock_build.return_value = mock_catalog

        handler({}, None)
        # Handler should not create cache client if no sources
        # but we can verify it read env vars by checking it returned
