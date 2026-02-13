"""EventBridge-triggered Lambda handler for scheduled health checks.

Runs health checks on all configured data sources in parallel
and writes results to DynamoDB ``secdash_health_cache``.

Environment variables::

    SECDASH_SECURITY_LAKE_DB   — Security Lake Glue database name
    SECDASH_REGION             — AWS region (default: us-west-2)
    SECDASH_ACCOUNT_ID         — AWS account ID (auto-detected if empty)
    SECDASH_USE_DIRECT_QUERY   — Use DuckDB+Iceberg direct queries (default: true)
    SECDASH_ATHENA_OUTPUT      — Athena output S3 location (fallback)
    SECDASH_HEALTH_CACHE_TABLE — DynamoDB table name for health cache
"""

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from secdashboards.health.cache import HealthCacheClient

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _build_catalog():
    """Build a minimal DataCatalog with Security Lake sources.

    Reuses the same auto-registration logic as the web app.
    """
    from secdashboards.catalog.models import DataSource, DataSourceType
    from secdashboards.catalog.registry import DataCatalog
    from secdashboards.web.config import WebConfig

    config = WebConfig()
    catalog = DataCatalog()

    # Register DuckDB for local queries
    duckdb_source = DataSource(
        name="duckdb-local",
        type=DataSourceType.DUCKDB,
        description="Local DuckDB engine",
        connector_config={"db_path": ":memory:"},
        tags=["local", "duckdb"],
    )
    catalog.add_source(duckdb_source)

    # Import and use the same auto-registration from state module
    if config.security_lake_db:
        from secdashboards.web.state import _register_default_security_lake_sources

        _register_default_security_lake_sources(catalog, config)

    return catalog


def _check_one(catalog, source_name: str) -> dict[str, Any]:
    """Check health of a single source (thread-safe)."""
    try:
        connector = catalog.get_connector(source_name)
        result = connector.check_health()
        return {"ok": True, "result": result}
    except Exception as exc:
        logger.error("Health check failed for %s: %s", source_name, exc)
        from secdashboards.connectors.base import HealthCheckResult

        return {
            "ok": False,
            "result": HealthCheckResult(
                source_name=source_name,
                healthy=False,
                error=str(exc),
            ),
        }


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """EventBridge Lambda handler — check all sources and cache results."""
    table_name = os.environ.get("SECDASH_HEALTH_CACHE_TABLE", "secdash_health_cache")
    region = os.environ.get("SECDASH_REGION", os.environ.get("AWS_REGION", "us-west-2"))

    logger.info("Starting scheduled health check (table=%s, region=%s)", table_name, region)

    # Build catalog with configured sources
    catalog = _build_catalog()
    sources = catalog.list_sources(tag="security-lake")

    if not sources:
        logger.warning("No Security Lake sources configured — skipping health checks")
        return {"checked": 0, "results": []}

    # Run health checks in parallel
    results = []
    with ThreadPoolExecutor(max_workers=min(len(sources), 5)) as executor:
        futures = {executor.submit(_check_one, catalog, s.name): s.name for s in sources}
        for future in as_completed(futures):
            outcome = future.result()
            results.append(outcome["result"])

    # Write to DynamoDB cache
    cache = HealthCacheClient(table_name=table_name, region_name=region)
    cache.put_many(results)

    healthy = sum(1 for r in results if r.healthy)
    total = len(results)
    logger.info("Health check complete: %d/%d healthy", healthy, total)

    return {
        "checked": total,
        "healthy": healthy,
        "unhealthy": total - healthy,
        "results": [r.to_dict() for r in results],
    }
