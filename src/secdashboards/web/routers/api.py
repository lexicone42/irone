"""JSON API router — programmatic access to sources, rules, and queries."""

import contextlib
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from secdashboards.connectors.base import HealthCheckResult
from secdashboards.web.state import AppState, get_state

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")


class QueryRequest(BaseModel):
    """SQL query request body."""

    sql: str


@router.get("/sources")
def list_sources(
    state: AppState = Depends(get_state),
    tag: str | None = None,
) -> list[dict[str, Any]]:
    """List all data sources, optionally filtered by tag."""
    sources = state.catalog.list_sources(tag=tag)
    return [
        {
            "name": s.name,
            "type": s.type.value,
            "description": s.description,
            "region": s.region,
            "tags": s.tags,
        }
        for s in sources
    ]


@router.get("/rules")
def list_rules(
    state: AppState = Depends(get_state),
    enabled_only: bool = True,
) -> list[dict[str, Any]]:
    """List all detection rules."""
    rules = state.runner.list_rules(enabled_only=enabled_only)
    return [r.to_dict() for r in rules]


@router.get("/rules/{rule_id}")
def get_rule(
    rule_id: str,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Get a specific rule by ID."""
    rule = state.runner.get_rule(rule_id)
    if not rule:
        return {"error": f"Rule {rule_id} not found"}
    return rule.to_dict()


@router.post("/query")
def execute_query(
    body: QueryRequest,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Execute a SQL query against DuckDB."""
    try:
        df = state.duckdb.query(body.sql)
        return {
            "columns": df.columns,
            "rows": df.to_dicts(),
            "row_count": len(df),
        }
    except Exception as exc:
        return {"error": str(exc), "columns": [], "rows": [], "row_count": 0}


@router.get("/operations/{op_id}")
def get_operation(
    op_id: str,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Poll operation status."""
    op = state.operations.get(op_id)
    if not op:
        return {"error": f"Operation {op_id} not found", "status": "unknown"}
    return op


# ------------------------------------------------------------------
# Health endpoints (read from DynamoDB cache, fall back to live check)
# ------------------------------------------------------------------


def _live_check_source(catalog, source_name: str) -> dict[str, Any]:
    """Run a live health check for one source (thread-safe helper)."""
    try:
        connector = catalog.get_connector(source_name)
        return connector.check_health().to_dict()
    except Exception as exc:
        return {
            "source_name": source_name,
            "healthy": False,
            "error": str(exc),
            "record_count": 0,
            "latency_seconds": 0,
        }


def _dicts_to_health_results(dicts: list[dict[str, Any]]) -> list[HealthCheckResult]:
    """Convert serialized health dicts back to HealthCheckResult objects."""
    results = []
    for r in dicts:
        last_data = None
        if r.get("last_data_time"):
            with contextlib.suppress(ValueError, TypeError):
                last_data = datetime.fromisoformat(r["last_data_time"])
        results.append(
            HealthCheckResult(
                source_name=r["source_name"],
                healthy=r.get("healthy", False),
                last_data_time=last_data,
                record_count=r.get("record_count", 0),
                latency_seconds=r.get("latency_seconds", 0),
                error=r.get("error"),
                details=r.get("details"),
            )
        )
    return results


def _write_through_cache(state: AppState, results: list[dict[str, Any]]) -> None:
    """Write health results to DynamoDB cache (best-effort)."""
    if not state.health_cache or not results:
        return
    try:
        state.health_cache.put_many(_dicts_to_health_results(results))
    except Exception:
        logger.warning("Failed to write health cache", exc_info=True)


@router.get("/sources/health")
def all_sources_health(
    state: AppState = Depends(get_state),
    live: bool = False,
) -> list[dict[str, Any]]:
    """Get health status for all sources.

    By default reads from DynamoDB cache. Pass ``?live=true`` to bypass cache
    and run live health checks (slower — triggers connector queries).
    """
    if not live and state.health_cache:
        cached = state.health_cache.get_all_latest()
        if cached:
            return sorted(cached, key=lambda r: r.get("source_name", ""))

    # Live fallback: check all sources in parallel
    sources = state.catalog.list_sources()
    results = []
    with ThreadPoolExecutor(max_workers=max(len(sources), 1)) as executor:
        futures = {
            executor.submit(_live_check_source, state.catalog, s.name): s.name for s in sources
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.get("source_name", ""))

    _write_through_cache(state, results)
    return results


@router.get("/sources/{source_name}/health")
def source_health(
    source_name: str,
    state: AppState = Depends(get_state),
    live: bool = False,
) -> dict[str, Any]:
    """Get health status for a single source.

    Reads from cache by default. Pass ``?live=true`` for a fresh check.
    """
    if not live and state.health_cache:
        cached = state.health_cache.get_latest(source_name)
        if cached:
            return cached

    # Live check
    return _live_check_source(state.catalog, source_name)


@router.get("/sources/{source_name}/health/history")
def source_health_history(
    source_name: str,
    state: AppState = Depends(get_state),
    limit: int = 24,
) -> list[dict[str, Any]]:
    """Get health check history for a source (newest first)."""
    if not state.health_cache:
        return []
    return state.health_cache.get_history(source_name, limit=limit)


@router.post("/sources/refresh")
def refresh_health(
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Trigger on-demand health checks for all sources.

    Runs all checks in parallel and writes results to cache.
    Returns the fresh results.
    """
    sources = state.catalog.list_sources()
    results = []
    with ThreadPoolExecutor(max_workers=max(len(sources), 1)) as executor:
        futures = {
            executor.submit(_live_check_source, state.catalog, s.name): s.name for s in sources
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.get("source_name", ""))

    _write_through_cache(state, results)
    return {"refreshed": len(results), "results": results}


@router.get("/dashboard")
def dashboard_summary(
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Dashboard summary stats — source counts, rule counts, health overview."""
    sources = state.catalog.list_sources()
    rules = state.runner.list_rules()

    # Health summary from cache (if available)
    health_summary: dict[str, Any] = {"available": False}
    if state.health_cache:
        cached = state.health_cache.get_all_latest()
        if cached:
            healthy_count = sum(1 for r in cached if r.get("healthy"))
            health_summary = {
                "available": True,
                "total": len(cached),
                "healthy": healthy_count,
                "unhealthy": len(cached) - healthy_count,
            }

    return {
        "source_count": len(sources),
        "rule_count": len(rules),
        "region": state.config.region,
        "investigation_count": len(state.investigations),
        "health": health_summary,
    }


@router.get("/auth/config")
def auth_config(
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Public auth configuration for the client-side PKCE flow.

    Returns Cognito domain, client ID, and redirect URI so the static
    frontend can initiate the OIDC flow without hardcoding secrets.
    """
    config = state.config
    return {
        "auth_enabled": config.auth_enabled,
        "cognito_domain": config.cognito_domain,
        "cognito_client_id": config.cognito_client_id,
        "cognito_region": config.cognito_region,
        "redirect_uri": config.cognito_redirect_uri,
    }
