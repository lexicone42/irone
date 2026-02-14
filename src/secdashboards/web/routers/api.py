"""JSON API router — programmatic access to sources, rules, and queries."""

import contextlib
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from secdashboards.connectors.base import HealthCheckResult
from secdashboards.web.state import AppState, get_state

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")


class QueryRequest(BaseModel):
    """SQL query request body."""

    sql: str


class RunDetectionRequest(BaseModel):
    """Request body for running a detection rule."""

    source_name: str = ""
    lookback_minutes: int = 15


class CreateFromDetectionRequest(BaseModel):
    """Request body for creating an investigation from a detection run."""

    rule_id: str
    name: str = ""
    source_name: str = ""
    lookback_minutes: int = 15
    enrichment_window_minutes: int = 60


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


@router.post("/detections/{rule_id}/run")
def run_detection(
    rule_id: str,
    body: RunDetectionRequest,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Run a detection rule and return the result.

    If ``source_name`` is empty, uses the first Security Lake source.
    Returns the detection result including whether it triggered,
    match count, and sample matches.
    """
    rule = state.runner.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    # Resolve connector
    try:
        if body.source_name:
            connector = state.catalog.get_connector(body.source_name)
        else:
            sl_sources = state.catalog.list_sources(tag="security-lake")
            if not sl_sources:
                raise ValueError("No Security Lake sources configured")
            connector = state.catalog.get_connector(sl_sources[0].name)
    except (ValueError, IndexError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    result = state.runner.run_rule(rule_id, connector, lookback_minutes=body.lookback_minutes)

    return {
        "rule_id": result.rule_id,
        "rule_name": result.rule_name,
        "triggered": result.triggered,
        "severity": result.severity,
        "match_count": result.match_count,
        "matches": result.matches[:20],
        "message": result.message,
        "executed_at": result.executed_at.isoformat(),
        "execution_time_ms": result.execution_time_ms,
        "error": result.error,
    }


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


# ─── Investigations ──────────────────────────────────────────────


class CreateInvestigationRequest(BaseModel):
    """Request body for creating an investigation."""

    name: str = ""
    users: list[str] = []
    ips: list[str] = []


class TagEventRequest(BaseModel):
    """Request body for tagging a timeline event."""

    event_id: str
    tag: str
    notes: str = ""


class EnrichRequest(BaseModel):
    """Request body for enriching an investigation."""

    users: list[str] = []
    ips: list[str] = []


@router.get("/investigations")
def list_investigations(
    state: AppState = Depends(get_state),
) -> list[dict[str, Any]]:
    """List all investigations with summary stats."""
    result = []
    for inv_id, data in state.investigations.items():
        graph = data["graph"]
        result.append(
            {
                "id": inv_id,
                "name": data.get("name", inv_id),
                "node_count": graph.node_count(),
                "edge_count": graph.edge_count(),
                "created_at": data.get("created_at", ""),
            }
        )
    return result


@router.post("/investigations")
def create_investigation_api(
    body: CreateInvestigationRequest,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Create a new investigation from user/IP identifiers."""
    import uuid
    from datetime import UTC

    inv_id = f"inv-{uuid.uuid4().hex[:8]}"

    try:
        from secdashboards.connectors.security_lake import SecurityLakeConnector
        from secdashboards.graph.builder import GraphBuilder

        sl_sources = state.catalog.list_sources(tag="security-lake")
        sl_connector = state.catalog.get_connector(sl_sources[0].name)
        if not isinstance(sl_connector, SecurityLakeConnector):
            raise TypeError("Expected SecurityLakeConnector")
        builder = GraphBuilder(security_lake=sl_connector)
        graph = builder.build_from_identifiers(
            users=body.users or None,
            ips=body.ips or None,
        )
    except Exception:
        from secdashboards.graph.models import SecurityGraph

        graph = SecurityGraph()

    created_at = datetime.now(UTC).isoformat()
    state.investigations[inv_id] = {
        "name": body.name or inv_id,
        "graph": graph,
        "created_at": created_at,
        "timeline_tags": {},
    }

    if state.investigation_store:
        state.investigation_store.save_investigation(
            inv_id, body.name or inv_id, graph, created_at=created_at
        )

    return {
        "id": inv_id,
        "name": body.name or inv_id,
        "created_at": created_at,
        "summary": graph.summary(),
    }


@router.post("/investigations/from-detection")
def create_investigation_from_detection(
    body: CreateFromDetectionRequest,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Full pipeline: run detection → build graph → create investigation.

    1. Runs the specified detection rule
    2. If triggered, builds a SecurityGraph via GraphBuilder.build_from_detection
    3. Extracts timeline from graph
    4. Saves everything as a new investigation

    Returns the new investigation ID and summary, or error details
    if the detection didn't trigger.
    """
    import uuid
    from datetime import UTC

    # Step 1: Run the detection
    rule = state.runner.get_rule(body.rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {body.rule_id} not found")

    try:
        if body.source_name:
            connector = state.catalog.get_connector(body.source_name)
        else:
            sl_sources = state.catalog.list_sources(tag="security-lake")
            if not sl_sources:
                raise ValueError("No Security Lake sources configured")
            connector = state.catalog.get_connector(sl_sources[0].name)
    except (ValueError, IndexError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    detection = state.runner.run_rule(
        body.rule_id, connector, lookback_minutes=body.lookback_minutes
    )

    if detection.error:
        return {
            "created": False,
            "error": detection.error,
            "rule_id": body.rule_id,
            "triggered": False,
        }

    if not detection.triggered:
        return {
            "created": False,
            "rule_id": body.rule_id,
            "triggered": False,
            "message": detection.message or "No matches found",
            "match_count": 0,
        }

    # Step 2: Build graph from detection
    from secdashboards.graph.builder import GraphBuilder

    try:
        from secdashboards.connectors.security_lake import SecurityLakeConnector

        sl_sources = state.catalog.list_sources(tag="security-lake")
        sl_connector = state.catalog.get_connector(sl_sources[0].name)
        if not isinstance(sl_connector, SecurityLakeConnector):
            raise TypeError("Expected SecurityLakeConnector")
        builder = GraphBuilder(security_lake=sl_connector)
    except Exception:
        builder = GraphBuilder()

    graph = builder.build_from_detection(
        detection, enrichment_window_minutes=body.enrichment_window_minutes
    )

    # Step 3: Extract timeline
    from secdashboards.graph.timeline import extract_timeline_from_graph

    timeline = extract_timeline_from_graph(graph)

    # Step 4: Save investigation
    inv_id = f"inv-{uuid.uuid4().hex[:8]}"
    inv_name = body.name or f"{detection.rule_name} - {detection.executed_at:%Y-%m-%d %H:%M}"
    created_at = datetime.now(UTC).isoformat()

    state.investigations[inv_id] = {
        "name": inv_name,
        "graph": graph,
        "created_at": created_at,
        "timeline_tags": {},
        "detection": {
            "rule_id": detection.rule_id,
            "rule_name": detection.rule_name,
            "severity": detection.severity,
            "match_count": detection.match_count,
            "triggered_at": detection.executed_at.isoformat(),
        },
    }

    if state.investigation_store:
        state.investigation_store.save_investigation(inv_id, inv_name, graph, created_at=created_at)

    return {
        "created": True,
        "id": inv_id,
        "name": inv_name,
        "created_at": created_at,
        "detection": {
            "rule_id": detection.rule_id,
            "triggered": True,
            "match_count": detection.match_count,
            "severity": detection.severity,
        },
        "summary": graph.summary(),
        "timeline_event_count": len(timeline.events) if timeline else 0,
    }


@router.get("/investigations/{inv_id}")
def get_investigation(
    inv_id: str,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Get investigation detail with summary."""
    inv = state.investigations.get(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {inv_id} not found")

    graph = inv["graph"]
    return {
        "id": inv_id,
        "name": inv.get("name", inv_id),
        "created_at": inv.get("created_at", ""),
        "summary": graph.summary(),
        "timeline_tags": inv.get("timeline_tags", {}),
    }


@router.get("/investigations/{inv_id}/graph")
def get_investigation_graph(
    inv_id: str,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Get graph data in Cytoscape.js format.

    Returns nodes and edges formatted for direct consumption
    by Cytoscape.js ``cy.add(elements)``.
    """
    inv = state.investigations.get(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {inv_id} not found")

    graph = inv["graph"]

    # Convert to Cytoscape.js elements format
    cy_nodes = []
    for node in graph.nodes.values():
        cy_nodes.append(
            {
                "group": "nodes",
                "data": {
                    "id": node.id,
                    "label": node.label,
                    "node_type": node.node_type.value,
                    "event_count": node.event_count,
                    "first_seen": node.first_seen.isoformat() if node.first_seen else None,
                    "last_seen": node.last_seen.isoformat() if node.last_seen else None,
                    **node.properties,
                },
            }
        )

    cy_edges = []
    for edge in graph.edges:
        cy_edges.append(
            {
                "group": "edges",
                "data": {
                    "id": edge.id,
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "edge_type": edge.edge_type.value,
                    "weight": edge.weight,
                    "event_count": edge.event_count,
                },
            }
        )

    return {
        "elements": cy_nodes + cy_edges,
        "summary": graph.summary(),
    }


@router.get("/investigations/{inv_id}/report")
def get_investigation_report(
    inv_id: str,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Generate a structured report from an investigation.

    Converts the investigation graph to ``InvestigationReportData``
    using the existing exporter pipeline. Includes timeline data,
    entity summaries, and detection metadata.
    """
    inv = state.investigations.get(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {inv_id} not found")

    graph = inv["graph"]

    from secdashboards.graph.timeline import extract_timeline_from_graph
    from secdashboards.reports.exporters import graph_to_report_data

    timeline = extract_timeline_from_graph(graph)
    report = graph_to_report_data(
        graph,
        investigation_id=inv_id,
        timeline=timeline,
    )

    return report.model_dump(mode="json")


@router.post("/investigations/{inv_id}/enrich")
def enrich_investigation_api(
    inv_id: str,
    body: EnrichRequest,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Enrich an investigation with additional users/IPs. Returns updated graph."""
    inv = state.investigations.get(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {inv_id} not found")

    try:
        from secdashboards.connectors.security_lake import SecurityLakeConnector
        from secdashboards.graph.builder import GraphBuilder

        sl_sources = state.catalog.list_sources(tag="security-lake")
        sl_connector = state.catalog.get_connector(sl_sources[0].name)
        if not isinstance(sl_connector, SecurityLakeConnector):
            raise TypeError("Expected SecurityLakeConnector")
        builder = GraphBuilder(security_lake=sl_connector)
        new_graph = builder.build_from_identifiers(
            users=body.users or None,
            ips=body.ips or None,
        )
        graph = inv["graph"]
        for node in new_graph.nodes.values():
            graph.add_node(node)
        for edge in new_graph.edges:
            graph.add_edge(edge)

        if state.investigation_store:
            state.investigation_store.save_graph(inv_id, graph)
            state.investigation_store.delete_artifacts(inv_id)

        return {
            "summary": graph.summary(),
            "added_nodes": new_graph.node_count(),
            "added_edges": new_graph.edge_count(),
        }
    except Exception as exc:
        return {"error": str(exc), "summary": inv["graph"].summary()}


@router.post("/investigations/{inv_id}/timeline/tag")
def tag_timeline_event_api(
    inv_id: str,
    body: TagEventRequest,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Tag a timeline event."""
    inv = state.investigations.get(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {inv_id} not found")

    inv.setdefault("timeline_tags", {})[body.event_id] = body.tag

    if state.investigation_store:
        state.investigation_store.tag_event(inv_id, body.event_id, body.tag, body.notes)
        state.investigation_store.delete_artifacts(inv_id)

    return {"event_id": body.event_id, "tag": body.tag}


@router.delete("/investigations/{inv_id}")
def delete_investigation_api(
    inv_id: str,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Delete an investigation."""
    if inv_id not in state.investigations:
        raise HTTPException(status_code=404, detail=f"Investigation {inv_id} not found")

    state.investigations.pop(inv_id, None)
    if state.investigation_store:
        state.investigation_store.delete_investigation(inv_id)

    return {"deleted": inv_id}
