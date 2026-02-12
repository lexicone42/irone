"""JSON API router — programmatic access to sources, rules, and queries."""

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from secdashboards.web.state import AppState, get_state

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
