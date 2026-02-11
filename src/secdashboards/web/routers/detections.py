"""Detections router — rule management, testing, and query exploration."""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from secdashboards.detections.rule import DetectionMetadata, Severity, SQLDetectionRule
from secdashboards.web.state import AppState, get_state

router = APIRouter(prefix="/detections")


@router.get("/", response_class=HTMLResponse)
def detections_index(request: Request, state: AppState = Depends(get_state)) -> HTMLResponse:
    """List all detection rules."""
    templates: Jinja2Templates = request.app.state.templates
    rules = state.runner.list_rules(enabled_only=False)
    return templates.TemplateResponse(request, "pages/detections/index.html", {"rules": rules})


@router.get("/new", response_class=HTMLResponse)
def new_rule_form(request: Request) -> HTMLResponse:
    """Blank rule editor form."""
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "pages/detections/rule_editor.html",
        {"severities": list(Severity), "rule": None},
    )


@router.post("/", response_class=HTMLResponse)
def create_rule(
    request: Request,
    state: AppState = Depends(get_state),
    name: str = Form(...),
    description: str = Form(""),
    severity: str = Form("medium"),
    query_template: str = Form(...),
    threshold: int = Form(1),
    tags: str = Form(""),
) -> HTMLResponse:
    """Create a new detection rule from form data."""
    templates: Jinja2Templates = request.app.state.templates
    rule_id = f"rule-{uuid.uuid4().hex[:8]}"
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]

    metadata = DetectionMetadata(
        id=rule_id,
        name=name,
        description=description,
        severity=Severity(severity),
        tags=tag_list,
    )
    rule = SQLDetectionRule(
        metadata=metadata,
        query_template=query_template,
        threshold=threshold,
    )
    state.runner.register_rule(rule)

    rules = state.runner.list_rules(enabled_only=False)
    return templates.TemplateResponse(request, "pages/detections/index.html", {"rules": rules})


@router.post("/{rule_id}/test", response_class=HTMLResponse)
def test_rule(
    request: Request,
    rule_id: str,
    state: AppState = Depends(get_state),
) -> HTMLResponse:
    """Test a detection rule against DuckDB, return results fragment."""
    templates: Jinja2Templates = request.app.state.templates
    try:
        result = state.runner.run_rule(
            rule_id,
            state.duckdb,
            start=datetime(2024, 1, 1, tzinfo=UTC),
            end=datetime.now(UTC),
        )
        return templates.TemplateResponse(
            request,
            "components/detection_result.html",
            {"result": result, "error": None},
        )
    except Exception as exc:
        return templates.TemplateResponse(
            request,
            "components/detection_result.html",
            {"result": None, "error": str(exc)},
        )


@router.get("/query-explorer", response_class=HTMLResponse)
def query_explorer(request: Request) -> HTMLResponse:
    """Ad-hoc SQL query page."""
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(request, "pages/detections/query_explorer.html", {})


@router.post("/query-explorer/run", response_class=HTMLResponse)
def run_query(
    request: Request,
    state: AppState = Depends(get_state),
    sql: str = Form(...),
) -> HTMLResponse:
    """Execute SQL query against DuckDB, return results fragment."""
    templates: Jinja2Templates = request.app.state.templates
    try:
        df = state.duckdb.query(sql)
        columns = df.columns
        rows = df.to_dicts()
        return templates.TemplateResponse(
            request,
            "components/query_results.html",
            {"columns": columns, "rows": rows, "row_count": len(rows), "error": None},
        )
    except Exception as exc:
        return templates.TemplateResponse(
            request,
            "components/query_results.html",
            {"columns": [], "rows": [], "row_count": 0, "error": str(exc)},
        )


@router.post("/ai-generate", response_class=HTMLResponse)
def ai_generate_rule(
    request: Request,
    state: AppState = Depends(get_state),
    description: str = Form(...),
    context: str = Form(""),
) -> HTMLResponse:
    """Generate a detection rule using Bedrock AI."""
    templates: Jinja2Templates = request.app.state.templates
    try:
        from secdashboards.ai.assistant import BedrockAssistant

        assistant = BedrockAssistant(region=state.config.region)
        response = assistant.generate_detection_rule(
            description=description,
            context=context or None,
        )
        return templates.TemplateResponse(
            request,
            "components/ai_result.html",
            {"content": response.content, "cost": response.cost_usd, "error": None},
        )
    except Exception as exc:
        return templates.TemplateResponse(
            request,
            "components/ai_result.html",
            {"content": "", "cost": 0, "error": str(exc)},
        )
