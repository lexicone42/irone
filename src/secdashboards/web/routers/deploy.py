"""Deploy router — Lambda build and deployment dashboard."""

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from secdashboards.web.state import AppState, get_state

router = APIRouter(prefix="/deploy")


@router.get("/", response_class=HTMLResponse)
def deploy_index(request: Request, state: AppState = Depends(get_state)) -> HTMLResponse:
    """Deployment dashboard showing rules and build status."""
    templates: Jinja2Templates = request.app.state.templates
    rules = state.runner.list_rules()
    return templates.TemplateResponse(
        request,
        "pages/deploy/index.html",
        {"rules": rules, "region": state.config.region},
    )


@router.post("/build", response_class=HTMLResponse)
def build_lambda(
    request: Request,
    state: AppState = Depends(get_state),
    rule_id: str = Form(...),
    data_source: str = Form("security-lake"),
    lookback_minutes: int = Form(15),
) -> HTMLResponse:
    """Build a Lambda deployment package for a rule."""
    templates: Jinja2Templates = request.app.state.templates
    try:
        from secdashboards.deploy.lambda_builder import LambdaBuilder

        rule = state.runner.get_rule(rule_id)
        if not rule:
            return templates.TemplateResponse(
                request,
                "components/build_result.html",
                {"success": False, "error": f"Rule {rule_id} not found", "package_path": ""},
            )

        builder = LambdaBuilder(output_dir=Path("/tmp/secdash-builds"))
        package_path = builder.build_package(
            rule=rule,
            data_source=data_source,
            lookback_minutes=lookback_minutes,
        )

        # Track operation
        op_id = f"build-{rule_id}"
        state.operations[op_id] = {
            "type": "build",
            "rule_id": rule_id,
            "status": "complete",
            "package_path": str(package_path),
        }

        return templates.TemplateResponse(
            request,
            "components/build_result.html",
            {
                "success": True,
                "error": None,
                "package_path": str(package_path),
                "rule_name": rule.name,
            },
        )
    except Exception as exc:
        return templates.TemplateResponse(
            request,
            "components/build_result.html",
            {"success": False, "error": str(exc), "package_path": ""},
        )


@router.get("/operations/{op_id}")
def get_operation_status(
    op_id: str,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Poll operation status (for HTMX polling pattern)."""
    op = state.operations.get(op_id)
    if not op:
        return {"error": f"Operation {op_id} not found", "status": "unknown"}
    return op
