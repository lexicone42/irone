"""Dashboard router — main overview page."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from secdashboards.web.state import AppState, get_state

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, state: AppState = Depends(get_state)) -> HTMLResponse:
    """Main dashboard showing source/rule counts and region info."""
    templates: Jinja2Templates = request.app.state.templates
    sources = state.catalog.list_sources()
    rules = state.runner.list_rules()
    return templates.TemplateResponse(
        request,
        "pages/dashboard.html",
        {
            "source_count": len(sources),
            "rule_count": len(rules),
            "region": state.config.region,
            "sources": sources,
        },
    )
