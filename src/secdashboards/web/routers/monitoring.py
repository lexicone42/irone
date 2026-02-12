"""Monitoring router — health checks and catalog overview."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from secdashboards.web.state import AppState, get_state

router = APIRouter(prefix="/monitoring")


@router.get("/", response_class=HTMLResponse)
def monitoring_index(request: Request, state: AppState = Depends(get_state)) -> HTMLResponse:
    """Health monitoring overview page."""
    templates: Jinja2Templates = request.app.state.templates
    sources = state.catalog.list_sources()
    return templates.TemplateResponse(request, "pages/monitoring.html", {"sources": sources})


@router.post("/check", response_class=HTMLResponse)
def run_health_check(request: Request, state: AppState = Depends(get_state)) -> HTMLResponse:
    """Run health checks on all sources, return results fragment."""
    templates: Jinja2Templates = request.app.state.templates
    results = []
    for source in state.catalog.list_sources():
        try:
            connector = state.catalog.get_connector(source.name)
            health = connector.check_health()
            results.append(health.to_dict())
        except Exception as exc:
            results.append(
                {
                    "source_name": source.name,
                    "healthy": False,
                    "error": str(exc),
                    "record_count": 0,
                    "latency_seconds": 0,
                }
            )

    return templates.TemplateResponse(
        request, "components/health_results.html", {"results": results}
    )


@router.get("/catalog", response_class=HTMLResponse)
def catalog_view(request: Request, state: AppState = Depends(get_state)) -> HTMLResponse:
    """Data catalog display."""
    templates: Jinja2Templates = request.app.state.templates
    sources = state.catalog.list_sources()
    return templates.TemplateResponse(request, "pages/catalog.html", {"sources": sources})
