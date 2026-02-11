"""Security Lake router — connectivity checks and data source health."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from secdashboards.web.state import AppState, get_state

router = APIRouter(prefix="/security-lake")


@router.get("/", response_class=HTMLResponse)
def security_lake_index(request: Request, state: AppState = Depends(get_state)) -> HTMLResponse:
    """Security Lake connectivity check page."""
    templates: Jinja2Templates = request.app.state.templates
    sl_sources = state.catalog.list_sources(tag="security-lake")
    return templates.TemplateResponse(
        request,
        "pages/security_lake.html",
        {"sources": sl_sources, "region": state.config.region},
    )


@router.post("/test", response_class=HTMLResponse)
def test_security_lake(request: Request, state: AppState = Depends(get_state)) -> HTMLResponse:
    """Test Security Lake connections, return results fragment."""
    templates: Jinja2Templates = request.app.state.templates
    results = []
    for source in state.catalog.list_sources(tag="security-lake"):
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
