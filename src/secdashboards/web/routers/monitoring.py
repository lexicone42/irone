"""Monitoring router — health checks and catalog overview."""

from concurrent.futures import ThreadPoolExecutor, as_completed

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


def _check_one_source(catalog, source_name: str) -> dict:
    """Run health check for a single source (thread-safe)."""
    try:
        connector = catalog.get_connector(source_name)
        health = connector.check_health()
        return health.to_dict()
    except Exception as exc:
        return {
            "source_name": source_name,
            "healthy": False,
            "error": str(exc),
            "record_count": 0,
            "latency_seconds": 0,
        }


@router.post("/check", response_class=HTMLResponse)
def run_health_check(request: Request, state: AppState = Depends(get_state)) -> HTMLResponse:
    """Run health checks on all sources in parallel, return results fragment."""
    templates: Jinja2Templates = request.app.state.templates
    sources = state.catalog.list_sources()

    results = []
    with ThreadPoolExecutor(max_workers=len(sources)) as executor:
        futures = {
            executor.submit(_check_one_source, state.catalog, s.name): s.name for s in sources
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.get("source_name", ""))

    return templates.TemplateResponse(
        request, "components/health_results.html", {"results": results}
    )


@router.get("/catalog", response_class=HTMLResponse)
def catalog_view(request: Request, state: AppState = Depends(get_state)) -> HTMLResponse:
    """Data catalog display."""
    templates: Jinja2Templates = request.app.state.templates
    sources = state.catalog.list_sources()
    return templates.TemplateResponse(request, "pages/catalog.html", {"sources": sources})
