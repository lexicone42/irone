"""Investigations router — graph-based security investigations."""

import uuid
from typing import Any, cast

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from secdashboards.web.state import AppState, get_state

router = APIRouter(prefix="/investigations")


@router.get("/", response_class=HTMLResponse)
def investigations_index(request: Request, state: AppState = Depends(get_state)) -> HTMLResponse:
    """List active investigations."""
    templates: Jinja2Templates = request.app.state.templates
    inv_list: list[dict[str, Any]] = []
    for inv_id, data in state.investigations.items():
        graph = data["graph"]
        inv_list.append(
            {
                "id": inv_id,
                "name": data.get("name", inv_id),
                "node_count": graph.node_count(),
                "edge_count": graph.edge_count(),
                "created_at": data.get("created_at", ""),
            }
        )
    return templates.TemplateResponse(
        request, "pages/investigations/index.html", {"investigations": inv_list}
    )


@router.get("/new", response_class=HTMLResponse)
def new_investigation_form(request: Request) -> HTMLResponse:
    """Form to start a new investigation."""
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(request, "pages/investigations/new.html", {})


@router.post("/", response_class=HTMLResponse)
def create_investigation(
    request: Request,
    state: AppState = Depends(get_state),
    name: str = Form(""),
    users: str = Form(""),
    ips: str = Form(""),
) -> HTMLResponse:
    """Start a new investigation from user/IP identifiers."""
    templates: Jinja2Templates = request.app.state.templates
    inv_id = f"inv-{uuid.uuid4().hex[:8]}"

    user_list = [u.strip() for u in users.split(",") if u.strip()]
    ip_list = [i.strip() for i in ips.split(",") if i.strip()]

    try:
        from secdashboards.connectors.security_lake import SecurityLakeConnector
        from secdashboards.graph.builder import GraphBuilder

        sl_sources = state.catalog.list_sources(tag="security-lake")
        sl_connector = cast(SecurityLakeConnector, state.catalog.get_connector(sl_sources[0].name))
        builder = GraphBuilder(security_lake=sl_connector)
        graph = builder.build_from_identifiers(
            users=user_list or None,
            ips=ip_list or None,
        )
    except Exception:
        from secdashboards.graph.models import SecurityGraph

        graph = SecurityGraph()

    from datetime import UTC, datetime

    created_at = datetime.now(UTC).isoformat()
    state.investigations[inv_id] = {
        "name": name or inv_id,
        "graph": graph,
        "created_at": created_at,
        "timeline_tags": {},
    }

    # Write-through to DuckDB if persistence is configured
    if state.investigation_store:
        state.investigation_store.save_investigation(
            inv_id, name or inv_id, graph, created_at=created_at
        )

    return templates.TemplateResponse(
        request,
        "pages/investigations/detail.html",
        {
            "inv_id": inv_id,
            "inv": state.investigations[inv_id],
            "graph": graph,
            "summary": graph.summary(),
        },
    )


@router.get("/{inv_id}", response_class=HTMLResponse)
def investigation_detail(
    request: Request,
    inv_id: str,
    state: AppState = Depends(get_state),
) -> HTMLResponse:
    """View an investigation."""
    templates: Jinja2Templates = request.app.state.templates
    inv = state.investigations.get(inv_id)
    if not inv:
        return templates.TemplateResponse(
            request,
            "pages/investigations/index.html",
            {"investigations": [], "error": f"Investigation {inv_id} not found"},
        )
    graph = inv["graph"]
    return templates.TemplateResponse(
        request,
        "pages/investigations/detail.html",
        {
            "inv_id": inv_id,
            "inv": inv,
            "graph": graph,
            "summary": graph.summary(),
        },
    )


@router.get("/{inv_id}/graph.html", response_class=HTMLResponse)
def investigation_graph_html(
    request: Request,
    inv_id: str,
    state: AppState = Depends(get_state),
) -> HTMLResponse:
    """Render graph visualization as standalone HTML for iframe embedding."""
    inv = state.investigations.get(inv_id)
    if not inv:
        return HTMLResponse("<p>Investigation not found.</p>", status_code=404)

    from secdashboards.graph.visualization import GraphVisualizer

    viz = GraphVisualizer(
        bgcolor="#0d1117",
        font_color="#c9d1d9",
    )
    html = viz.to_html(inv["graph"])
    return HTMLResponse(html)


@router.get("/{inv_id}/timeline.html", response_class=HTMLResponse)
def investigation_timeline_html(
    inv_id: str,
    state: AppState = Depends(get_state),
) -> HTMLResponse:
    """Render timeline visualization as standalone HTML for iframe embedding."""
    inv = state.investigations.get(inv_id)
    if not inv:
        return HTMLResponse("<p>Investigation not found.</p>", status_code=404)

    graph = inv["graph"]
    if graph.node_count() == 0:
        return HTMLResponse("<p style='color:#8b949e;padding:1rem;'>No events to display.</p>")

    try:
        from secdashboards.graph.timeline import (
            TimelineVisualizer,
            extract_timeline_from_graph,
        )

        timeline = extract_timeline_from_graph(graph)
        if not timeline.events:
            return HTMLResponse(
                "<p style='color:#8b949e;padding:1rem;'>" "No timestamped events in graph.</p>"
            )

        viz = TimelineVisualizer(height="400px")
        body = viz.to_html(timeline)
        html = (
            "<!DOCTYPE html><html><head>"
            '<meta charset="utf-8">'
            "<style>body{margin:0;background:#0d1117;}</style>"
            "</head><body>" + body + "</body></html>"
        )

        # Cache the rendered HTML if store is available
        if state.investigation_store:
            state.investigation_store.save_artifact(inv_id, "timeline_html", html)

        return HTMLResponse(html)
    except ImportError:
        return HTMLResponse(
            "<p style='color:#8b949e;padding:1rem;'>"
            "Timeline visualization requires plotly. "
            "Install with: pip install 'secdashboards[investigation]'</p>"
        )


@router.post("/{inv_id}/timeline/tag", response_class=HTMLResponse)
def tag_timeline_event(
    inv_id: str,
    state: AppState = Depends(get_state),
    event_id: str = Form(""),
    tag: str = Form(""),
    notes: str = Form(""),
) -> HTMLResponse:
    """Tag a timeline event (HTMX endpoint)."""
    inv = state.investigations.get(inv_id)
    if not inv:
        return HTMLResponse("<p>Investigation not found.</p>", status_code=404)

    if not event_id or not tag:
        return HTMLResponse("<p>Missing event_id or tag.</p>", status_code=400)

    # Update in-memory timeline_tags
    inv.setdefault("timeline_tags", {})[event_id] = tag

    # Persist tag to store
    if state.investigation_store:
        state.investigation_store.tag_event(inv_id, event_id, tag, notes)
        # Invalidate cached timeline HTML
        state.investigation_store.delete_artifacts(inv_id)

    return HTMLResponse(f'<span style="color:#58a6ff;">Tagged {event_id} as {tag}</span>')


@router.post("/{inv_id}/enrich", response_class=HTMLResponse)
def enrich_investigation(
    request: Request,
    inv_id: str,
    state: AppState = Depends(get_state),
    users: str = Form(""),
    ips: str = Form(""),
) -> HTMLResponse:
    """Enrich an investigation with additional users/IPs."""
    templates: Jinja2Templates = request.app.state.templates
    inv = state.investigations.get(inv_id)
    if not inv:
        return HTMLResponse("<p>Investigation not found.</p>", status_code=404)

    user_list = [u.strip() for u in users.split(",") if u.strip()]
    ip_list = [i.strip() for i in ips.split(",") if i.strip()]

    try:
        from secdashboards.connectors.security_lake import SecurityLakeConnector
        from secdashboards.graph.builder import GraphBuilder

        sl_sources = state.catalog.list_sources(tag="security-lake")
        sl_connector = cast(SecurityLakeConnector, state.catalog.get_connector(sl_sources[0].name))
        builder = GraphBuilder(security_lake=sl_connector)
        new_graph = builder.build_from_identifiers(
            users=user_list or None,
            ips=ip_list or None,
        )
        # Merge new graph into existing
        graph = inv["graph"]
        for node in new_graph.nodes.values():
            graph.add_node(node)
        for edge in new_graph.edges:
            graph.add_edge(edge)

        # Write-through updated graph + invalidate cached artifacts
        if state.investigation_store:
            state.investigation_store.save_graph(inv_id, graph)
            state.investigation_store.delete_artifacts(inv_id)

        summary = graph.summary()
        error = None
    except Exception as exc:
        graph = inv["graph"]
        summary = graph.summary()
        error = str(exc)

    return templates.TemplateResponse(
        request,
        "components/investigation_summary.html",
        {"inv_id": inv_id, "summary": summary, "error": error},
    )


@router.post("/{inv_id}/ai-analyze", response_class=HTMLResponse)
def ai_analyze_investigation(
    request: Request,
    inv_id: str,
    state: AppState = Depends(get_state),
    focus_area: str = Form(""),
) -> HTMLResponse:
    """Run AI analysis on an investigation graph."""
    templates: Jinja2Templates = request.app.state.templates
    inv = state.investigations.get(inv_id)
    if not inv:
        return HTMLResponse("<p>Investigation not found.</p>", status_code=404)

    try:
        from secdashboards.ai.assistant import BedrockAssistant

        assistant = BedrockAssistant(region=state.config.region)
        response = assistant.analyze_graph(
            graph=inv["graph"],
            focus_area=focus_area or None,
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


@router.post("/{inv_id}/export")
def export_investigation(
    inv_id: str,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Export investigation to JSON."""
    inv = state.investigations.get(inv_id)
    if not inv:
        return {"error": f"Investigation {inv_id} not found"}

    graph = inv["graph"]
    return {
        "id": inv_id,
        "name": inv.get("name", inv_id),
        "created_at": inv.get("created_at", ""),
        "summary": graph.summary(),
        "nodes": {k: v.model_dump() for k, v in graph.nodes.items()},
        "edges": [e.model_dump() for e in graph.edges],
    }


@router.delete("/{inv_id}", response_class=HTMLResponse)
def delete_investigation(
    request: Request,
    inv_id: str,
    state: AppState = Depends(get_state),
) -> HTMLResponse:
    """Delete an investigation."""
    state.investigations.pop(inv_id, None)
    if state.investigation_store:
        state.investigation_store.delete_investigation(inv_id)

    templates: Jinja2Templates = request.app.state.templates
    inv_list: list[dict[str, Any]] = []
    for iid, data in state.investigations.items():
        graph = data["graph"]
        inv_list.append(
            {
                "id": iid,
                "name": data.get("name", iid),
                "node_count": graph.node_count(),
                "edge_count": graph.edge_count(),
                "created_at": data.get("created_at", ""),
            }
        )
    return templates.TemplateResponse(
        request, "pages/investigations/index.html", {"investigations": inv_list}
    )
