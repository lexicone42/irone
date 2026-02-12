"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from secdashboards.web.config import WebConfig
from secdashboards.web.routers import (
    api,
    dashboard,
    deploy,
    detections,
    investigations,
    monitoring,
    security_lake,
)
from secdashboards.web.state import create_app_state

_WEB_DIR = Path(__file__).parent


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown lifecycle for the FastAPI app."""
    yield
    # Shutdown: close DuckDB connection
    state = getattr(app.state, "secdash", None)
    if state is not None:
        state.duckdb.close()


def create_app(config: WebConfig | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        config: Web configuration. If None, reads from environment variables.

    Returns:
        A fully configured FastAPI application with state attached.
    """
    config = config or WebConfig()

    app = FastAPI(
        title="secdashboards",
        description="Security Data Lake Analytics",
        version="0.1.0",
        lifespan=_lifespan,
    )

    # Static files and templates
    app.mount("/static", StaticFiles(directory=_WEB_DIR / "static"), name="static")
    app.state.templates = Jinja2Templates(directory=_WEB_DIR / "templates")

    # Build and attach application state
    app.state.secdash = create_app_state(config)

    # Include routers
    app.include_router(dashboard.router)
    app.include_router(monitoring.router)
    app.include_router(security_lake.router)
    app.include_router(detections.router)
    app.include_router(investigations.router)
    app.include_router(deploy.router)
    app.include_router(api.router)

    # --- Health endpoint ---
    @app.get("/api/health")
    def health_check() -> JSONResponse:
        return JSONResponse({"status": "ok", "version": "0.1.0"})

    return app
