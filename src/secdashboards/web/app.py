"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from secdashboards.web.config import WebConfig
from secdashboards.web.state import create_app_state


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown lifecycle for the FastAPI app."""
    # Startup: state is already attached by create_app
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

    # Build and attach application state
    app.state.secdash = create_app_state(config)

    # --- Health endpoint ---
    @app.get("/api/health")
    def health_check() -> JSONResponse:
        return JSONResponse({"status": "ok", "version": "0.1.0"})

    return app
