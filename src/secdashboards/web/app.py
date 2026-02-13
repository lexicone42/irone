"""FastAPI application factory."""

from __future__ import annotations

import logging
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

logger = logging.getLogger(__name__)

_WEB_DIR = Path(__file__).parent


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown lifecycle for the FastAPI app."""
    config: WebConfig = app.state.secdash.config

    # Initialize Cedar authorization engine if auth is enabled
    if config.auth_enabled and config.cedar_enabled:
        from secdashboards.web.auth import cedar_engine

        cedar_dir = _WEB_DIR / "cedar"
        try:
            cedar_engine.init_cedar_engine(
                schema_path=str(cedar_dir / "schema.cedarschema.json"),
                policy_dir=str(cedar_dir / "policies"),
            )
            logger.info("Cedar: initialized (policies validated)")
        except Exception as e:
            logger.error("Cedar: FAILED — %s", e)
            logger.error("Authorization endpoint will return 503")

    # Load persisted investigations into memory
    state = app.state.secdash
    if state.investigation_store:
        for inv_meta in state.investigation_store.list_investigations():
            inv_id = inv_meta["id"]
            if inv_id not in state.investigations:
                loaded = state.investigation_store.load_investigation(inv_id)
                if loaded:
                    state.investigations[inv_id] = loaded
        logger.info("Loaded %d persisted investigations", len(state.investigations))

    yield

    # Shutdown: close connections
    state = getattr(app.state, "secdash", None)
    if state is not None:
        if state.investigation_store:
            state.investigation_store.close()
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

    # --- Auth middleware (conditional) ---
    if config.auth_enabled:
        from secdashboards.web.auth.cognito import configure as configure_cognito
        from secdashboards.web.auth.middleware import AuthEnforcementMiddleware
        from secdashboards.web.auth.routes import router as auth_router
        from secdashboards.web.auth.session import SessionMiddleware

        # Configure Cognito module
        configure_cognito(
            client_id=config.cognito_client_id,
            client_secret=config.cognito_client_secret,
            user_pool_id=config.cognito_user_pool_id,
            domain=config.cognito_domain,
            region=config.cognito_region,
        )

        # Select session backend
        backend = _build_session_backend(config)

        # Middleware order: add auth enforcement first (inner), session second (outer).
        # Starlette processes add_middleware in reverse — session runs first on request.
        app.add_middleware(AuthEnforcementMiddleware)  # type: ignore[arg-type]
        app.add_middleware(
            SessionMiddleware,  # type: ignore[arg-type]
            secret=config.session_secret_key,
            backend=backend,
            max_age=config.session_max_age,
            https_only=config.is_lambda,  # HTTPS in production (Lambda behind ALB/APIGW)
        )

        # Register auth routes
        app.include_router(auth_router)

    # Include application routers
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


def _build_session_backend(config: WebConfig):
    """Build the appropriate session backend based on config."""
    if config.session_backend == "dynamodb":
        from secdashboards.web.auth.session.dynamodb import DynamoDBSessionBackend

        return DynamoDBSessionBackend(
            table_name="secdash_sessions",
            max_age=config.session_max_age,
            region_name=config.region,
        )
    else:
        from secdashboards.web.auth.session import InMemoryBackend

        return InMemoryBackend(max_age=config.session_max_age)
