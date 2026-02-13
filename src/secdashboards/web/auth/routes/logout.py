"""GET /auth/logout — Destroy session and sign out of Cognito."""

# NOTE: No `from __future__ import annotations` — breaks FastAPI Request detection.

from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from secdashboards.web.auth.dependencies import destroy_session
from secdashboards.web.config import WebConfig

router = APIRouter()


@router.get("/auth/logout")
async def logout(request: Request):
    destroy_session(request)

    config: WebConfig = request.app.state.secdash.config

    if config.auth_enabled and config.cognito_domain and config.cognito_client_id:
        # Redirect to Cognito's logout endpoint to kill the hosted UI session too
        logout_uri = str(request.base_url).rstrip("/") + "/auth/login"
        params = urlencode(
            {
                "client_id": config.cognito_client_id,
                "logout_uri": logout_uri,
            }
        )
        return RedirectResponse(f"https://{config.cognito_domain}/logout?{params}", status_code=302)

    return RedirectResponse("/auth/login", status_code=302)
