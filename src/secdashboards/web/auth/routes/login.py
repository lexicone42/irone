"""GET /auth/login — Redirect to Cognito Hosted UI for authentication."""

# NOTE: No `from __future__ import annotations` — breaks FastAPI Request detection.

from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from secdashboards.web.config import WebConfig

router = APIRouter()


@router.get("/auth/login")
async def login(request: Request):
    """Redirect to Cognito Hosted UI."""
    config: WebConfig = request.app.state.secdash.config

    redirect_uri = config.cognito_redirect_uri or str(request.url_for("oauth_callback"))

    params = urlencode(
        {
            "client_id": config.cognito_client_id,
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": redirect_uri,
        }
    )

    authorize_url = f"https://{config.cognito_domain}/oauth2/authorize?{params}"
    return RedirectResponse(authorize_url)
