"""GET /auth/callback — OAuth callback from Cognito Hosted UI."""

# NOTE: No `from __future__ import annotations` — breaks FastAPI Request detection.

import logging

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from secdashboards.web.auth.cognito import exchange_code_for_tokens
from secdashboards.web.config import WebConfig

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/auth/callback")
async def oauth_callback(request: Request):
    code = request.query_params.get("code")
    error = request.query_params.get("error")
    error_description = request.query_params.get("error_description")

    if error:
        logger.error("OAuth error: %s %s", error, error_description)
        return RedirectResponse(f"/?error={error_description or error}")

    if not code:
        return RedirectResponse("/?error=Missing+authorization+code")

    try:
        config: WebConfig = request.app.state.secdash.config
        redirect_uri = config.cognito_redirect_uri or str(request.url_for("oauth_callback"))
        token_response = await exchange_code_for_tokens(code, redirect_uri)

        request.state.session["tokens"] = {
            "access_token": token_response["access_token"],
            "id_token": token_response["id_token"],
            "refresh_token": token_response.get("refresh_token"),
            "auth_method": "oauth",
        }

        return RedirectResponse("/")

    except Exception as e:
        logger.error("Token exchange error: %s", e)
        return RedirectResponse("/?error=Authentication+failed")
