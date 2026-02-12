"""POST /auth/refresh — Refresh tokens via Cognito."""

# NOTE: No `from __future__ import annotations` — breaks FastAPI Request detection.

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from secdashboards.web.auth.cognito import cognito_request, get_client_id
from secdashboards.web.auth.dependencies import destroy_session, require_auth, require_csrf

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/auth/refresh")
async def refresh_tokens(
    request: Request,
    _csrf: None = Depends(require_csrf),
    tokens: dict = Depends(require_auth),
):
    if not tokens.get("refresh_token"):
        return JSONResponse({"error": "No refresh token"}, status_code=401)

    try:
        result = await cognito_request(
            "InitiateAuth",
            {
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "ClientId": get_client_id(),
                "AuthParameters": {
                    "REFRESH_TOKEN": tokens["refresh_token"],
                },
            },
        )
    except Exception as e:
        logger.error("Token refresh error: %s", e)
        destroy_session(request)
        return JSONResponse({"error": "Refresh failed", "message": str(e)}, status_code=401)

    auth_result = result.get("AuthenticationResult")
    if not auth_result:
        return JSONResponse({"error": "Refresh failed"}, status_code=500)

    # Update session with new tokens
    request.state.session["tokens"] = {
        "access_token": auth_result["AccessToken"],
        "id_token": auth_result["IdToken"],
        "refresh_token": auth_result.get("RefreshToken", tokens["refresh_token"]),
        "auth_method": tokens.get("auth_method"),
    }

    return {
        "access_token": auth_result["AccessToken"],
        "id_token": auth_result["IdToken"],
        "auth_method": tokens.get("auth_method", "handler"),
    }
