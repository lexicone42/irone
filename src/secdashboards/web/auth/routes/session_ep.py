"""POST /auth/session — Store tokens from direct login (passkey/password)."""

# NOTE: No `from __future__ import annotations` — breaks FastAPI Request detection.

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from secdashboards.web.auth.cognito import verify_id_token
from secdashboards.web.auth.dependencies import require_csrf

logger = logging.getLogger(__name__)

router = APIRouter()


class SessionRequest(BaseModel):
    access_token: str
    id_token: str
    refresh_token: str | None = None
    auth_method: str = "direct"


@router.post("/auth/session")
async def create_session(
    body: SessionRequest,
    request: Request,
    _csrf: None = Depends(require_csrf),
):
    if not body.access_token or not body.id_token:
        return JSONResponse({"error": "Missing access_token or id_token"}, status_code=400)

    # Verify id_token signature via JWKS before storing
    try:
        await verify_id_token(body.id_token)
    except Exception as e:
        logger.error("Token verification failed: %s", e)
        return JSONResponse({"error": "Token verification failed"}, status_code=403)

    request.state.session["tokens"] = {
        "access_token": body.access_token,
        "id_token": body.id_token,
        "refresh_token": body.refresh_token,
        "auth_method": body.auth_method,
    }

    return {"success": True}
