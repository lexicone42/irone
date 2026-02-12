"""GET /auth/token — Return tokens from session."""

# NOTE: No `from __future__ import annotations` — breaks FastAPI Request detection.

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from secdashboards.web.auth.cognito import is_token_expired
from secdashboards.web.auth.dependencies import require_auth

router = APIRouter()


@router.get("/auth/token")
async def get_token(request: Request, tokens: dict = Depends(require_auth)):
    if is_token_expired(tokens["id_token"]):
        return JSONResponse({"error": "Token expired"}, status_code=401)

    return {
        "access_token": tokens["access_token"],
        "id_token": tokens["id_token"],
        "auth_method": tokens.get("auth_method", "handler"),
    }
