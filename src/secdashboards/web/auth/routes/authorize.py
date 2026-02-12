"""POST /auth/authorize — Cedar authorization endpoint."""

# NOTE: No `from __future__ import annotations` — breaks FastAPI Request detection.

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from secdashboards.web.auth import cedar_engine
from secdashboards.web.auth.cognito import is_token_expired
from secdashboards.web.auth.dependencies import require_auth, require_csrf

logger = logging.getLogger(__name__)

router = APIRouter()


class ResourceModel(BaseModel):
    id: str | None = None
    type: str | None = None
    owner: str | None = None


class AuthorizeRequest(BaseModel):
    action: str
    resource: ResourceModel | None = None
    context: dict[str, Any] | None = None


@router.post("/auth/authorize")
async def authorize(
    body: AuthorizeRequest,
    request: Request,
    _csrf: None = Depends(require_csrf),
    tokens: dict = Depends(require_auth),
):
    if is_token_expired(tokens["id_token"]):
        return JSONResponse({"error": "Token expired"}, status_code=401)

    if not cedar_engine.is_initialized():
        return JSONResponse(
            {"error": "Authorization engine not available", "authorized": False},
            status_code=503,
        )

    if not body.action:
        return JSONResponse({"error": "Missing or invalid action"}, status_code=400)

    try:
        resource = body.resource.model_dump(exclude_none=True) if body.resource else {}
        result = cedar_engine.authorize(
            session=request.state.session,
            action=body.action,
            resource=resource,
            context=body.context or {},
        )

        status = 200 if result["authorized"] else 403
        return JSONResponse(result, status_code=status)

    except Exception as e:
        logger.error("Authorization error: %s", e)
        return JSONResponse(
            {"authorized": False, "error": "Authorization evaluation failed"},
            status_code=500,
        )
