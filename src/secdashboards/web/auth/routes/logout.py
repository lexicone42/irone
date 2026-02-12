"""POST /auth/logout — Destroy session."""

# NOTE: No `from __future__ import annotations` — breaks FastAPI Request detection.

from fastapi import APIRouter, Depends, Request

from secdashboards.web.auth.dependencies import destroy_session, require_csrf

router = APIRouter()


@router.post("/auth/logout")
async def logout(
    request: Request,
    _csrf: None = Depends(require_csrf),
):
    destroy_session(request)
    return {"success": True}
