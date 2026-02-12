"""Auth route aggregation."""

from fastapi import APIRouter

from . import authorize, callback, login, logout, me, refresh, session_ep, token

router = APIRouter(tags=["auth"])
router.include_router(token.router)
router.include_router(session_ep.router)
router.include_router(refresh.router)
router.include_router(logout.router)
router.include_router(callback.router)
router.include_router(authorize.router)
router.include_router(me.router)
router.include_router(login.router)
