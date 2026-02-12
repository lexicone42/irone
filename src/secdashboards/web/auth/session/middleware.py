"""ASGI server-side session middleware.

Starlette's built-in SessionMiddleware stores all data in signed cookies,
which can't hold JWTs (too large). This middleware stores a signed session ID
in a cookie and delegates data storage to a SessionBackend.
"""

from __future__ import annotations

import secrets
from typing import Any

from itsdangerous import BadSignature, URLSafeTimedSerializer
from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .backend import InMemoryBackend, SessionBackend

COOKIE_NAME = "secdash_session"
MAX_AGE = 30 * 24 * 3600  # 30 days


class SessionMiddleware:
    """ASGI middleware for server-side sessions.

    Reads a signed session ID from a cookie, loads session data from the
    backend, and attaches it to request.state.session. On response, saves
    any modifications back.
    """

    def __init__(
        self,
        app: ASGIApp,
        secret: str,
        backend: SessionBackend | None = None,
        cookie_name: str = COOKIE_NAME,
        max_age: int = MAX_AGE,
        https_only: bool = False,
        same_site: str = "lax",
    ) -> None:
        self.app = app
        self.signer = URLSafeTimedSerializer(secret)
        self.backend = backend or InMemoryBackend(max_age=max_age)
        self.cookie_name = cookie_name
        self.max_age = max_age
        self.https_only = https_only
        self.same_site = same_site

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        conn = HTTPConnection(scope)
        session_id = self._load_session_id(conn)
        initial_data: dict[str, Any] = {}
        is_new = True

        if session_id:
            loaded = await self.backend.load(session_id)
            if loaded is not None:
                initial_data = loaded
                is_new = False
            else:
                session_id = None  # Expired or missing — will create new

        if session_id is None:
            session_id = secrets.token_urlsafe(32)

        # Attach session to scope so request.state.session works
        scope["state"] = scope.get("state", {})
        scope["state"]["session"] = dict(initial_data)
        scope["state"]["session_id"] = session_id
        scope["state"]["session_destroyed"] = False

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                session_data: dict[str, Any] = scope["state"]["session"]
                destroyed: bool = scope["state"].get("session_destroyed", False)

                headers = MutableHeaders(scope=message)

                if destroyed:
                    await self.backend.delete(session_id)
                    headers.append(
                        "set-cookie",
                        self._make_cookie(session_id, delete=True),
                    )
                elif session_data != initial_data or is_new:
                    await self.backend.save(session_id, session_data)
                    headers.append(
                        "set-cookie",
                        self._make_cookie(session_id),
                    )

            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _load_session_id(self, conn: HTTPConnection) -> str | None:
        raw = conn.cookies.get(self.cookie_name)
        if not raw:
            return None
        try:
            return self.signer.loads(raw, max_age=self.max_age)
        except BadSignature:
            return None

    def _make_cookie(self, session_id: str, *, delete: bool = False) -> str:
        if delete:
            value = ""
            max_age = 0
        else:
            value = self.signer.dumps(session_id)
            max_age = self.max_age

        parts = [
            f"{self.cookie_name}={value}",
            f"Max-Age={max_age}",
            "Path=/",
            "HttpOnly",
            f"SameSite={self.same_site}",
        ]
        if self.https_only:
            parts.append("Secure")
        return "; ".join(parts)
