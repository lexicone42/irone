"""Global auth enforcement middleware.

Requires a valid session on all routes except exempt paths.
HTML requests without a session get redirected to /auth/login;
API requests get a 401 JSON response.
"""

from __future__ import annotations

import json

from starlette.types import ASGIApp, Receive, Scope, Send

# Paths that do not require authentication
EXEMPT_PREFIXES = (
    "/auth/",
    "/api/health",
    "/static/",
    "/health",
)


class AuthEnforcementMiddleware:
    """ASGI middleware that enforces authentication on all non-exempt routes."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        # Check exempt paths
        if any(path.startswith(prefix) for prefix in EXEMPT_PREFIXES):
            await self.app(scope, receive, send)
            return

        # Check for valid session with tokens
        state = scope.get("state", {})
        session = state.get("session", {})
        tokens = session.get("tokens")

        if tokens and tokens.get("id_token"):
            # Authenticated — proceed
            await self.app(scope, receive, send)
            return

        # Not authenticated — check if this is an API or HTML request
        headers = dict(scope.get("headers", []))
        accept = headers.get(b"accept", b"").decode("utf-8", errors="ignore")

        if "text/html" in accept:
            # HTML request → redirect to login
            await self._redirect_to_login(scope, receive, send)
        else:
            # API request → 401 JSON
            await self._send_401(scope, receive, send)

    async def _redirect_to_login(self, scope: Scope, receive: Receive, send: Send) -> None:
        body = b""
        await send(
            {
                "type": "http.response.start",
                "status": 302,
                "headers": [
                    [b"location", b"/auth/login"],
                    [b"content-length", b"0"],
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body,
            }
        )

    async def _send_401(self, scope: Scope, receive: Receive, send: Send) -> None:
        body = json.dumps({"error": "Not authenticated"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(body)).encode()],
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body,
            }
        )
