"""Session storage backends."""

from __future__ import annotations

import time
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SessionBackend(Protocol):
    """Protocol for server-side session storage."""

    async def load(self, session_id: str) -> dict[str, Any] | None:
        """Load session data by ID. Returns None if not found or expired."""
        ...

    async def save(self, session_id: str, data: dict[str, Any]) -> None:
        """Save session data."""
        ...

    async def delete(self, session_id: str) -> None:
        """Delete a session."""
        ...


class InMemoryBackend:
    """In-memory session backend for development/testing.

    Not suitable for production — sessions are lost on restart and not
    shared across processes.
    """

    def __init__(self, max_age: int = 30 * 24 * 3600) -> None:
        self._store: dict[str, tuple[dict[str, Any], float]] = {}
        self._max_age = max_age

    async def load(self, session_id: str) -> dict[str, Any] | None:
        entry = self._store.get(session_id)
        if entry is None:
            return None
        data, created = entry
        if time.time() - created > self._max_age:
            del self._store[session_id]
            return None
        return data

    async def save(self, session_id: str, data: dict[str, Any]) -> None:
        existing = self._store.get(session_id)
        created = existing[1] if existing else time.time()
        self._store[session_id] = (data, created)

    async def delete(self, session_id: str) -> None:
        self._store.pop(session_id, None)
