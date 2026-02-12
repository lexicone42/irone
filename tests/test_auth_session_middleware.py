"""Tests for the ASGI session middleware."""

import time

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from secdashboards.web.auth.session import InMemoryBackend, SessionMiddleware


@pytest.fixture
def simple_app():
    """Minimal app for testing session middleware in isolation."""
    app = FastAPI()
    backend = InMemoryBackend()

    @app.get("/set")
    async def set_value(request: Request):
        request.state.session["key"] = "value"
        return {"ok": True}

    @app.get("/get")
    async def get_value(request: Request):
        return {"key": request.state.session.get("key")}

    @app.get("/destroy")
    async def destroy(request: Request):
        request.state.session_destroyed = True
        request.state.session.clear()
        return {"ok": True}

    app.add_middleware(SessionMiddleware, secret="test-secret", backend=backend)
    return app


@pytest.fixture
def session_client(simple_app):
    return TestClient(simple_app, cookies={})


def test_new_session_sets_cookie(session_client):
    resp = session_client.get("/set")
    assert resp.status_code == 200
    assert "secdash_session" in resp.cookies


def test_session_persists_across_requests(session_client):
    session_client.get("/set")
    resp = session_client.get("/get")
    assert resp.json()["key"] == "value"


def test_session_empty_by_default(session_client):
    resp = session_client.get("/get")
    assert resp.json()["key"] is None


def test_session_destroy_clears_data(session_client):
    session_client.get("/set")
    session_client.get("/destroy")
    resp = session_client.get("/get")
    assert resp.json()["key"] is None


def test_session_cookie_is_httponly(session_client):
    resp = session_client.get("/set")
    cookie_header = resp.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie_header


def test_session_cookie_samesite_lax(session_client):
    resp = session_client.get("/set")
    cookie_header = resp.headers.get("set-cookie", "")
    assert "SameSite=lax" in cookie_header


def test_invalid_cookie_creates_new_session(session_client):
    session_client.cookies.set("secdash_session", "garbage-value")
    resp = session_client.get("/get")
    assert resp.status_code == 200
    assert resp.json()["key"] is None


@pytest.mark.asyncio
async def test_inmemory_backend_expiry():
    backend = InMemoryBackend(max_age=1)
    await backend.save("test-id", {"key": "value"})

    data = await backend.load("test-id")
    assert data == {"key": "value"}

    # Simulate expiry
    backend._store["test-id"] = ({"key": "value"}, time.time() - 2)

    data = await backend.load("test-id")
    assert data is None


@pytest.mark.asyncio
async def test_inmemory_backend_delete():
    backend = InMemoryBackend()
    await backend.save("test-id", {"key": "value"})
    await backend.delete("test-id")
    data = await backend.load("test-id")
    assert data is None


@pytest.mark.asyncio
async def test_inmemory_backend_delete_nonexistent():
    backend = InMemoryBackend()
    await backend.delete("nonexistent")
