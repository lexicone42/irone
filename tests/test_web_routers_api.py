"""Tests for API routes — JSON endpoints for sources, rules, queries, operations."""

import pytest
from fastapi.testclient import TestClient

from secdashboards.detections.rule import DetectionMetadata, Severity, SQLDetectionRule
from secdashboards.web.app import create_app
from secdashboards.web.config import WebConfig


@pytest.fixture
def app():
    config = WebConfig(duckdb_path=":memory:")
    return create_app(config)


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def app_with_rule(app):
    state = app.state.secdash
    metadata = DetectionMetadata(
        id="api-rule-1",
        name="API Test Rule",
        severity=Severity.MEDIUM,
        tags=["api-test"],
    )
    rule = SQLDetectionRule(
        metadata=metadata,
        query_template="SELECT 1 AS alert",
        threshold=1,
    )
    state.runner.register_rule(rule)
    return app


@pytest.fixture
def client_with_rule(app_with_rule):
    return TestClient(app_with_rule)


class TestSourcesAPI:
    def test_list_sources(self, client) -> None:
        resp = client.get("/api/sources")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        # Should have at least the duckdb-local source
        assert any(s["name"] == "duckdb-local" for s in data)

    def test_list_sources_with_tag(self, client) -> None:
        resp = client.get("/api/sources?tag=duckdb")
        assert resp.status_code == 200
        data = resp.json()
        assert all("duckdb" in s["tags"] for s in data)

    def test_list_sources_unknown_tag(self, client) -> None:
        resp = client.get("/api/sources?tag=nonexistent")
        assert resp.status_code == 200
        assert resp.json() == []


class TestRulesAPI:
    def test_list_rules_empty(self, client) -> None:
        resp = client.get("/api/rules")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_rules_with_rule(self, client_with_rule) -> None:
        resp = client_with_rule.get("/api/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["name"] == "API Test Rule"

    def test_list_rules_all(self, client_with_rule) -> None:
        resp = client_with_rule.get("/api/rules?enabled_only=false")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_get_rule(self, client_with_rule) -> None:
        resp = client_with_rule.get("/api/rules/api-rule-1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "API Test Rule"
        assert data["id"] == "api-rule-1"

    def test_get_rule_not_found(self, client) -> None:
        resp = client.get("/api/rules/nonexistent")
        assert resp.status_code == 200
        data = resp.json()
        assert "error" in data


class TestQueryAPI:
    def test_execute_query(self, client) -> None:
        resp = client.post("/api/query", json={"sql": "SELECT 42 AS answer"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["row_count"] == 1
        assert data["columns"] == ["answer"]
        assert data["rows"][0]["answer"] == 42

    def test_execute_query_error(self, client) -> None:
        resp = client.post("/api/query", json={"sql": "INVALID SQL !!!"})
        assert resp.status_code == 200
        data = resp.json()
        assert "error" in data
        assert data["row_count"] == 0


class TestOperationsAPI:
    def test_operation_not_found(self, client) -> None:
        resp = client.get("/api/operations/nonexistent")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "unknown"

    def test_operation_exists(self, app) -> None:
        app.state.secdash.operations["op-1"] = {
            "type": "build",
            "status": "complete",
            "rule_id": "test",
        }
        client = TestClient(app)
        resp = client.get("/api/operations/op-1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "complete"


class TestHealthEndpoint:
    def test_health_still_works(self, client) -> None:
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
