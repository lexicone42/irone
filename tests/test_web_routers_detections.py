"""Tests for detection routes — rule CRUD, testing, and query explorer."""

from unittest.mock import MagicMock, patch

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
    """App with a pre-registered detection rule."""
    state = app.state.secdash
    metadata = DetectionMetadata(
        id="test-rule-1",
        name="Test Rule",
        description="A test detection rule",
        severity=Severity.HIGH,
        tags=["test"],
    )
    rule = SQLDetectionRule(
        metadata=metadata,
        query_template="SELECT 1 AS event WHERE 1=1",
        threshold=1,
    )
    state.runner.register_rule(rule)
    return app


@pytest.fixture
def client_with_rule(app_with_rule):
    return TestClient(app_with_rule)


class TestDetectionRoutes:
    def test_index_returns_200(self, client) -> None:
        resp = client.get("/detections/")
        assert resp.status_code == 200
        assert "Detection Rules" in resp.text

    def test_index_shows_rule_count(self, client_with_rule) -> None:
        resp = client_with_rule.get("/detections/")
        assert resp.status_code == 200
        assert "Test Rule" in resp.text

    def test_new_rule_form(self, client) -> None:
        resp = client.get("/detections/new")
        assert resp.status_code == 200
        assert "New Detection Rule" in resp.text
        assert "severity" in resp.text.lower()

    def test_create_rule(self, client) -> None:
        resp = client.post(
            "/detections/",
            data={
                "name": "My New Rule",
                "description": "Detects bad things",
                "severity": "high",
                "query_template": "SELECT * FROM events",
                "threshold": "5",
                "tags": "iam, auth",
            },
        )
        assert resp.status_code == 200
        assert "My New Rule" in resp.text

    def test_create_rule_appears_in_list(self, client) -> None:
        client.post(
            "/detections/",
            data={
                "name": "Listed Rule",
                "severity": "low",
                "query_template": "SELECT 1",
                "threshold": "1",
                "tags": "",
            },
        )
        resp = client.get("/detections/")
        assert "Listed Rule" in resp.text

    def test_test_rule_success(self, client_with_rule) -> None:
        resp = client_with_rule.post("/detections/test-rule-1/test")
        assert resp.status_code == 200
        # The rule SELECT 1 should succeed and return a result
        assert "TRIGGERED" in resp.text or "CLEAN" in resp.text

    def test_test_rule_not_found(self, client) -> None:
        resp = client.post("/detections/nonexistent/test")
        assert resp.status_code == 200
        # Runner returns a DetectionResult with triggered=False for unknown rules
        assert "CLEAN" in resp.text


class TestQueryExplorer:
    def test_explorer_page(self, client) -> None:
        resp = client.get("/detections/query-explorer")
        assert resp.status_code == 200
        assert "Query Explorer" in resp.text

    def test_run_query_success(self, client) -> None:
        resp = client.post(
            "/detections/query-explorer/run",
            data={"sql": "SELECT 42 AS answer"},
        )
        assert resp.status_code == 200
        assert "42" in resp.text
        assert "answer" in resp.text

    def test_run_query_error(self, client) -> None:
        resp = client.post(
            "/detections/query-explorer/run",
            data={"sql": "SELECT * FROM nonexistent_table_xyz"},
        )
        assert resp.status_code == 200
        assert "alert-error" in resp.text

    def test_run_query_multiple_rows(self, client) -> None:
        resp = client.post(
            "/detections/query-explorer/run",
            data={"sql": "SELECT unnest([1,2,3]) AS num"},
        )
        assert resp.status_code == 200
        assert "3 rows" in resp.text


class TestAIGenerate:
    @patch("secdashboards.ai.assistant.BedrockAssistant")
    def test_ai_generate_success(self, mock_assistant_cls, client) -> None:
        mock_assistant = MagicMock()
        mock_response = MagicMock()
        mock_response.content = "name: AI Generated Rule\nquery: SELECT * FROM events"
        mock_response.cost_usd = 0.005
        mock_assistant.generate_detection_rule.return_value = mock_response
        mock_assistant_cls.return_value = mock_assistant

        resp = client.post(
            "/detections/ai-generate",
            data={"description": "Detect brute force logins", "context": ""},
        )
        assert resp.status_code == 200
        assert "AI Generated Rule" in resp.text

    @patch(
        "secdashboards.ai.assistant.BedrockAssistant",
        side_effect=Exception("No Bedrock access"),
    )
    def test_ai_generate_error(self, mock_cls, client) -> None:
        resp = client.post(
            "/detections/ai-generate",
            data={"description": "test", "context": ""},
        )
        assert resp.status_code == 200
        assert "No Bedrock access" in resp.text
