"""Tests for investigation routes — graph investigations, enrichment, analysis."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from secdashboards.graph.models import SecurityGraph
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
def app_with_investigation(app):
    """App with a pre-created investigation."""
    from datetime import UTC, datetime

    graph = SecurityGraph()
    app.state.secdash.investigations["inv-test1"] = {
        "name": "Test Investigation",
        "graph": graph,
        "created_at": datetime(2024, 6, 1, tzinfo=UTC).isoformat(),
        "timeline_tags": {},
    }
    return app


@pytest.fixture
def client_with_investigation(app_with_investigation):
    return TestClient(app_with_investigation)


class TestInvestigationRoutes:
    def test_index_empty(self, client) -> None:
        resp = client.get("/investigations/")
        assert resp.status_code == 200
        assert "Investigations" in resp.text
        assert "0" in resp.text  # 0 investigations

    def test_index_with_investigation(self, client_with_investigation) -> None:
        resp = client_with_investigation.get("/investigations/")
        assert resp.status_code == 200
        assert "Test Investigation" in resp.text

    def test_new_form(self, client) -> None:
        resp = client.get("/investigations/new")
        assert resp.status_code == 200
        assert "New Investigation" in resp.text

    def test_create_investigation(self, client) -> None:
        """Creating an investigation without Security Lake still works (empty graph)."""
        resp = client.post(
            "/investigations/",
            data={"name": "My Investigation", "users": "admin@test.com", "ips": "10.0.0.1"},
        )
        assert resp.status_code == 200
        # Should show the detail page (even with empty graph from exception fallback)
        assert "My Investigation" in resp.text

    def test_create_stores_investigation(self, app) -> None:
        client = TestClient(app)
        client.post(
            "/investigations/",
            data={"name": "Stored Inv", "users": "", "ips": ""},
        )
        # Should have exactly one investigation
        assert len(app.state.secdash.investigations) == 1

    def test_detail_page(self, client_with_investigation) -> None:
        resp = client_with_investigation.get("/investigations/inv-test1")
        assert resp.status_code == 200
        assert "Test Investigation" in resp.text
        assert "inv-test1" in resp.text

    def test_detail_not_found(self, client) -> None:
        resp = client.get("/investigations/nonexistent")
        assert resp.status_code == 200
        assert "not found" in resp.text

    def test_graph_html_not_found(self, client) -> None:
        resp = client.get("/investigations/nonexistent/graph.html")
        assert resp.status_code == 404

    @patch("secdashboards.graph.visualization.GraphVisualizer")
    def test_graph_html_renders(self, mock_viz_cls, client_with_investigation) -> None:
        mock_viz = MagicMock()
        mock_viz.to_html.return_value = "<html><body>Graph</body></html>"
        mock_viz_cls.return_value = mock_viz

        resp = client_with_investigation.get("/investigations/inv-test1/graph.html")
        assert resp.status_code == 200
        assert "Graph" in resp.text


class TestInvestigationEnrich:
    def test_enrich_not_found(self, client) -> None:
        resp = client.post(
            "/investigations/nonexistent/enrich",
            data={"users": "", "ips": ""},
        )
        assert resp.status_code == 404

    def test_enrich_fallback_on_error(self, client_with_investigation) -> None:
        """Enrichment without Security Lake source still returns a summary."""
        resp = client_with_investigation.post(
            "/investigations/inv-test1/enrich",
            data={"users": "admin", "ips": ""},
        )
        assert resp.status_code == 200
        # Should show enrichment error or partial message
        assert "Nodes:" in resp.text


class TestInvestigationAI:
    @patch("secdashboards.ai.assistant.BedrockAssistant")
    def test_ai_analyze_success(self, mock_cls, client_with_investigation) -> None:
        mock_assistant = MagicMock()
        mock_response = MagicMock()
        mock_response.content = "Analysis: No suspicious activity detected."
        mock_response.cost_usd = 0.01
        mock_assistant.analyze_graph.return_value = mock_response
        mock_cls.return_value = mock_assistant

        resp = client_with_investigation.post(
            "/investigations/inv-test1/ai-analyze",
            data={"focus_area": "lateral movement"},
        )
        assert resp.status_code == 200
        assert "No suspicious activity" in resp.text

    @patch(
        "secdashboards.ai.assistant.BedrockAssistant",
        side_effect=Exception("Bedrock unavailable"),
    )
    def test_ai_analyze_error(self, mock_cls, client_with_investigation) -> None:
        resp = client_with_investigation.post(
            "/investigations/inv-test1/ai-analyze",
            data={"focus_area": ""},
        )
        assert resp.status_code == 200
        assert "Bedrock unavailable" in resp.text

    def test_ai_analyze_not_found(self, client) -> None:
        resp = client.post(
            "/investigations/nonexistent/ai-analyze",
            data={"focus_area": ""},
        )
        assert resp.status_code == 404


class TestInvestigationExport:
    def test_export_json(self, client_with_investigation) -> None:
        resp = client_with_investigation.post("/investigations/inv-test1/export")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "inv-test1"
        assert data["name"] == "Test Investigation"
        assert "summary" in data

    def test_export_not_found(self, client) -> None:
        resp = client.post("/investigations/nonexistent/export")
        assert resp.status_code == 200
        data = resp.json()
        assert "error" in data
