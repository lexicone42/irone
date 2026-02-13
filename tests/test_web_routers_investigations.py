"""Tests for investigation routes — graph investigations, enrichment, analysis."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from secdashboards.graph.models import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    SecurityGraph,
)
from secdashboards.graph.persistence import InvestigationStore
from secdashboards.web.app import create_app
from secdashboards.web.config import WebConfig


@pytest.fixture
def app():
    config = WebConfig(duckdb_path=":memory:")
    return create_app(config)


@pytest.fixture
def app_with_store():
    """App with :memory: investigation store for persistence tests."""
    config = WebConfig(duckdb_path=":memory:", investigations_db_path=":memory:")
    return create_app(config)


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def app_with_investigation(app):
    """App with a pre-created investigation."""
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


class TestInvestigationPersistence:
    """Tests for write-through persistence when investigation_store is configured."""

    def test_create_persists_to_store(self, app_with_store) -> None:
        client = TestClient(app_with_store)
        client.post(
            "/investigations/",
            data={"name": "Persisted Inv", "users": "", "ips": ""},
        )
        store = app_with_store.state.secdash.investigation_store
        inv_list = store.list_investigations()
        assert len(inv_list) == 1
        assert inv_list[0]["name"] == "Persisted Inv"

    def test_create_without_store_still_works(self, app) -> None:
        """No store configured — create still succeeds (in-memory only)."""
        client = TestClient(app)
        resp = client.post(
            "/investigations/",
            data={"name": "Memory Only", "users": "", "ips": ""},
        )
        assert resp.status_code == 200
        assert app.state.secdash.investigation_store is None

    def test_delete_removes_from_store(self, app_with_store) -> None:
        client = TestClient(app_with_store)
        client.post(
            "/investigations/",
            data={"name": "To Delete", "users": "", "ips": ""},
        )
        store = app_with_store.state.secdash.investigation_store
        inv_id = store.list_investigations()[0]["id"]

        resp = client.delete(f"/investigations/{inv_id}")
        assert resp.status_code == 200
        assert store.list_investigations() == []
        assert inv_id not in app_with_store.state.secdash.investigations

    def test_delete_nonexistent_returns_index(self, app_with_store) -> None:
        client = TestClient(app_with_store)
        resp = client.delete("/investigations/nonexistent")
        assert resp.status_code == 200

    def test_store_field_none_when_no_path(self, app) -> None:
        assert app.state.secdash.investigation_store is None

    def test_store_field_set_when_path_configured(self, app_with_store) -> None:
        store = app_with_store.state.secdash.investigation_store
        assert store is not None
        assert isinstance(store, InvestigationStore)


@pytest.fixture
def app_with_graph():
    """App with an investigation containing timestamped graph nodes."""
    config = WebConfig(duckdb_path=":memory:")
    app = create_app(config)
    graph = SecurityGraph()
    graph.add_node(
        GraphNode(
            id="principal:admin",
            node_type=NodeType.PRINCIPAL,
            label="admin@test.com",
            first_seen=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
            last_seen=datetime(2024, 6, 1, 13, 0, tzinfo=UTC),
            event_count=5,
        )
    )
    graph.add_node(
        GraphNode(
            id="ip:10.0.0.1",
            node_type=NodeType.IP_ADDRESS,
            label="10.0.0.1",
            first_seen=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
            event_count=3,
        )
    )
    graph.add_edge(
        GraphEdge(
            id=GraphEdge.create_id(EdgeType.AUTHENTICATED_FROM, "principal:admin", "ip:10.0.0.1"),
            edge_type=EdgeType.AUTHENTICATED_FROM,
            source_id="principal:admin",
            target_id="ip:10.0.0.1",
            first_seen=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
        )
    )
    app.state.secdash.investigations["inv-graph"] = {
        "name": "Graph Investigation",
        "graph": graph,
        "created_at": datetime(2024, 6, 1, tzinfo=UTC).isoformat(),
        "timeline_tags": {},
    }
    return app


class TestTimelineRoutes:
    def test_timeline_not_found(self, client) -> None:
        resp = client.get("/investigations/nonexistent/timeline.html")
        assert resp.status_code == 404

    def test_timeline_empty_graph(self, client_with_investigation) -> None:
        """Empty graph returns a message, not an error."""
        resp = client_with_investigation.get("/investigations/inv-test1/timeline.html")
        assert resp.status_code == 200
        assert "No events" in resp.text

    @patch("secdashboards.graph.timeline.TimelineVisualizer")
    @patch("secdashboards.graph.timeline.extract_timeline_from_graph")
    def test_timeline_renders(self, mock_extract, mock_viz_cls, app_with_graph) -> None:
        from secdashboards.graph.timeline import InvestigationTimeline, TimelineEvent

        mock_timeline = InvestigationTimeline(
            investigation_id="inv-graph",
            events=[
                TimelineEvent(
                    id="evt-1",
                    timestamp=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
                    title="Login",
                    entity_type="Principal",
                    entity_id="principal:admin",
                ),
            ],
        )
        mock_extract.return_value = mock_timeline
        mock_viz = MagicMock()
        mock_viz.to_html.return_value = "<div>Timeline Chart</div>"
        mock_viz_cls.return_value = mock_viz

        client = TestClient(app_with_graph)
        resp = client.get("/investigations/inv-graph/timeline.html")
        assert resp.status_code == 200
        assert "Timeline Chart" in resp.text

    def test_tag_event_not_found(self, client) -> None:
        resp = client.post(
            "/investigations/nonexistent/timeline/tag",
            data={"event_id": "e1", "tag": "suspicious"},
        )
        assert resp.status_code == 404

    def test_tag_event_missing_params(self, client_with_investigation) -> None:
        resp = client_with_investigation.post(
            "/investigations/inv-test1/timeline/tag",
            data={"event_id": "", "tag": ""},
        )
        assert resp.status_code == 400

    def test_tag_event_success(self, client_with_investigation) -> None:
        resp = client_with_investigation.post(
            "/investigations/inv-test1/timeline/tag",
            data={"event_id": "evt-1", "tag": "suspicious", "notes": "test"},
        )
        assert resp.status_code == 200
        assert "suspicious" in resp.text
        # Check in-memory timeline_tags updated
        inv = client_with_investigation.app.state.secdash.investigations
        assert inv["inv-test1"]["timeline_tags"]["evt-1"] == "suspicious"
