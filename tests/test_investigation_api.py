"""Tests for the investigation JSON API endpoints."""

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from secdashboards.graph.models import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    SecurityGraph,
)
from secdashboards.web.app import create_app
from secdashboards.web.config import WebConfig


@pytest.fixture
def app():
    config = WebConfig(duckdb_path=":memory:")
    return create_app(config)


@pytest.fixture
def client(app):
    return TestClient(app)


def _make_graph() -> SecurityGraph:
    """Build a small test graph with 2 nodes and 1 edge."""
    graph = SecurityGraph()
    graph.add_node(
        GraphNode(
            id="user-alice",
            node_type=NodeType.PRINCIPAL,
            label="alice@example.com",
            event_count=5,
        )
    )
    graph.add_node(
        GraphNode(
            id="ip-1.2.3.4",
            node_type=NodeType.IP_ADDRESS,
            label="1.2.3.4",
            event_count=3,
        )
    )
    graph.add_edge(
        GraphEdge(
            id="AUTHENTICATED_FROM:user-alice->ip-1.2.3.4",
            edge_type=EdgeType.AUTHENTICATED_FROM,
            source_id="user-alice",
            target_id="ip-1.2.3.4",
        )
    )
    return graph


def _seed_investigation(app, inv_id: str = "inv-test1234", name: str = "Test Inv"):
    """Seed the app state with a test investigation."""
    graph = _make_graph()
    app.state.secdash.investigations[inv_id] = {
        "name": name,
        "graph": graph,
        "created_at": "2026-02-13T12:00:00+00:00",
        "timeline_tags": {},
    }
    return inv_id


class TestListInvestigations:
    def test_empty_list(self, client) -> None:
        resp = client.get("/api/investigations")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_with_investigations(self, app, client) -> None:
        _seed_investigation(app, "inv-aaa", "First")
        _seed_investigation(app, "inv-bbb", "Second")
        resp = client.get("/api/investigations")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        ids = {d["id"] for d in data}
        assert "inv-aaa" in ids
        assert "inv-bbb" in ids

    def test_list_includes_counts(self, app, client) -> None:
        _seed_investigation(app)
        resp = client.get("/api/investigations")
        data = resp.json()
        assert data[0]["node_count"] == 2
        assert data[0]["edge_count"] == 1


class TestCreateInvestigation:
    def test_create_empty_graph(self, client) -> None:
        """Without Security Lake, creates investigation with empty graph."""
        resp = client.post(
            "/api/investigations",
            json={"name": "My Inv", "users": ["alice"], "ips": []},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "My Inv"
        assert data["id"].startswith("inv-")
        assert "summary" in data
        assert "created_at" in data

    def test_create_auto_names(self, client) -> None:
        """Without a name, uses the inv ID."""
        resp = client.post(
            "/api/investigations",
            json={"users": ["bob"], "ips": []},
        )
        data = resp.json()
        assert data["name"] == data["id"]


class TestGetInvestigation:
    def test_get_existing(self, app, client) -> None:
        inv_id = _seed_investigation(app)
        resp = client.get(f"/api/investigations/{inv_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == inv_id
        assert data["name"] == "Test Inv"
        assert data["summary"]["total_nodes"] == 2
        assert data["timeline_tags"] == {}

    def test_get_not_found(self, client) -> None:
        resp = client.get("/api/investigations/inv-nonexistent")
        assert resp.status_code == 404


class TestGetInvestigationGraph:
    def test_graph_cytoscape_format(self, app, client) -> None:
        inv_id = _seed_investigation(app)
        resp = client.get(f"/api/investigations/{inv_id}/graph")
        assert resp.status_code == 200
        data = resp.json()
        assert "elements" in data
        assert "summary" in data

        elements = data["elements"]
        nodes = [e for e in elements if e["group"] == "nodes"]
        edges = [e for e in elements if e["group"] == "edges"]
        assert len(nodes) == 2
        assert len(edges) == 1

    def test_graph_node_data(self, app, client) -> None:
        inv_id = _seed_investigation(app)
        resp = client.get(f"/api/investigations/{inv_id}/graph")
        elements = resp.json()["elements"]
        nodes = [e for e in elements if e["group"] == "nodes"]
        alice = next(n for n in nodes if n["data"]["id"] == "user-alice")
        assert alice["data"]["label"] == "alice@example.com"
        assert alice["data"]["node_type"] == "Principal"
        assert alice["data"]["event_count"] == 5

    def test_graph_edge_data(self, app, client) -> None:
        inv_id = _seed_investigation(app)
        resp = client.get(f"/api/investigations/{inv_id}/graph")
        elements = resp.json()["elements"]
        edges = [e for e in elements if e["group"] == "edges"]
        edge = edges[0]["data"]
        assert edge["source"] == "user-alice"
        assert edge["target"] == "ip-1.2.3.4"
        assert edge["edge_type"] == "AUTHENTICATED_FROM"

    def test_graph_not_found(self, client) -> None:
        resp = client.get("/api/investigations/inv-nonexistent/graph")
        assert resp.status_code == 404


class TestTagTimelineEvent:
    def test_tag_event(self, app, client) -> None:
        inv_id = _seed_investigation(app)
        resp = client.post(
            f"/api/investigations/{inv_id}/timeline/tag",
            json={"event_id": "evt-001", "tag": "lateral_movement", "notes": "suspicious"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["event_id"] == "evt-001"
        assert data["tag"] == "lateral_movement"

        # Verify persisted in state
        inv = app.state.secdash.investigations[inv_id]
        assert inv["timeline_tags"]["evt-001"] == "lateral_movement"

    def test_tag_not_found(self, client) -> None:
        resp = client.post(
            "/api/investigations/inv-nonexistent/timeline/tag",
            json={"event_id": "evt-001", "tag": "test"},
        )
        assert resp.status_code == 404


class TestDeleteInvestigation:
    def test_delete_existing(self, app, client) -> None:
        inv_id = _seed_investigation(app)
        resp = client.delete(f"/api/investigations/{inv_id}")
        assert resp.status_code == 200
        assert resp.json()["deleted"] == inv_id

        # Verify removed from state
        assert inv_id not in app.state.secdash.investigations

    def test_delete_not_found(self, client) -> None:
        resp = client.delete("/api/investigations/inv-nonexistent")
        assert resp.status_code == 404

    def test_delete_with_store(self, app, client) -> None:
        inv_id = _seed_investigation(app)
        mock_store = MagicMock()
        app.state.secdash.investigation_store = mock_store

        client.delete(f"/api/investigations/{inv_id}")
        mock_store.delete_investigation.assert_called_once_with(inv_id)


class TestEnrichInvestigation:
    def test_enrich_not_found(self, client) -> None:
        resp = client.post(
            "/api/investigations/inv-nonexistent/enrich",
            json={"users": ["bob"]},
        )
        assert resp.status_code == 404

    def test_enrich_without_security_lake(self, app, client) -> None:
        """Without Security Lake configured, enrich returns error gracefully."""
        inv_id = _seed_investigation(app)
        resp = client.post(
            f"/api/investigations/{inv_id}/enrich",
            json={"users": ["bob"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Should return error but not crash
        assert "error" in data
        assert "summary" in data
