"""Tests for the detection → investigation pipeline API endpoints.

Covers:
- POST /api/detections/{rule_id}/run
- POST /api/investigations/from-detection
- GET /api/investigations/{inv_id}/report
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from secdashboards.detections.rule import (
    DetectionMetadata,
    DetectionResult,
    Severity,
    SQLDetectionRule,
)
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


def _register_test_rule(app, rule_id: str = "test-rule") -> SQLDetectionRule:
    """Register a simple detection rule into the app's runner."""
    meta = DetectionMetadata(
        id=rule_id,
        name="Test Detection",
        severity=Severity.HIGH,
    )
    rule = SQLDetectionRule(
        metadata=meta,
        query_template="SELECT * FROM events WHERE time_dt BETWEEN '{start}' AND '{end}'",
    )
    app.state.secdash.runner.register_rule(rule)
    return rule


def _make_detection_result(triggered: bool = True, rule_id: str = "test-rule") -> DetectionResult:
    """Create a DetectionResult for testing."""
    return DetectionResult(
        rule_id=rule_id,
        rule_name="Test Detection",
        triggered=triggered,
        severity=Severity.HIGH,
        match_count=3 if triggered else 0,
        matches=[
            {"actor.user.name": "alice", "src_endpoint.ip": "10.0.0.1"},
            {"actor.user.name": "alice", "src_endpoint.ip": "10.0.0.2"},
            {"actor.user.name": "bob", "src_endpoint.ip": "10.0.0.1"},
        ]
        if triggered
        else [],
        message="Test detection triggered" if triggered else "No matches",
        executed_at=datetime(2026, 2, 13, 12, 0, 0, tzinfo=UTC),
    )


def _make_graph() -> SecurityGraph:
    """Build a small test graph."""
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
            id="ip-10.0.0.1",
            node_type=NodeType.IP_ADDRESS,
            label="10.0.0.1",
            event_count=3,
        )
    )
    graph.add_edge(
        GraphEdge(
            id="AUTHENTICATED_FROM:user-alice->ip-10.0.0.1",
            edge_type=EdgeType.AUTHENTICATED_FROM,
            source_id="user-alice",
            target_id="ip-10.0.0.1",
        )
    )
    return graph


def _seed_investigation(app, inv_id: str = "inv-test1234") -> str:
    """Seed the app with a test investigation."""
    app.state.secdash.investigations[inv_id] = {
        "name": "Test Investigation",
        "graph": _make_graph(),
        "created_at": "2026-02-13T12:00:00+00:00",
        "timeline_tags": {},
    }
    return inv_id


# ─── POST /api/detections/{rule_id}/run ──────────────────────────


class TestRunDetection:
    def test_rule_not_found(self, client) -> None:
        resp = client.post(
            "/api/detections/nonexistent/run",
            json={"lookback_minutes": 15},
        )
        assert resp.status_code == 404

    def test_no_sources_configured(self, app, client) -> None:
        _register_test_rule(app)
        resp = client.post(
            "/api/detections/test-rule/run",
            json={},
        )
        # No SL sources → 400
        assert resp.status_code == 400
        assert "No Security Lake sources" in resp.json()["detail"]

    def test_explicit_source(self, app, client) -> None:
        """Run detection against a named source (duckdb-local)."""
        _register_test_rule(app)

        mock_result = _make_detection_result(triggered=False)
        with patch.object(app.state.secdash.runner, "run_rule", return_value=mock_result):
            resp = client.post(
                "/api/detections/test-rule/run",
                json={"source_name": "duckdb-local", "lookback_minutes": 30},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["rule_id"] == "test-rule"
        assert data["triggered"] is False
        assert data["match_count"] == 0

    def test_triggered_detection(self, app, client) -> None:
        _register_test_rule(app)

        mock_result = _make_detection_result(triggered=True)
        with patch.object(app.state.secdash.runner, "run_rule", return_value=mock_result):
            resp = client.post(
                "/api/detections/test-rule/run",
                json={"source_name": "duckdb-local"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["triggered"] is True
        assert data["match_count"] == 3
        assert data["severity"] == "high"
        assert len(data["matches"]) == 3
        assert data["executed_at"] == "2026-02-13T12:00:00+00:00"

    def test_detection_with_error(self, app, client) -> None:
        _register_test_rule(app)

        error_result = DetectionResult(
            rule_id="test-rule",
            rule_name="Test Detection",
            triggered=False,
            error="Connection timeout",
        )
        with patch.object(app.state.secdash.runner, "run_rule", return_value=error_result):
            resp = client.post(
                "/api/detections/test-rule/run",
                json={"source_name": "duckdb-local"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["triggered"] is False
        assert data["error"] == "Connection timeout"

    def test_invalid_source_name(self, app, client) -> None:
        _register_test_rule(app)
        resp = client.post(
            "/api/detections/test-rule/run",
            json={"source_name": "nonexistent-source"},
        )
        assert resp.status_code == 400


# ─── POST /api/investigations/from-detection ─────────────────────


class TestCreateFromDetection:
    def test_rule_not_found(self, client) -> None:
        resp = client.post(
            "/api/investigations/from-detection",
            json={"rule_id": "nonexistent"},
        )
        assert resp.status_code == 404

    def test_detection_not_triggered(self, app, client) -> None:
        _register_test_rule(app)

        mock_result = _make_detection_result(triggered=False)
        with patch.object(app.state.secdash.runner, "run_rule", return_value=mock_result):
            resp = client.post(
                "/api/investigations/from-detection",
                json={"rule_id": "test-rule", "source_name": "duckdb-local"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["created"] is False
        assert data["triggered"] is False

    def test_detection_error(self, app, client) -> None:
        _register_test_rule(app)

        error_result = DetectionResult(
            rule_id="test-rule",
            rule_name="Test Detection",
            triggered=False,
            error="Athena timeout",
        )
        with patch.object(app.state.secdash.runner, "run_rule", return_value=error_result):
            resp = client.post(
                "/api/investigations/from-detection",
                json={"rule_id": "test-rule", "source_name": "duckdb-local"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["created"] is False
        assert data["error"] == "Athena timeout"

    @patch("secdashboards.graph.timeline.extract_timeline_from_graph")
    @patch("secdashboards.graph.builder.GraphBuilder")
    def test_successful_pipeline(
        self, MockGraphBuilder, mock_extract_timeline, app, client
    ) -> None:
        _register_test_rule(app)

        # Mock detection
        mock_result = _make_detection_result(triggered=True)

        # Mock graph builder
        mock_builder_instance = MagicMock()
        mock_builder_instance.build_from_detection.return_value = _make_graph()
        MockGraphBuilder.return_value = mock_builder_instance

        # Mock timeline
        mock_timeline = MagicMock()
        mock_timeline.events = [MagicMock(), MagicMock()]
        mock_extract_timeline.return_value = mock_timeline

        with patch.object(app.state.secdash.runner, "run_rule", return_value=mock_result):
            resp = client.post(
                "/api/investigations/from-detection",
                json={
                    "rule_id": "test-rule",
                    "name": "My Investigation",
                    "source_name": "duckdb-local",
                    "lookback_minutes": 30,
                    "enrichment_window_minutes": 120,
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["created"] is True
        assert data["id"].startswith("inv-")
        assert data["name"] == "My Investigation"
        assert data["detection"]["triggered"] is True
        assert data["detection"]["match_count"] == 3
        assert data["detection"]["severity"] == "high"
        assert data["summary"]["total_nodes"] == 2
        assert data["timeline_event_count"] == 2

        # Verify investigation was saved to state
        inv = app.state.secdash.investigations[data["id"]]
        assert inv["name"] == "My Investigation"
        assert inv["detection"]["rule_id"] == "test-rule"

    @patch("secdashboards.graph.timeline.extract_timeline_from_graph")
    @patch("secdashboards.graph.builder.GraphBuilder")
    def test_auto_generated_name(
        self, MockGraphBuilder, mock_extract_timeline, app, client
    ) -> None:
        """Without a name, uses rule_name + timestamp."""
        _register_test_rule(app)

        mock_result = _make_detection_result(triggered=True)
        mock_builder = MagicMock()
        mock_builder.build_from_detection.return_value = SecurityGraph()
        MockGraphBuilder.return_value = mock_builder
        mock_extract_timeline.return_value = MagicMock(events=[])

        with patch.object(app.state.secdash.runner, "run_rule", return_value=mock_result):
            resp = client.post(
                "/api/investigations/from-detection",
                json={"rule_id": "test-rule", "source_name": "duckdb-local"},
            )

        data = resp.json()
        assert "Test Detection" in data["name"]
        assert "2026-02-13" in data["name"]

    @patch("secdashboards.graph.timeline.extract_timeline_from_graph")
    @patch("secdashboards.graph.builder.GraphBuilder")
    def test_persists_to_store(self, MockGraphBuilder, mock_extract_timeline, app, client) -> None:
        _register_test_rule(app)
        mock_store = MagicMock()
        app.state.secdash.investigation_store = mock_store

        mock_result = _make_detection_result(triggered=True)
        mock_builder = MagicMock()
        mock_builder.build_from_detection.return_value = _make_graph()
        MockGraphBuilder.return_value = mock_builder
        mock_extract_timeline.return_value = MagicMock(events=[])

        with patch.object(app.state.secdash.runner, "run_rule", return_value=mock_result):
            resp = client.post(
                "/api/investigations/from-detection",
                json={"rule_id": "test-rule", "source_name": "duckdb-local"},
            )

        assert resp.json()["created"] is True
        mock_store.save_investigation.assert_called_once()

    def test_no_sources_returns_400(self, app, client) -> None:
        _register_test_rule(app)
        resp = client.post(
            "/api/investigations/from-detection",
            json={"rule_id": "test-rule"},
        )
        assert resp.status_code == 400


# ─── GET /api/investigations/{inv_id}/report ─────────────────────


class TestGetInvestigationReport:
    def test_not_found(self, client) -> None:
        resp = client.get("/api/investigations/inv-nonexistent/report")
        assert resp.status_code == 404

    def test_report_structure(self, app, client) -> None:
        inv_id = _seed_investigation(app)
        resp = client.get(f"/api/investigations/{inv_id}/report")
        assert resp.status_code == 200
        data = resp.json()

        # Report data fields from InvestigationReportData
        assert data["investigation_id"] == inv_id
        assert "generated_at" in data
        assert "total_nodes" in data
        assert "total_edges" in data
        assert data["total_nodes"] == 2
        assert data["total_edges"] == 1

    def test_report_includes_entities(self, app, client) -> None:
        inv_id = _seed_investigation(app)
        resp = client.get(f"/api/investigations/{inv_id}/report")
        data = resp.json()

        # Should have entity summaries from the graph
        assert "entity_summaries" in data
        assert "principals" in data
        assert "ip_addresses" in data

    def test_report_includes_timeline(self, app, client) -> None:
        inv_id = _seed_investigation(app)
        resp = client.get(f"/api/investigations/{inv_id}/report")
        data = resp.json()

        assert "timeline_events" in data
        assert isinstance(data["timeline_events"], list)

    def test_empty_graph_report(self, app, client) -> None:
        """Report from empty graph should not error."""
        app.state.secdash.investigations["inv-empty"] = {
            "name": "Empty",
            "graph": SecurityGraph(),
            "created_at": "2026-02-13T00:00:00+00:00",
            "timeline_tags": {},
        }

        resp = client.get("/api/investigations/inv-empty/report")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_nodes"] == 0
        assert data["total_edges"] == 0
