"""Tests for NeptuneConnector with mocked boto3 client.

Tests Gremlin query delegation, result conversion, and graph operations
without requiring a real Neptune cluster.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from secdashboards.graph.connector import NeptuneConnector
from secdashboards.graph.models import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    SecurityGraph,
)


@pytest.fixture
def mock_client():
    """Create a mock boto3 neptunedata client."""
    return MagicMock()


@pytest.fixture
def connector(mock_client):
    """Create a NeptuneConnector with mocked client."""
    with patch("boto3.client", return_value=mock_client):
        conn = NeptuneConnector(endpoint="test.neptune.amazonaws.com")
        conn._client = mock_client
        return conn


# =============================================================================
# Result Conversion Tests (_result_to_node, _result_to_edge)
# =============================================================================


class TestResultToNode:
    """Tests for converting Neptune vertex data to GraphNode."""

    def test_basic_vertex(self, connector):
        """Should convert a Neptune vertex dict to a GraphNode."""
        data = {
            "id": "principal-123",
            "label": "Principal",
            "properties": {
                "label": [{"value": "admin-user"}],
                "event_count": [{"value": 42}],
            },
        }
        node = connector._result_to_node(data)

        assert node is not None
        assert node.id == "principal-123"
        assert node.node_type == NodeType.PRINCIPAL
        assert node.label == "admin-user"
        assert node.event_count == 42

    def test_empty_data_returns_none(self, connector):
        """Should return None for empty data."""
        assert connector._result_to_node({}) is None
        assert connector._result_to_node(None) is None

    def test_unknown_label_defaults_to_event(self, connector):
        """Should default to NodeType.EVENT for unknown labels."""
        data = {
            "id": "unknown-1",
            "label": "SomeNewType",
            "properties": {},
        }
        node = connector._result_to_node(data)
        assert node is not None
        assert node.node_type == NodeType.EVENT

    def test_single_value_property_flattened(self, connector):
        """Should flatten single-value property lists."""
        data = {
            "id": "ip-1",
            "label": "IPAddress",
            "properties": {
                "address": [{"value": "10.0.0.1"}],
                "geo_country": [{"value": "US"}],
            },
        }
        node = connector._result_to_node(data)
        assert node.properties["address"] == "10.0.0.1"
        assert node.properties["geo_country"] == "US"

    def test_multi_value_property_preserved(self, connector):
        """Should preserve multi-value property lists."""
        data = {
            "id": "res-1",
            "label": "Resource",
            "properties": {
                "tags": [{"value": "env:prod"}, {"value": "team:security"}],
            },
        }
        node = connector._result_to_node(data)
        # Multi-value properties stay as lists
        assert isinstance(node.properties["tags"], list)
        assert len(node.properties["tags"]) == 2

    def test_all_node_types(self, connector):
        """Should correctly map all NodeType labels."""
        for node_type in NodeType:
            data = {"id": f"test-{node_type.value}", "label": node_type.value, "properties": {}}
            node = connector._result_to_node(data)
            assert node.node_type == node_type

    def test_missing_label_property_uses_id(self, connector):
        """Should use node ID as label when label property is missing."""
        data = {
            "id": "node-999",
            "label": "Principal",
            "properties": {},
        }
        node = connector._result_to_node(data)
        assert node.label == "node-999"


class TestResultToEdge:
    """Tests for converting Neptune edge data to GraphEdge."""

    def test_basic_edge(self, connector):
        """Should convert a Neptune edge dict to a GraphEdge."""
        data = {
            "id": "edge-1",
            "label": "CALLED_API",
            "outV": "principal-1",
            "inV": "api-1",
            "properties": {
                "event_count": [{"value": 10}],
            },
        }
        edge = connector._result_to_edge(data)

        assert edge is not None
        assert edge.id == "edge-1"
        assert edge.edge_type == EdgeType.CALLED_API
        assert edge.source_id == "principal-1"
        assert edge.target_id == "api-1"
        assert edge.event_count == 10

    def test_empty_data_returns_none(self, connector):
        """Should return None for empty data."""
        assert connector._result_to_edge({}) is None
        assert connector._result_to_edge(None) is None

    def test_unknown_label_defaults_to_related_to(self, connector):
        """Should default to RELATED_TO for unknown edge labels."""
        data = {
            "id": "edge-2",
            "label": "SOME_NEW_RELATION",
            "outV": "a",
            "inV": "b",
            "properties": {},
        }
        edge = connector._result_to_edge(data)
        assert edge.edge_type == EdgeType.RELATED_TO

    def test_all_edge_types(self, connector):
        """Should correctly map all EdgeType labels."""
        for edge_type in EdgeType:
            data = {
                "id": f"test-{edge_type.value}",
                "label": edge_type.value,
                "outV": "source",
                "inV": "target",
                "properties": {},
            }
            edge = connector._result_to_edge(data)
            assert edge.edge_type == edge_type


# =============================================================================
# Vertex/Edge Detection Tests
# =============================================================================


class TestIsVertexIsEdge:
    """Tests for _is_vertex and _is_edge helpers."""

    def test_vertex_detection(self, connector):
        vertex = {"id": "v1", "label": "Principal", "properties": {}}
        assert connector._is_vertex(vertex) is True
        assert connector._is_edge(vertex) is False

    def test_edge_detection(self, connector):
        edge = {"id": "e1", "label": "CALLED_API", "outV": "v1", "inV": "v2"}
        assert connector._is_edge(edge) is True
        assert connector._is_vertex(edge) is False

    def test_non_dict_items(self, connector):
        assert connector._is_vertex("not a dict") is False
        assert connector._is_edge(42) is False
        assert connector._is_vertex(None) is False


# =============================================================================
# CRUD Operations (mocked execute_gremlin)
# =============================================================================


class TestUpsertNode:
    """Tests for upsert_node delegation."""

    def test_calls_execute_gremlin(self, connector, mock_client):
        """Should delegate to execute_gremlin with query from GremlinQueries."""
        node = GraphNode(
            id="principal-1",
            node_type=NodeType.PRINCIPAL,
            label="test-user",
            properties={"name": "test-user"},
        )
        mock_client.execute_gremlin_query.return_value = {}

        result = connector.upsert_node(node)

        assert result == "principal-1"
        mock_client.execute_gremlin_query.assert_called_once()
        call_args = mock_client.execute_gremlin_query.call_args
        assert "principal-1" in call_args.kwargs["gremlinQuery"]

    def test_returns_node_id(self, connector, mock_client):
        """Should return the node ID."""
        node = GraphNode(id="ip-10.0.0.1", node_type=NodeType.IP_ADDRESS, label="10.0.0.1")
        mock_client.execute_gremlin_query.return_value = {}

        assert connector.upsert_node(node) == "ip-10.0.0.1"


class TestGetNode:
    """Tests for get_node with mocked responses."""

    def test_found_node(self, connector, mock_client):
        """Should return a GraphNode when result has data."""
        mock_client.execute_gremlin_query.return_value = {
            "result": {
                "data": [
                    {
                        "id": "principal-1",
                        "label": "Principal",
                        "properties": {"label": [{"value": "admin"}]},
                    }
                ]
            }
        }

        node = connector.get_node("principal-1")
        assert node is not None
        assert node.id == "principal-1"
        assert node.node_type == NodeType.PRINCIPAL

    def test_not_found_returns_none(self, connector, mock_client):
        """Should return None when no data."""
        mock_client.execute_gremlin_query.return_value = {"result": {"data": []}}
        assert connector.get_node("nonexistent") is None

    def test_empty_response_returns_none(self, connector, mock_client):
        """Should return None for empty response."""
        mock_client.execute_gremlin_query.return_value = {}
        assert connector.get_node("missing") is None


class TestFindNodes:
    """Tests for find_nodes with mocked responses."""

    def test_returns_matching_nodes(self, connector, mock_client):
        """Should return list of GraphNodes from result data."""
        mock_client.execute_gremlin_query.return_value = {
            "result": {
                "data": [
                    {"id": "p1", "label": "Principal", "properties": {}},
                    {"id": "p2", "label": "Principal", "properties": {}},
                ]
            }
        }

        nodes = connector.find_nodes(node_type=NodeType.PRINCIPAL)
        assert len(nodes) == 2
        assert all(n.node_type == NodeType.PRINCIPAL for n in nodes)

    def test_empty_result_returns_empty_list(self, connector, mock_client):
        """Should return empty list when no matches."""
        mock_client.execute_gremlin_query.return_value = {"result": {"data": []}}
        assert connector.find_nodes() == []


class TestUpsertEdge:
    """Tests for upsert_edge delegation."""

    def test_calls_execute_gremlin(self, connector, mock_client):
        """Should delegate to execute_gremlin."""
        edge = GraphEdge(
            id="edge-1",
            edge_type=EdgeType.CALLED_API,
            source_id="principal-1",
            target_id="api-1",
        )
        mock_client.execute_gremlin_query.return_value = {}

        result = connector.upsert_edge(edge)
        assert result == "edge-1"
        mock_client.execute_gremlin_query.assert_called_once()


class TestGetEdges:
    """Tests for get_edges with mocked responses."""

    def test_returns_matching_edges(self, connector, mock_client):
        """Should return list of GraphEdges from result data."""
        mock_client.execute_gremlin_query.return_value = {
            "result": {
                "data": [
                    {
                        "id": "e1",
                        "label": "CALLED_API",
                        "outV": "p1",
                        "inV": "api1",
                        "properties": {},
                    },
                ]
            }
        }

        edges = connector.get_edges(source_id="p1")
        assert len(edges) == 1
        assert edges[0].edge_type == EdgeType.CALLED_API

    def test_empty_result_returns_empty_list(self, connector, mock_client):
        """Should return empty list when no matches."""
        mock_client.execute_gremlin_query.return_value = {"result": {"data": []}}
        assert connector.get_edges() == []


# =============================================================================
# Graph Operations
# =============================================================================


class TestSaveGraph:
    """Tests for saving a SecurityGraph to Neptune."""

    def test_saves_nodes_and_edges(self, connector, mock_client):
        """Should upsert all nodes then all edges."""
        mock_client.execute_gremlin_query.return_value = {}

        graph = SecurityGraph()
        node1 = GraphNode(id="p1", node_type=NodeType.PRINCIPAL, label="user1")
        node2 = GraphNode(id="api1", node_type=NodeType.API_OPERATION, label="AssumeRole")
        edge = GraphEdge(id="e1", edge_type=EdgeType.CALLED_API, source_id="p1", target_id="api1")
        graph.add_node(node1)
        graph.add_node(node2)
        graph.add_edge(edge)

        count = connector.save_graph(graph)
        assert count == 3  # 2 nodes + 1 edge
        assert mock_client.execute_gremlin_query.call_count == 3

    def test_empty_graph(self, connector, mock_client):
        """Should handle empty graph gracefully."""
        graph = SecurityGraph()
        count = connector.save_graph(graph)
        assert count == 0
        mock_client.execute_gremlin_query.assert_not_called()

    def test_continues_on_node_error(self, connector, mock_client):
        """Should continue saving when a single node fails."""
        call_count = 0

        def side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Transient Neptune error")
            return {}

        mock_client.execute_gremlin_query.side_effect = side_effect

        graph = SecurityGraph()
        graph.add_node(GraphNode(id="p1", node_type=NodeType.PRINCIPAL, label="user1"))
        graph.add_node(GraphNode(id="p2", node_type=NodeType.PRINCIPAL, label="user2"))

        count = connector.save_graph(graph)
        # First node fails, second succeeds
        assert count == 1


class TestLoadGraph:
    """Tests for loading a subgraph from Neptune."""

    def test_loads_vertices_and_edges(self, connector, mock_client):
        """Should parse path results into nodes and edges."""
        mock_client.execute_gremlin_query.return_value = {
            "result": {
                "data": [
                    [
                        {"id": "p1", "label": "Principal", "properties": {}},
                        {
                            "id": "e1",
                            "label": "CALLED_API",
                            "outV": "p1",
                            "inV": "api1",
                            "properties": {},
                        },
                        {"id": "api1", "label": "APIOperation", "properties": {}},
                    ]
                ]
            }
        }

        graph = connector.load_graph("p1", depth=1)
        assert graph.node_count() == 2
        assert graph.edge_count() == 1

    def test_empty_result_returns_empty_graph(self, connector, mock_client):
        """Should return empty SecurityGraph when no data."""
        mock_client.execute_gremlin_query.return_value = {"result": {"data": []}}

        graph = connector.load_graph("nonexistent")
        assert graph.node_count() == 0
        assert graph.edge_count() == 0


# =============================================================================
# Health Check
# =============================================================================


class TestCheckHealth:
    """Tests for check_health."""

    def test_healthy(self, connector, mock_client):
        """Should return healthy status when query succeeds."""
        mock_client.execute_gremlin_query.return_value = {"result": {"data": [0]}}

        health = connector.check_health()
        assert health["status"] == "healthy"
        assert health["endpoint"] == "test.neptune.amazonaws.com"
        assert health["region"] == "us-west-2"
        assert "checked_at" in health

    def test_unhealthy(self, connector, mock_client):
        """Should return unhealthy status when query fails."""
        mock_client.execute_gremlin_query.side_effect = RuntimeError("Connection refused")

        health = connector.check_health()
        assert health["status"] == "unhealthy"
        assert "Connection refused" in health["error"]

    def test_health_check_query(self, connector, mock_client):
        """Should use a simple count query for health check."""
        mock_client.execute_gremlin_query.return_value = {"result": {"data": [0]}}

        connector.check_health()
        call_args = mock_client.execute_gremlin_query.call_args
        assert "g.V().limit(1).count()" in call_args.kwargs["gremlinQuery"]


# =============================================================================
# Execute Gremlin
# =============================================================================


class TestExecuteGremlin:
    """Tests for execute_gremlin error handling."""

    def test_propagates_exceptions(self, connector, mock_client):
        """Should re-raise exceptions from Neptune API."""
        mock_client.execute_gremlin_query.side_effect = RuntimeError("Query timeout")

        with pytest.raises(RuntimeError, match="Query timeout"):
            connector.execute_gremlin("g.V().count()")

    def test_returns_response(self, connector, mock_client):
        """Should return the response dict from Neptune API."""
        expected = {"result": {"data": [42]}}
        mock_client.execute_gremlin_query.return_value = expected

        result = connector.execute_gremlin("g.V().count()")
        assert result == expected


# =============================================================================
# Context Manager
# =============================================================================


class TestContextManager:
    """Tests for NeptuneConnector as context manager."""

    def test_enter_returns_self(self, connector):
        """Should return self on __enter__."""
        assert connector.__enter__() is connector

    def test_exit_closes(self, connector):
        """Should close gremlin client on __exit__."""
        connector._gremlin_client = MagicMock()
        connector.__exit__(None, None, None)
        # After close, _gremlin_client should be reset
        assert connector._gremlin_client is None


# =============================================================================
# Initialization
# =============================================================================


class TestInit:
    """Tests for NeptuneConnector initialization."""

    def test_default_values(self):
        """Should set default port, region, and IAM auth."""
        conn = NeptuneConnector(endpoint="test.cluster.neptune.amazonaws.com")
        assert conn.endpoint == "test.cluster.neptune.amazonaws.com"
        assert conn.port == 8182
        assert conn.region == "us-west-2"
        assert conn.use_iam_auth is True
        assert conn._client is None

    def test_custom_values(self):
        """Should accept custom configuration."""
        conn = NeptuneConnector(
            endpoint="custom.neptune.amazonaws.com",
            port=9999,
            region="eu-west-1",
            use_iam_auth=False,
        )
        assert conn.port == 9999
        assert conn.region == "eu-west-1"
        assert conn.use_iam_auth is False

    def test_neptune_url_property(self):
        """Should construct the correct Neptune URL."""
        conn = NeptuneConnector(endpoint="my-cluster.neptune.amazonaws.com", port=8182)
        assert conn.neptune_url == "https://my-cluster.neptune.amazonaws.com:8182"
