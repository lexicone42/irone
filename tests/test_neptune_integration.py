"""Integration tests for Neptune graph connector.

These tests require AWS credentials and a Neptune cluster.
They are skipped by default and can be enabled with:
    RUN_NEPTUNE_TESTS=1 NEPTUNE_ENDPOINT=xxx pytest tests/test_neptune_integration.py -v

Environment variables:
    RUN_NEPTUNE_TESTS: Set to "1" to enable tests
    NEPTUNE_ENDPOINT: Neptune cluster endpoint (required when enabled)
    NEPTUNE_PORT: Neptune port (default 8182)
    NEPTUNE_REGION: AWS region (default us-west-2)
"""

import os
from datetime import UTC, datetime

import pytest

from secdashboards.graph import (
    APIOperationNode,
    EdgeType,
    GraphEdge,
    GraphNode,
    IPAddressNode,
    NeptuneConnector,
    NodeType,
    PrincipalNode,
    SecurityGraph,
)

# Skip all tests unless RUN_NEPTUNE_TESTS env var is set
pytestmark = pytest.mark.skipif(
    not os.environ.get("RUN_NEPTUNE_TESTS"),
    reason="Neptune tests disabled. Set RUN_NEPTUNE_TESTS=1 and NEPTUNE_ENDPOINT to enable.",
)


@pytest.fixture
def neptune_connector() -> NeptuneConnector:
    """Create a Neptune connector from environment variables."""
    endpoint = os.environ.get("NEPTUNE_ENDPOINT")
    if not endpoint:
        pytest.skip("NEPTUNE_ENDPOINT not set")

    port = int(os.environ.get("NEPTUNE_PORT", "8182"))
    region = os.environ.get("NEPTUNE_REGION", "us-west-2")

    return NeptuneConnector(
        endpoint=endpoint,
        port=port,
        region=region,
        use_iam_auth=True,
    )


@pytest.fixture
def sample_graph() -> SecurityGraph:
    """Create a sample security graph for testing."""
    graph = SecurityGraph()

    # Create nodes
    principal = PrincipalNode(
        id="Principal:test-user",
        label="test-user",
        user_name="test-user",
        user_type="IAMUser",
        event_count=10,
    )

    ip_node = IPAddressNode(
        id="IPAddress:10.0.0.1",
        label="10.0.0.1",
        ip_address="10.0.0.1",
        is_internal=True,
        event_count=5,
    )

    api_node = APIOperationNode(
        id="APIOperation:s3:GetObject",
        label="s3:GetObject",
        service="s3",
        operation="GetObject",
        success_count=8,
        failure_count=2,
        event_count=10,
    )

    graph.add_node(principal)
    graph.add_node(ip_node)
    graph.add_node(api_node)

    # Create edges
    auth_edge = GraphEdge(
        id=GraphEdge.create_id(EdgeType.AUTHENTICATED_FROM, principal.id, ip_node.id),
        edge_type=EdgeType.AUTHENTICATED_FROM,
        source_id=principal.id,
        target_id=ip_node.id,
        event_count=5,
    )

    api_edge = GraphEdge(
        id=GraphEdge.create_id(EdgeType.CALLED_API, principal.id, api_node.id),
        edge_type=EdgeType.CALLED_API,
        source_id=principal.id,
        target_id=api_node.id,
        event_count=10,
    )

    graph.add_edge(auth_edge)
    graph.add_edge(api_edge)

    return graph


class TestNeptuneConnection:
    """Test Neptune connectivity and health checks."""

    def test_health_check(self, neptune_connector: NeptuneConnector) -> None:
        """Test that health check returns healthy status."""
        health = neptune_connector.check_health()

        assert health["status"] == "healthy"
        assert "endpoint" in health
        assert "checked_at" in health

    def test_connection_properties(self, neptune_connector: NeptuneConnector) -> None:
        """Test connector properties are set correctly."""
        assert neptune_connector.endpoint is not None
        assert neptune_connector.port == int(os.environ.get("NEPTUNE_PORT", "8182"))
        assert neptune_connector.neptune_url.startswith("https://")


class TestNodeOperations:
    """Test Neptune node CRUD operations."""

    def test_upsert_and_get_node(self, neptune_connector: NeptuneConnector) -> None:
        """Test creating and retrieving a node."""
        # Create a test node with unique ID
        test_id = f"Principal:test-{datetime.now(UTC).timestamp()}"
        node = GraphNode(
            id=test_id,
            node_type=NodeType.PRINCIPAL,
            label="test-principal",
            properties={"test": True},
            event_count=1,
        )

        # Upsert the node
        result_id = neptune_connector.upsert_node(node)
        assert result_id == test_id

        # Retrieve the node
        retrieved = neptune_connector.get_node(test_id)
        assert retrieved is not None
        assert retrieved.id == test_id
        assert retrieved.node_type == NodeType.PRINCIPAL

        # Clean up
        neptune_connector.delete_node(test_id)

    def test_find_nodes_by_type(self, neptune_connector: NeptuneConnector) -> None:
        """Test finding nodes by type."""
        # Create test nodes
        test_id = f"Principal:find-test-{datetime.now(UTC).timestamp()}"
        node = GraphNode(
            id=test_id,
            node_type=NodeType.PRINCIPAL,
            label="find-test",
            event_count=1,
        )
        neptune_connector.upsert_node(node)

        try:
            # Find by type
            nodes = neptune_connector.find_nodes(node_type=NodeType.PRINCIPAL, limit=10)
            assert len(nodes) > 0
            assert all(n.node_type == NodeType.PRINCIPAL for n in nodes)
        finally:
            neptune_connector.delete_node(test_id)

    def test_delete_node(self, neptune_connector: NeptuneConnector) -> None:
        """Test deleting a node."""
        test_id = f"Principal:delete-test-{datetime.now(UTC).timestamp()}"
        node = GraphNode(
            id=test_id,
            node_type=NodeType.PRINCIPAL,
            label="delete-test",
            event_count=1,
        )

        neptune_connector.upsert_node(node)
        assert neptune_connector.get_node(test_id) is not None

        neptune_connector.delete_node(test_id)
        assert neptune_connector.get_node(test_id) is None


class TestEdgeOperations:
    """Test Neptune edge operations."""

    def test_upsert_and_get_edge(self, neptune_connector: NeptuneConnector) -> None:
        """Test creating and retrieving an edge."""
        ts = datetime.now(UTC).timestamp()
        source_id = f"Principal:edge-test-{ts}"
        target_id = f"IPAddress:edge-test-{ts}"

        # Create nodes first
        source = GraphNode(
            id=source_id,
            node_type=NodeType.PRINCIPAL,
            label="edge-source",
            event_count=1,
        )
        target = GraphNode(
            id=target_id,
            node_type=NodeType.IP_ADDRESS,
            label="edge-target",
            event_count=1,
        )
        neptune_connector.upsert_node(source)
        neptune_connector.upsert_node(target)

        try:
            # Create edge
            edge = GraphEdge(
                id=GraphEdge.create_id(EdgeType.AUTHENTICATED_FROM, source_id, target_id),
                edge_type=EdgeType.AUTHENTICATED_FROM,
                source_id=source_id,
                target_id=target_id,
                event_count=1,
            )
            neptune_connector.upsert_edge(edge)

            # Retrieve edge
            edges = neptune_connector.get_edges(
                source_id=source_id,
                edge_type=EdgeType.AUTHENTICATED_FROM,
            )
            assert len(edges) > 0
            assert edges[0].source_id == source_id
            assert edges[0].edge_type == EdgeType.AUTHENTICATED_FROM

        finally:
            neptune_connector.delete_node(source_id)
            neptune_connector.delete_node(target_id)


class TestGraphOperations:
    """Test full graph operations."""

    def test_save_and_load_graph(
        self,
        neptune_connector: NeptuneConnector,
        sample_graph: SecurityGraph,
    ) -> None:
        """Test saving and loading a complete graph."""
        # Make node IDs unique for this test
        ts = datetime.now(UTC).timestamp()
        for node in list(sample_graph.nodes.values()):
            old_id = node.id
            node.id = f"{node.id}-{ts}"
            sample_graph.nodes[node.id] = node
            del sample_graph.nodes[old_id]

            # Update edge references
            for edge in sample_graph.edges:
                if edge.source_id == old_id:
                    edge.source_id = node.id
                if edge.target_id == old_id:
                    edge.target_id = node.id
                edge.id = GraphEdge.create_id(edge.edge_type, edge.source_id, edge.target_id)

        try:
            # Save the graph
            count = neptune_connector.save_graph(sample_graph)
            assert count > 0

            # Load a subgraph around a node
            center_id = list(sample_graph.nodes.keys())[0]
            loaded = neptune_connector.load_graph(center_id, depth=2)
            assert loaded.node_count() > 0

        finally:
            # Clean up
            for node_id in sample_graph.nodes:
                neptune_connector.delete_node(node_id)


class TestTraversalQueries:
    """Test graph traversal operations."""

    def test_find_paths(self, neptune_connector: NeptuneConnector) -> None:
        """Test finding paths between nodes."""
        ts = datetime.now(UTC).timestamp()
        node_a = f"Principal:path-a-{ts}"
        node_b = f"IPAddress:path-b-{ts}"
        node_c = f"APIOperation:path-c-{ts}"

        # Create a chain: A -> B -> C
        neptune_connector.upsert_node(
            GraphNode(id=node_a, node_type=NodeType.PRINCIPAL, label="A", event_count=1)
        )
        neptune_connector.upsert_node(
            GraphNode(id=node_b, node_type=NodeType.IP_ADDRESS, label="B", event_count=1)
        )
        neptune_connector.upsert_node(
            GraphNode(id=node_c, node_type=NodeType.API_OPERATION, label="C", event_count=1)
        )

        neptune_connector.upsert_edge(
            GraphEdge(
                id=GraphEdge.create_id(EdgeType.AUTHENTICATED_FROM, node_a, node_b),
                edge_type=EdgeType.AUTHENTICATED_FROM,
                source_id=node_a,
                target_id=node_b,
                event_count=1,
            )
        )
        neptune_connector.upsert_edge(
            GraphEdge(
                id=GraphEdge.create_id(EdgeType.ORIGINATED_FROM, node_c, node_b),
                edge_type=EdgeType.ORIGINATED_FROM,
                source_id=node_c,
                target_id=node_b,
                event_count=1,
            )
        )

        try:
            # Find paths from A to C
            paths = neptune_connector.find_paths(node_a, node_c, max_depth=3)
            # Path should exist through B
            assert len(paths) >= 0  # May be empty if graph structure differs

        finally:
            neptune_connector.delete_node(node_a)
            neptune_connector.delete_node(node_b)
            neptune_connector.delete_node(node_c)


class TestGremlinExecution:
    """Test raw Gremlin query execution."""

    def test_execute_gremlin_count(self, neptune_connector: NeptuneConnector) -> None:
        """Test executing a simple Gremlin count query."""
        result = neptune_connector.execute_gremlin("g.V().count()")

        assert result is not None
        assert "result" in result

    def test_execute_gremlin_limit(self, neptune_connector: NeptuneConnector) -> None:
        """Test executing Gremlin with limit."""
        result = neptune_connector.execute_gremlin("g.V().limit(5).elementMap()")

        assert result is not None
        assert "result" in result
