"""Tests for the graph module.

This module contains unit tests for entity models, graph builder,
visualization, and query generation.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import polars as pl
import pytest

from secdashboards.detections.rule import DetectionResult, Severity
from secdashboards.graph.builder import GraphBuilder
from secdashboards.graph.models import (
    APIOperationNode,
    EdgeType,
    GraphEdge,
    GraphNode,
    IPAddressNode,
    NodeType,
    PrincipalNode,
    ResourceNode,
    SecurityFindingNode,
    SecurityGraph,
)
from secdashboards.graph.queries import GremlinQueries
from secdashboards.graph.visualization import GraphVisualizer

# =============================================================================
# Model Tests
# =============================================================================


class TestNodeType:
    """Tests for NodeType enum."""

    def test_all_node_types_defined(self) -> None:
        """Verify all expected node types exist."""
        assert NodeType.PRINCIPAL.value == "Principal"
        assert NodeType.IP_ADDRESS.value == "IPAddress"
        assert NodeType.RESOURCE.value == "Resource"
        assert NodeType.API_OPERATION.value == "APIOperation"
        assert NodeType.SECURITY_FINDING.value == "SecurityFinding"
        assert NodeType.EVENT.value == "Event"


class TestEdgeType:
    """Tests for EdgeType enum."""

    def test_all_edge_types_defined(self) -> None:
        """Verify all expected edge types exist."""
        assert EdgeType.AUTHENTICATED_FROM.value == "AUTHENTICATED_FROM"
        assert EdgeType.CALLED_API.value == "CALLED_API"
        assert EdgeType.ACCESSED_RESOURCE.value == "ACCESSED_RESOURCE"
        assert EdgeType.ORIGINATED_FROM.value == "ORIGINATED_FROM"
        assert EdgeType.RELATED_TO.value == "RELATED_TO"
        assert EdgeType.TRIGGERED_BY.value == "TRIGGERED_BY"
        assert EdgeType.PERFORMED_BY.value == "PERFORMED_BY"
        assert EdgeType.TARGETED.value == "TARGETED"


class TestGraphNode:
    """Tests for base GraphNode model."""

    def test_create_base_node(self) -> None:
        """Test creating a base graph node."""
        node = GraphNode(
            id="test-node-1",
            node_type=NodeType.EVENT,
            label="Test Node",
        )
        assert node.id == "test-node-1"
        assert node.node_type == NodeType.EVENT
        assert node.label == "Test Node"
        assert node.event_count == 0

    def test_update_timestamps(self) -> None:
        """Test timestamp updates."""
        node = GraphNode(
            id="test-node",
            node_type=NodeType.EVENT,
            label="Test",
        )
        now = datetime.now(UTC)
        earlier = now - timedelta(hours=1)
        later = now + timedelta(hours=1)

        # First update
        node.update_timestamps(now)
        assert node.first_seen == now
        assert node.last_seen == now
        assert node.event_count == 1

        # Earlier event
        node.update_timestamps(earlier)
        assert node.first_seen == earlier
        assert node.last_seen == now
        assert node.event_count == 2

        # Later event
        node.update_timestamps(later)
        assert node.first_seen == earlier
        assert node.last_seen == later
        assert node.event_count == 3


class TestPrincipalNode:
    """Tests for PrincipalNode model."""

    def test_create_principal_node(self) -> None:
        """Test creating a principal node."""
        node = PrincipalNode(
            id="Principal:admin-user",
            label="admin-user",
            user_name="admin-user",
            user_type="IAMUser",
            arn="arn:aws:iam::123456789012:user/admin-user",
            account_id="123456789012",
        )
        assert node.node_type == NodeType.PRINCIPAL
        assert node.user_name == "admin-user"
        assert node.user_type == "IAMUser"

    def test_create_id(self) -> None:
        """Test ID creation."""
        node_id = PrincipalNode.create_id("test-user")
        assert node_id == "Principal:test-user"

    def test_from_ocsf_flat(self) -> None:
        """Test creating from flat OCSF data."""
        event = {
            "actor.user.name": "admin",
            "actor.user.type": "Root",
            "actor.user.uid": "arn:aws:iam::123:root",
            "cloud.account.uid": "123456789012",
        }
        node = PrincipalNode.from_ocsf(event)
        assert node is not None
        assert node.user_name == "admin"
        assert node.user_type == "Root"

    def test_from_ocsf_nested(self) -> None:
        """Test creating from nested OCSF data."""
        event = {
            "actor": {
                "user": {
                    "name": "admin",
                    "type": "IAMUser",
                    "uid": "arn:aws:iam::123:user/admin",
                }
            },
            "cloud": {"account": {"uid": "123456789012"}},
        }
        node = PrincipalNode.from_ocsf(event)
        assert node is not None
        assert node.user_name == "admin"

    def test_from_ocsf_missing_user(self) -> None:
        """Test creating from OCSF data without user info."""
        event = {"some_other_field": "value"}
        node = PrincipalNode.from_ocsf(event)
        assert node is None


class TestIPAddressNode:
    """Tests for IPAddressNode model."""

    def test_create_ip_node(self) -> None:
        """Test creating an IP address node."""
        node = IPAddressNode(
            id="IPAddress:192.168.1.1",
            label="192.168.1.1",
            ip_address="192.168.1.1",
            is_internal=True,
        )
        assert node.node_type == NodeType.IP_ADDRESS
        assert node.ip_address == "192.168.1.1"
        assert node.is_internal is True

    def test_create_id(self) -> None:
        """Test ID creation."""
        node_id = IPAddressNode.create_id("10.0.0.1")
        assert node_id == "IPAddress:10.0.0.1"

    def test_from_ocsf_detects_internal_ip(self) -> None:
        """Test that internal IPs are detected."""
        # Private IP ranges
        internal_ips = ["10.0.0.1", "172.16.0.1", "192.168.1.1"]
        for ip in internal_ips:
            event = {"src_endpoint.ip": ip}
            node = IPAddressNode.from_ocsf(event)
            assert node is not None
            assert node.is_internal is True, f"{ip} should be internal"

    def test_from_ocsf_detects_external_ip(self) -> None:
        """Test that external IPs are detected."""
        event = {"src_endpoint.ip": "8.8.8.8"}
        node = IPAddressNode.from_ocsf(event)
        assert node is not None
        assert node.is_internal is False


class TestAPIOperationNode:
    """Tests for APIOperationNode model."""

    def test_create_api_node(self) -> None:
        """Test creating an API operation node."""
        node = APIOperationNode(
            id="APIOperation:iam:CreateUser",
            label="iam:CreateUser",
            operation="CreateUser",
            service="iam",
        )
        assert node.node_type == NodeType.API_OPERATION
        assert node.operation == "CreateUser"
        assert node.service == "iam"

    def test_record_status(self) -> None:
        """Test recording success/failure status."""
        node = APIOperationNode(
            id="APIOperation:s3:GetObject",
            label="s3:GetObject",
            operation="GetObject",
            service="s3",
        )

        node.record_status("Success")
        assert node.success_count == 1
        assert node.failure_count == 0

        node.record_status("Failure")
        assert node.success_count == 1
        assert node.failure_count == 1

    def test_from_ocsf_normalizes_service(self) -> None:
        """Test that service names are normalized."""
        event = {
            "api.operation": "CreateUser",
            "api.service.name": "iam.amazonaws.com",
        }
        node = APIOperationNode.from_ocsf(event)
        assert node is not None
        assert node.service == "iam"


class TestResourceNode:
    """Tests for ResourceNode model."""

    def test_from_arn(self) -> None:
        """Test creating from an ARN."""
        arn = "arn:aws:s3:::my-bucket"
        node = ResourceNode.from_arn(arn)
        assert node is not None
        assert node.resource_type == "s3"
        assert node.arn == arn

    def test_from_arn_with_path(self) -> None:
        """Test creating from ARN with resource path."""
        arn = "arn:aws:lambda:us-west-2:123456789012:function/my-function"
        node = ResourceNode.from_arn(arn)
        assert node is not None
        assert node.resource_type == "function"
        assert node.resource_id == "my-function"
        assert node.region == "us-west-2"

    def test_from_arn_invalid(self) -> None:
        """Test that invalid ARNs return None."""
        assert ResourceNode.from_arn("not-an-arn") is None
        assert ResourceNode.from_arn("arn:aws:s3") is None


class TestSecurityFindingNode:
    """Tests for SecurityFindingNode model."""

    def test_create_finding_node(self) -> None:
        """Test creating a security finding node."""
        now = datetime.now(UTC)
        node = SecurityFindingNode(
            id="Finding:detect-root-login:20260113120000",
            label="Root Login Detected",
            rule_id="detect-root-login",
            rule_name="Root Login Detected",
            severity="high",
            triggered_at=now,
            match_count=5,
        )
        assert node.node_type == NodeType.SECURITY_FINDING
        assert node.severity == "high"
        assert node.match_count == 5


class TestGraphEdge:
    """Tests for GraphEdge model."""

    def test_create_edge(self) -> None:
        """Test creating an edge."""
        edge = GraphEdge(
            id="AUTHENTICATED_FROM:Principal:admin->IPAddress:1.2.3.4",
            edge_type=EdgeType.AUTHENTICATED_FROM,
            source_id="Principal:admin",
            target_id="IPAddress:1.2.3.4",
        )
        assert edge.edge_type == EdgeType.AUTHENTICATED_FROM
        assert edge.event_count == 1

    def test_create_id(self) -> None:
        """Test edge ID creation."""
        edge_id = GraphEdge.create_id(
            EdgeType.CALLED_API,
            "Principal:user1",
            "APIOperation:iam:CreateUser",
        )
        assert edge_id == "CALLED_API:Principal:user1->APIOperation:iam:CreateUser"

    def test_update_timestamps(self) -> None:
        """Test edge timestamp updates."""
        edge = GraphEdge(
            id="test-edge",
            edge_type=EdgeType.RELATED_TO,
            source_id="a",
            target_id="b",
        )
        now = datetime.now(UTC)

        edge.update_timestamps(now)
        assert edge.first_seen == now
        assert edge.last_seen == now
        assert edge.event_count == 2  # Started at 1, now 2


class TestSecurityGraph:
    """Tests for SecurityGraph container."""

    def test_add_node(self) -> None:
        """Test adding a node."""
        graph = SecurityGraph()
        node = PrincipalNode(
            id="Principal:test",
            label="test",
            user_name="test",
        )
        graph.add_node(node)

        assert "Principal:test" in graph.nodes
        assert graph.node_count() == 1

    def test_add_node_merges_duplicates(self) -> None:
        """Test that duplicate nodes are merged."""
        graph = SecurityGraph()
        now = datetime.now(UTC)
        earlier = now - timedelta(hours=1)

        node1 = PrincipalNode(
            id="Principal:test",
            label="test",
            user_name="test",
            first_seen=now,
            last_seen=now,
            event_count=1,
        )
        graph.add_node(node1)

        node2 = PrincipalNode(
            id="Principal:test",
            label="test",
            user_name="test",
            first_seen=earlier,
            last_seen=earlier,
        )
        graph.add_node(node2)

        # Should still be one node
        assert graph.node_count() == 1
        # But timestamps should be updated
        merged = graph.get_node("Principal:test")
        assert merged is not None
        assert merged.first_seen == earlier

    def test_add_edge(self) -> None:
        """Test adding an edge."""
        graph = SecurityGraph()

        # Add nodes first
        graph.add_node(PrincipalNode(id="Principal:user1", label="user1", user_name="user1"))
        graph.add_node(IPAddressNode(id="IPAddress:1.1.1.1", label="1.1.1.1", ip_address="1.1.1.1"))

        # Add edge
        edge = GraphEdge(
            id="e1",
            edge_type=EdgeType.AUTHENTICATED_FROM,
            source_id="Principal:user1",
            target_id="IPAddress:1.1.1.1",
        )
        graph.add_edge(edge)

        assert graph.edge_count() == 1

    def test_get_neighbors(self) -> None:
        """Test getting neighbors of a node."""
        graph = SecurityGraph()

        # Build small graph
        user = PrincipalNode(id="Principal:user1", label="user1", user_name="user1")
        ip1 = IPAddressNode(id="IPAddress:1.1.1.1", label="1.1.1.1", ip_address="1.1.1.1")
        ip2 = IPAddressNode(id="IPAddress:2.2.2.2", label="2.2.2.2", ip_address="2.2.2.2")

        graph.add_node(user)
        graph.add_node(ip1)
        graph.add_node(ip2)

        graph.add_edge(
            GraphEdge(
                id="e1",
                edge_type=EdgeType.AUTHENTICATED_FROM,
                source_id=user.id,
                target_id=ip1.id,
            )
        )
        graph.add_edge(
            GraphEdge(
                id="e2",
                edge_type=EdgeType.AUTHENTICATED_FROM,
                source_id=user.id,
                target_id=ip2.id,
            )
        )

        neighbors = graph.get_neighbors("Principal:user1")
        assert len(neighbors) == 2

    def test_get_nodes_by_type(self) -> None:
        """Test filtering nodes by type."""
        graph = SecurityGraph()

        graph.add_node(PrincipalNode(id="Principal:u1", label="u1", user_name="u1"))
        graph.add_node(PrincipalNode(id="Principal:u2", label="u2", user_name="u2"))
        graph.add_node(IPAddressNode(id="IPAddress:1.1.1.1", label="1.1.1.1", ip_address="1.1.1.1"))

        principals = graph.get_nodes_by_type(NodeType.PRINCIPAL)
        assert len(principals) == 2

        ips = graph.get_nodes_by_type(NodeType.IP_ADDRESS)
        assert len(ips) == 1

    def test_summary(self) -> None:
        """Test graph summary."""
        graph = SecurityGraph()

        graph.add_node(PrincipalNode(id="Principal:u1", label="u1", user_name="u1"))
        graph.add_node(IPAddressNode(id="IPAddress:1.1.1.1", label="1.1.1.1", ip_address="1.1.1.1"))
        graph.add_edge(
            GraphEdge(
                id="e1",
                edge_type=EdgeType.AUTHENTICATED_FROM,
                source_id="Principal:u1",
                target_id="IPAddress:1.1.1.1",
            )
        )

        summary = graph.summary()
        assert summary["total_nodes"] == 2
        assert summary["total_edges"] == 1
        assert "Principal" in summary["nodes_by_type"]
        assert "AUTHENTICATED_FROM" in summary["edges_by_type"]

    def test_to_networkx(self) -> None:
        """Test conversion to NetworkX graph."""
        graph = SecurityGraph()

        graph.add_node(PrincipalNode(id="Principal:u1", label="u1", user_name="u1"))
        graph.add_node(IPAddressNode(id="IPAddress:1.1.1.1", label="1.1.1.1", ip_address="1.1.1.1"))
        graph.add_edge(
            GraphEdge(
                id="e1",
                edge_type=EdgeType.AUTHENTICATED_FROM,
                source_id="Principal:u1",
                target_id="IPAddress:1.1.1.1",
            )
        )

        nx_graph = graph.to_networkx()
        assert nx_graph.number_of_nodes() == 2
        assert nx_graph.number_of_edges() == 1


# =============================================================================
# GraphBuilder Tests
# =============================================================================


class TestGraphBuilder:
    """Tests for GraphBuilder class."""

    @pytest.fixture
    def mock_connector(self) -> MagicMock:
        """Create a mock Security Lake connector."""
        mock = MagicMock()
        # Return empty DataFrames by default
        mock.query_by_event_class.return_value = pl.DataFrame()
        return mock

    @pytest.fixture
    def sample_detection_result(self) -> DetectionResult:
        """Create a sample detection result."""
        return DetectionResult(
            rule_id="detect-root-login",
            rule_name="Root Login Detected",
            triggered=True,
            severity=Severity.HIGH,
            match_count=2,
            matches=[
                {
                    "actor.user.name": "root",
                    "actor.user.type": "Root",
                    "src_endpoint.ip": "203.0.113.50",
                    "api.operation": "ConsoleLogin",
                    "api.service.name": "signin.amazonaws.com",
                    "status": "Success",
                    "time_dt": "2026-01-13T10:00:00Z",
                },
                {
                    "actor.user.name": "root",
                    "actor.user.type": "Root",
                    "src_endpoint.ip": "203.0.113.51",
                    "api.operation": "ConsoleLogin",
                    "api.service.name": "signin.amazonaws.com",
                    "status": "Success",
                    "time_dt": "2026-01-13T11:00:00Z",
                },
            ],
            executed_at=datetime.now(UTC),
        )

    def test_extract_identifiers(
        self, mock_connector: MagicMock, sample_detection_result: DetectionResult
    ) -> None:
        """Test identifier extraction from matches."""
        builder = GraphBuilder(mock_connector)
        identifiers = builder._extract_identifiers(sample_detection_result.matches)

        assert "root" in identifiers["users"]
        assert "203.0.113.50" in identifiers["ips"]
        assert "203.0.113.51" in identifiers["ips"]
        assert "ConsoleLogin" in identifiers["operations"]
        assert "signin.amazonaws.com" in identifiers["services"]

    def test_build_from_detection_creates_finding_node(
        self, mock_connector: MagicMock, sample_detection_result: DetectionResult
    ) -> None:
        """Test that detection builds a finding node."""
        builder = GraphBuilder(mock_connector)
        graph = builder.build_from_detection(
            sample_detection_result,
            enrichment_window_minutes=60,
        )

        findings = graph.get_nodes_by_type(NodeType.SECURITY_FINDING)
        assert len(findings) == 1
        assert findings[0].label == "Root Login Detected"

    def test_build_from_detection_creates_principal_nodes(
        self, mock_connector: MagicMock, sample_detection_result: DetectionResult
    ) -> None:
        """Test that detection builds principal nodes."""
        builder = GraphBuilder(mock_connector)
        graph = builder.build_from_detection(sample_detection_result)

        principals = graph.get_nodes_by_type(NodeType.PRINCIPAL)
        assert len(principals) >= 1
        assert any(p.label == "root" for p in principals)

    def test_build_from_detection_creates_ip_nodes(
        self, mock_connector: MagicMock, sample_detection_result: DetectionResult
    ) -> None:
        """Test that detection builds IP nodes."""
        builder = GraphBuilder(mock_connector)
        graph = builder.build_from_detection(sample_detection_result)

        ips = graph.get_nodes_by_type(NodeType.IP_ADDRESS)
        assert len(ips) >= 2
        ip_addresses = [ip.ip_address for ip in ips]
        assert "203.0.113.50" in ip_addresses
        assert "203.0.113.51" in ip_addresses

    def test_build_from_detection_creates_edges(
        self, mock_connector: MagicMock, sample_detection_result: DetectionResult
    ) -> None:
        """Test that detection builds edges."""
        builder = GraphBuilder(mock_connector)
        graph = builder.build_from_detection(sample_detection_result)

        assert graph.edge_count() > 0

    def test_build_from_identifiers(self, mock_connector: MagicMock) -> None:
        """Test building graph from identifiers."""
        builder = GraphBuilder(mock_connector)
        graph = builder.build_from_identifiers(
            users=["admin"],
            ips=["10.0.0.1"],
        )

        # Should return a graph (even if empty due to mocked connector)
        assert isinstance(graph, SecurityGraph)

    def test_reset_clears_graph(
        self, mock_connector: MagicMock, sample_detection_result: DetectionResult
    ) -> None:
        """Test that reset clears the graph."""
        builder = GraphBuilder(mock_connector)
        builder.build_from_detection(sample_detection_result)

        assert builder.get_graph().node_count() > 0

        builder.reset()
        assert builder.get_graph().node_count() == 0


# =============================================================================
# Visualization Tests
# =============================================================================


class TestGraphVisualizer:
    """Tests for GraphVisualizer class."""

    @pytest.fixture
    def sample_graph(self) -> SecurityGraph:
        """Create a sample graph for testing."""
        graph = SecurityGraph()

        # Add nodes
        user = PrincipalNode(
            id="Principal:attacker",
            label="attacker",
            user_name="attacker",
            user_type="IAMUser",
            event_count=50,
        )
        ip = IPAddressNode(
            id="IPAddress:203.0.113.1",
            label="203.0.113.1",
            ip_address="203.0.113.1",
            event_count=25,
        )
        api = APIOperationNode(
            id="APIOperation:iam:CreateAccessKey",
            label="iam:CreateAccessKey",
            operation="CreateAccessKey",
            service="iam",
            success_count=1,
        )

        graph.add_node(user)
        graph.add_node(ip)
        graph.add_node(api)

        # Add edges
        graph.add_edge(
            GraphEdge(
                id="e1",
                edge_type=EdgeType.AUTHENTICATED_FROM,
                source_id=user.id,
                target_id=ip.id,
                event_count=25,
            )
        )
        graph.add_edge(
            GraphEdge(
                id="e2",
                edge_type=EdgeType.CALLED_API,
                source_id=user.id,
                target_id=api.id,
                event_count=1,
            )
        )

        return graph

    def test_create_network(self, sample_graph: SecurityGraph) -> None:
        """Test creating a pyvis network."""
        visualizer = GraphVisualizer()
        network = visualizer.create_network(sample_graph, notebook=False)

        # Verify nodes and edges were added
        assert len(network.nodes) == 3
        assert len(network.edges) == 2

    def test_to_html(self, sample_graph: SecurityGraph) -> None:
        """Test HTML generation."""
        visualizer = GraphVisualizer()
        html = visualizer.to_html(sample_graph, notebook=False)

        # Should return valid HTML string
        assert "<html>" in html.lower() or "<!doctype" in html.lower()
        assert "vis-network" in html.lower() or "vis.js" in html.lower()

    def test_generate_legend_html(self) -> None:
        """Test legend HTML generation."""
        visualizer = GraphVisualizer()
        legend = visualizer.generate_legend_html()

        assert "<div" in legend
        assert "Principal" in legend
        assert "IPAddress" in legend

    def test_generate_summary_html(self, sample_graph: SecurityGraph) -> None:
        """Test summary HTML generation."""
        visualizer = GraphVisualizer()
        summary = visualizer.generate_summary_html(sample_graph)

        assert "Total Nodes" in summary
        assert "3" in summary  # 3 nodes


# =============================================================================
# Gremlin Query Tests
# =============================================================================


class TestGremlinQueries:
    """Tests for GremlinQueries class."""

    def test_escape_string(self) -> None:
        """Test string escaping."""
        assert GremlinQueries._escape_string("test") == "test"
        assert GremlinQueries._escape_string("test's") == "test\\'s"
        assert GremlinQueries._escape_string('test"s') == 'test\\"s'

    def test_upsert_node_query(self) -> None:
        """Test node upsert query generation."""
        queries = GremlinQueries()
        node = PrincipalNode(
            id="Principal:admin",
            label="admin",
            user_name="admin",
            user_type="IAMUser",
            event_count=10,
        )

        query = queries.upsert_node(node)

        assert "Principal:admin" in query
        assert "Principal" in query
        assert "addV" in query
        assert "coalesce" in query

    def test_get_node_query(self) -> None:
        """Test node retrieval query generation."""
        queries = GremlinQueries()
        query = queries.get_node("Principal:admin")

        assert "Principal:admin" in query
        assert "elementMap" in query

    def test_find_nodes_query(self) -> None:
        """Test node search query generation."""
        queries = GremlinQueries()
        query = queries.find_nodes(
            node_type=NodeType.PRINCIPAL,
            properties={"user_type": "Root"},
            limit=50,
        )

        assert "hasLabel('Principal')" in query
        assert "user_type" in query
        assert "limit(50)" in query

    def test_upsert_edge_query(self) -> None:
        """Test edge upsert query generation."""
        queries = GremlinQueries()
        edge = GraphEdge(
            id="e1",
            edge_type=EdgeType.AUTHENTICATED_FROM,
            source_id="Principal:admin",
            target_id="IPAddress:1.2.3.4",
            event_count=5,
        )

        query = queries.upsert_edge(edge)

        assert "Principal:admin" in query
        assert "IPAddress:1.2.3.4" in query
        assert "AUTHENTICATED_FROM" in query
        assert "addE" in query

    def test_find_paths_query(self) -> None:
        """Test path finding query generation."""
        queries = GremlinQueries()
        query = queries.find_paths(
            start_id="Principal:admin",
            end_id="Resource:s3:my-bucket",
            max_depth=5,
        )

        assert "Principal:admin" in query
        assert "Resource:s3:my-bucket" in query
        assert "repeat" in query
        assert "path" in query

    def test_find_principals_by_ip_query(self) -> None:
        """Test principal-by-IP query generation."""
        queries = GremlinQueries()
        query = queries.find_principals_by_ip("203.0.113.1")

        assert "IPAddress:203.0.113.1" in query
        assert "AUTHENTICATED_FROM" in query
        assert "Principal" in query

    def test_find_high_activity_principals_query(self) -> None:
        """Test high-activity principals query generation."""
        queries = GremlinQueries()
        query = queries.find_high_activity_principals(min_event_count=100, limit=10)

        assert "event_count" in query
        assert "100" in query
        assert "limit(10)" in query


# =============================================================================
# Integration Tests (Mock-based)
# =============================================================================


class TestGraphIntegration:
    """Integration tests for the graph module."""

    def test_full_workflow(self) -> None:
        """Test a full workflow from detection to visualization."""
        # Create a mock connector
        mock_connector = MagicMock()
        mock_connector.query_by_event_class.return_value = pl.DataFrame()

        # Create a detection result
        result = DetectionResult(
            rule_id="test-rule",
            rule_name="Test Rule",
            triggered=True,
            severity=Severity.MEDIUM,
            match_count=1,
            matches=[
                {
                    "actor.user.name": "testuser",
                    "src_endpoint.ip": "10.0.0.1",
                    "api.operation": "TestOperation",
                    "api.service.name": "test.amazonaws.com",
                    "status": "Success",
                    "time_dt": "2026-01-13T12:00:00Z",
                }
            ],
            executed_at=datetime.now(UTC),
        )

        # Build graph
        builder = GraphBuilder(mock_connector)
        graph = builder.build_from_detection(result)

        # Verify graph structure
        assert graph.node_count() > 0
        assert graph.edge_count() > 0

        # Visualize
        visualizer = GraphVisualizer()
        html = visualizer.to_html(graph, notebook=False)

        # Verify HTML output
        assert len(html) > 0
        assert "html" in html.lower()

        # Get summary
        summary = graph.summary()
        assert summary["total_nodes"] > 0
