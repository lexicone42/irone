"""Neptune graph database connector.

This module provides the NeptuneConnector class for interacting with
AWS Neptune graph database for persisting and querying security graphs.
"""

import contextlib
from datetime import datetime
from typing import Any

import boto3
import structlog
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from secdashboards.graph.models import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    SecurityGraph,
)
from secdashboards.graph.queries import GremlinQueries

logger = structlog.get_logger()


class NeptuneConnector:
    """Connector for AWS Neptune graph database.

    This class provides methods for storing and querying security
    investigation graphs in Neptune using Gremlin traversals.

    Example usage:
        ```python
        neptune = NeptuneConnector(
            endpoint="my-cluster.cluster-xxx.us-west-2.neptune.amazonaws.com",
            port=8182,
            region="us-west-2",
        )

        # Check health
        health = neptune.check_health()

        # Save a graph
        count = neptune.save_graph(graph)

        # Load a graph around a node
        subgraph = neptune.load_graph("Principal:admin", depth=2)
        ```
    """

    def __init__(
        self,
        endpoint: str,
        port: int = 8182,
        region: str = "us-west-2",
        use_iam_auth: bool = True,
    ) -> None:
        """Initialize Neptune connection.

        Args:
            endpoint: Neptune cluster endpoint
            port: Neptune port (default 8182)
            region: AWS region
            use_iam_auth: Use IAM authentication
        """
        self.endpoint = endpoint
        self.port = port
        self.region = region
        self.use_iam_auth = use_iam_auth
        self._client: Any = None
        self._gremlin_client: Any = None
        self.queries = GremlinQueries()

    @property
    def neptune_url(self) -> str:
        """Get the Neptune HTTPS URL."""
        return f"https://{self.endpoint}:{self.port}"

    @property
    def client(self) -> Any:
        """Lazy initialization of Neptune data client."""
        if self._client is None:
            self._client = boto3.client(
                "neptunedata",
                region_name=self.region,
                endpoint_url=self.neptune_url,
            )
        return self._client

    def _get_gremlin_client(self) -> Any:
        """Get or create a Gremlin Python client."""
        if self._gremlin_client is None:
            try:
                from gremlin_python.driver.driver_remote_connection import (
                    DriverRemoteConnection,
                )
                from gremlin_python.process.anonymous_traversal import traversal

                # For IAM auth, we need to sign requests
                if self.use_iam_auth:
                    # Use the boto3 session credentials
                    session = boto3.Session()
                    credentials = session.get_credentials()
                    if credentials is None:
                        raise ValueError("No AWS credentials found for IAM authentication")
                    ws_url = f"wss://{self.endpoint}:{self.port}/gremlin"

                    # Create signed connection
                    connection = DriverRemoteConnection(
                        ws_url,
                        "g",
                        headers=self._get_signed_headers(ws_url, credentials),
                    )
                else:
                    ws_url = f"ws://{self.endpoint}:{self.port}/gremlin"
                    connection = DriverRemoteConnection(ws_url, "g")

                self._gremlin_client = traversal().withRemote(connection)

            except ImportError:
                logger.warning("gremlin_python not available, using HTTP API")
                self._gremlin_client = None

        return self._gremlin_client

    def _get_signed_headers(self, url: str, credentials: Credentials) -> dict[str, str]:
        """Generate signed headers for IAM authentication.

        Args:
            url: The URL to sign
            credentials: AWS credentials

        Returns:
            Dictionary of signed headers
        """
        request = AWSRequest(method="GET", url=url)
        SigV4Auth(credentials, "neptune-db", self.region).add_auth(request)
        return dict(request.headers)

    # =========================================================================
    # Node Operations
    # =========================================================================

    def upsert_node(self, node: GraphNode) -> str:
        """Insert or update a node in Neptune.

        Args:
            node: The node to upsert

        Returns:
            The node ID
        """
        query = self.queries.upsert_node(node)
        self.execute_gremlin(query)
        return node.id

    def get_node(self, node_id: str) -> GraphNode | None:
        """Get a node by ID.

        Args:
            node_id: The node ID to retrieve

        Returns:
            The node if found, None otherwise
        """
        query = self.queries.get_node(node_id)
        result = self.execute_gremlin(query)

        if not result or not result.get("result", {}).get("data"):
            return None

        data = result["result"]["data"]
        if not data:
            return None

        # Convert Neptune result to GraphNode
        return self._result_to_node(data[0])

    def find_nodes(
        self,
        node_type: NodeType | None = None,
        properties: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> list[GraphNode]:
        """Find nodes matching criteria.

        Args:
            node_type: Optional node type filter
            properties: Optional property filters
            limit: Maximum nodes to return

        Returns:
            List of matching nodes
        """
        query = self.queries.find_nodes(node_type, properties, limit)
        result = self.execute_gremlin(query)

        if not result or not result.get("result", {}).get("data"):
            return []

        nodes = []
        for item in result["result"]["data"]:
            node = self._result_to_node(item)
            if node:
                nodes.append(node)

        return nodes

    def delete_node(self, node_id: str) -> bool:
        """Delete a node by ID.

        Args:
            node_id: The node ID to delete

        Returns:
            True if deleted
        """
        query = self.queries.delete_node(node_id)
        self.execute_gremlin(query)
        return True

    # =========================================================================
    # Edge Operations
    # =========================================================================

    def upsert_edge(self, edge: GraphEdge) -> str:
        """Insert or update an edge in Neptune.

        Args:
            edge: The edge to upsert

        Returns:
            The edge ID
        """
        query = self.queries.upsert_edge(edge)
        self.execute_gremlin(query)
        return edge.id

    def get_edges(
        self,
        source_id: str | None = None,
        target_id: str | None = None,
        edge_type: EdgeType | None = None,
    ) -> list[GraphEdge]:
        """Get edges matching criteria.

        Args:
            source_id: Optional source node filter
            target_id: Optional target node filter
            edge_type: Optional edge type filter

        Returns:
            List of matching edges
        """
        query = self.queries.get_edges(source_id, target_id, edge_type)
        result = self.execute_gremlin(query)

        if not result or not result.get("result", {}).get("data"):
            return []

        edges = []
        for item in result["result"]["data"]:
            edge = self._result_to_edge(item)
            if edge:
                edges.append(edge)

        return edges

    def delete_edge(self, edge_id: str) -> bool:
        """Delete an edge by ID.

        Args:
            edge_id: The edge ID to delete

        Returns:
            True if deleted
        """
        query = self.queries.delete_edge(edge_id)
        self.execute_gremlin(query)
        return True

    # =========================================================================
    # Graph Operations
    # =========================================================================

    def save_graph(self, graph: SecurityGraph) -> int:
        """Save a complete graph to Neptune.

        Args:
            graph: The SecurityGraph to save

        Returns:
            Number of entities saved
        """
        count = 0

        # Save nodes first
        for node in graph.nodes.values():
            try:
                self.upsert_node(node)
                count += 1
            except Exception as e:
                logger.warning("failed_to_save_node", node_id=node.id, error=str(e))

        # Then save edges
        for edge in graph.edges:
            try:
                self.upsert_edge(edge)
                count += 1
            except Exception as e:
                logger.warning("failed_to_save_edge", edge_id=edge.id, error=str(e))

        logger.info("graph_saved_to_neptune", entities=count)
        return count

    def load_graph(
        self,
        center_node_id: str,
        depth: int = 2,
        edge_types: list[EdgeType] | None = None,
    ) -> SecurityGraph:
        """Load a subgraph centered on a node.

        Args:
            center_node_id: The center node ID
            depth: How many hops to traverse
            edge_types: Optional edge type filter

        Returns:
            A SecurityGraph with the subgraph
        """
        query = self.queries.get_subgraph(center_node_id, depth, edge_types)
        result = self.execute_gremlin(query)

        graph = SecurityGraph()

        if not result or not result.get("result", {}).get("data"):
            return graph

        # Parse the path results
        for path in result["result"]["data"]:
            if isinstance(path, list):
                for item in path:
                    if self._is_vertex(item):
                        node = self._result_to_node(item)
                        if node:
                            graph.add_node(node)
                    elif self._is_edge(item):
                        edge = self._result_to_edge(item)
                        if edge:
                            graph.add_edge(edge)

        return graph

    # =========================================================================
    # Traversal Queries
    # =========================================================================

    def find_paths(
        self,
        start_id: str,
        end_id: str,
        max_depth: int = 5,
    ) -> list[list[str]]:
        """Find all paths between two nodes.

        Args:
            start_id: Starting node ID
            end_id: Ending node ID
            max_depth: Maximum path length

        Returns:
            List of paths (each path is a list of node IDs)
        """
        query = self.queries.find_paths(start_id, end_id, max_depth)
        result = self.execute_gremlin(query)

        if not result or not result.get("result", {}).get("data"):
            return []

        paths = []
        for path in result["result"]["data"]:
            if isinstance(path, list):
                paths.append(path)

        return paths

    def get_related_entities(
        self,
        node_id: str,
        relationship_types: list[EdgeType] | None = None,
        depth: int = 1,
    ) -> SecurityGraph:
        """Get all entities related to a node.

        Args:
            node_id: The center node ID
            relationship_types: Optional edge type filter
            depth: How many hops to traverse

        Returns:
            A SecurityGraph with related entities
        """
        return self.load_graph(node_id, depth, relationship_types)

    def find_common_neighbors(
        self,
        node_ids: list[str],
    ) -> list[GraphNode]:
        """Find nodes connected to all specified nodes.

        Args:
            node_ids: List of node IDs

        Returns:
            List of common neighbor nodes
        """
        if len(node_ids) < 2:
            return []

        query = self.queries.find_common_neighbors(node_ids)
        result = self.execute_gremlin(query)

        if not result or not result.get("result", {}).get("data"):
            return []

        nodes = []
        for item in result["result"]["data"]:
            node = self._result_to_node(item)
            if node:
                nodes.append(node)

        return nodes

    # =========================================================================
    # Query Execution
    # =========================================================================

    def execute_gremlin(self, query: str) -> dict[str, Any]:
        """Execute a Gremlin query using the Neptune Data API.

        Args:
            query: The Gremlin query string

        Returns:
            Query result dictionary
        """
        try:
            response = self.client.execute_gremlin_query(gremlinQuery=query)
            return response
        except Exception as e:
            logger.error("gremlin_query_failed", query=query[:200], error=str(e))
            raise

    def execute_opencypher(self, query: str) -> dict[str, Any]:
        """Execute an openCypher query.

        Args:
            query: The openCypher query string

        Returns:
            Query result dictionary
        """
        try:
            response = self.client.execute_open_cypher_query(openCypherQuery=query)
            return response
        except Exception as e:
            logger.error("opencypher_query_failed", query=query[:200], error=str(e))
            raise

    # =========================================================================
    # Health Check
    # =========================================================================

    def check_health(self) -> dict[str, Any]:
        """Check Neptune cluster health.

        Returns:
            Health check result dictionary
        """
        try:
            # Execute a simple query to check connectivity
            self.execute_gremlin("g.V().limit(1).count()")

            return {
                "status": "healthy",
                "endpoint": self.endpoint,
                "port": self.port,
                "region": self.region,
                "checked_at": datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "endpoint": self.endpoint,
                "port": self.port,
                "region": self.region,
                "error": str(e),
                "checked_at": datetime.now().isoformat(),
            }

    # =========================================================================
    # Result Conversion Helpers
    # =========================================================================

    def _result_to_node(self, data: dict[str, Any]) -> GraphNode | None:
        """Convert Neptune result to a GraphNode.

        Args:
            data: Neptune vertex data

        Returns:
            A GraphNode or None
        """
        if not data:
            return None

        # Extract node type from label
        label = data.get("label", "Unknown")
        try:
            node_type = NodeType(label)
        except ValueError:
            node_type = NodeType.EVENT

        # Build base node
        node_id = data.get("id", "")
        properties = data.get("properties", {})

        # Flatten single-value properties
        flat_props = {}
        for key, value in properties.items():
            if isinstance(value, list) and len(value) == 1:
                flat_props[key] = value[0].get("value", value[0])
            else:
                flat_props[key] = value

        return GraphNode(
            id=str(node_id),
            node_type=node_type,
            label=flat_props.get("label", str(node_id)),
            properties=flat_props,
            event_count=int(flat_props.get("event_count", 0)),
        )

    def _result_to_edge(self, data: dict[str, Any]) -> GraphEdge | None:
        """Convert Neptune result to a GraphEdge.

        Args:
            data: Neptune edge data

        Returns:
            A GraphEdge or None
        """
        if not data:
            return None

        label = data.get("label", "RELATED_TO")
        try:
            edge_type = EdgeType(label)
        except ValueError:
            edge_type = EdgeType.RELATED_TO

        properties = data.get("properties", {})
        flat_props = {}
        for key, value in properties.items():
            if isinstance(value, list) and len(value) == 1:
                flat_props[key] = value[0].get("value", value[0])
            else:
                flat_props[key] = value

        return GraphEdge(
            id=str(data.get("id", "")),
            edge_type=edge_type,
            source_id=str(data.get("outV", "")),
            target_id=str(data.get("inV", "")),
            properties=flat_props,
            event_count=int(flat_props.get("event_count", 1)),
        )

    def _is_vertex(self, item: Any) -> bool:
        """Check if an item is a vertex."""
        if isinstance(item, dict):
            return "label" in item and "id" in item and "outV" not in item
        return False

    def _is_edge(self, item: Any) -> bool:
        """Check if an item is an edge."""
        if isinstance(item, dict):
            return "outV" in item and "inV" in item
        return False

    def close(self) -> None:
        """Close connections."""
        if self._gremlin_client:
            with contextlib.suppress(Exception):
                self._gremlin_client.close()
            self._gremlin_client = None

    def __enter__(self) -> "NeptuneConnector":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
