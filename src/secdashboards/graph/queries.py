"""Gremlin query templates for Neptune operations.

This module provides Gremlin query strings for common graph operations
in the security investigation domain.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from secdashboards.graph.models import EdgeType, GraphEdge, GraphNode, NodeType


class GremlinQueries:
    """Generate Gremlin queries for Neptune operations.

    This class provides methods to generate Gremlin traversal strings
    for common operations like node/edge upsert, graph traversal,
    and path finding.
    """

    @staticmethod
    def _escape_string(value: str) -> str:
        """Escape a string for Gremlin.

        Args:
            value: The string to escape

        Returns:
            Escaped string safe for Gremlin queries
        """
        return value.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')

    @staticmethod
    def _format_value(value: Any) -> str:
        """Format a value for Gremlin query.

        Args:
            value: The value to format

        Returns:
            Formatted string representation
        """
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, int | float):
            return str(value)
        if isinstance(value, datetime):
            return f"'{value.isoformat()}'"
        if isinstance(value, str):
            return f"'{GremlinQueries._escape_string(value)}'"
        return f"'{GremlinQueries._escape_string(str(value))}'"

    # =========================================================================
    # Node Operations
    # =========================================================================

    def upsert_node(self, node: "GraphNode") -> str:
        """Generate a node upsert (merge) query.

        Args:
            node: The node to upsert

        Returns:
            Gremlin query string
        """
        node_id = self._escape_string(node.id)
        label = node.node_type.value

        # Build property assignments
        props = [
            f".property('label', {self._format_value(node.label)})",
            f".property('event_count', {node.event_count})",
        ]

        if node.first_seen:
            props.append(f".property('first_seen', {self._format_value(node.first_seen)})")
        if node.last_seen:
            props.append(f".property('last_seen', {self._format_value(node.last_seen)})")

        # Add custom properties
        for key, value in node.properties.items():
            if key not in ("id", "label", "event_count", "first_seen", "last_seen"):
                props.append(
                    f".property('{self._escape_string(key)}', {self._format_value(value)})"
                )

        prop_string = "".join(props)

        return f"""
        g.V().has('id', '{node_id}')
         .fold()
         .coalesce(
           unfold(),
           addV('{label}').property('id', '{node_id}')
         )
         {prop_string}
        """

    def get_node(self, node_id: str) -> str:
        """Generate a query to get a node by ID.

        Args:
            node_id: The node ID

        Returns:
            Gremlin query string
        """
        return f"g.V().has('id', '{self._escape_string(node_id)}').elementMap()"

    def find_nodes(
        self,
        node_type: "NodeType | None" = None,
        properties: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> str:
        """Generate a query to find nodes.

        Args:
            node_type: Optional node type filter
            properties: Optional property filters
            limit: Maximum nodes to return

        Returns:
            Gremlin query string
        """
        query = "g.V()"

        if node_type:
            query += f".hasLabel('{node_type.value}')"

        if properties:
            for key, value in properties.items():
                query += f".has('{self._escape_string(key)}', {self._format_value(value)})"

        query += f".limit({limit}).elementMap()"
        return query

    def delete_node(self, node_id: str) -> str:
        """Generate a query to delete a node.

        Args:
            node_id: The node ID

        Returns:
            Gremlin query string
        """
        return f"g.V().has('id', '{self._escape_string(node_id)}').drop()"

    # =========================================================================
    # Edge Operations
    # =========================================================================

    def upsert_edge(self, edge: "GraphEdge") -> str:
        """Generate an edge upsert (merge) query.

        Args:
            edge: The edge to upsert

        Returns:
            Gremlin query string
        """
        source_id = self._escape_string(edge.source_id)
        target_id = self._escape_string(edge.target_id)
        edge_type = edge.edge_type.value

        # Build property assignments
        props = [f".property('event_count', {edge.event_count})"]

        if edge.first_seen:
            props.append(f".property('first_seen', {self._format_value(edge.first_seen)})")
        if edge.last_seen:
            props.append(f".property('last_seen', {self._format_value(edge.last_seen)})")
        if edge.weight != 1.0:
            props.append(f".property('weight', {edge.weight})")

        prop_string = "".join(props)

        return f"""
        g.V().has('id', '{source_id}').as('s')
         .V().has('id', '{target_id}').as('t')
         .coalesce(
           select('s').outE('{edge_type}').where(inV().has('id', '{target_id}')),
           select('s').addE('{edge_type}').to(select('t'))
         )
         {prop_string}
        """

    def get_edges(
        self,
        source_id: str | None = None,
        target_id: str | None = None,
        edge_type: "EdgeType | None" = None,
    ) -> str:
        """Generate a query to find edges.

        Args:
            source_id: Optional source node filter
            target_id: Optional target node filter
            edge_type: Optional edge type filter

        Returns:
            Gremlin query string
        """
        query = "g.E()"

        if edge_type:
            query += f".hasLabel('{edge_type.value}')"

        if source_id:
            query += f".where(outV().has('id', '{self._escape_string(source_id)}'))"

        if target_id:
            query += f".where(inV().has('id', '{self._escape_string(target_id)}'))"

        query += ".elementMap()"
        return query

    def delete_edge(self, edge_id: str) -> str:
        """Generate a query to delete an edge.

        Args:
            edge_id: The edge ID

        Returns:
            Gremlin query string
        """
        return f"g.E('{self._escape_string(edge_id)}').drop()"

    # =========================================================================
    # Graph Traversal Operations
    # =========================================================================

    def get_subgraph(
        self,
        center_id: str,
        depth: int = 2,
        edge_types: "list[EdgeType] | None" = None,
    ) -> str:
        """Generate a query to get a subgraph around a center node.

        Args:
            center_id: The center node ID
            depth: How many hops to traverse
            edge_types: Optional edge type filter

        Returns:
            Gremlin query string
        """
        edge_filter = ""
        if edge_types:
            labels = ", ".join(f"'{et.value}'" for et in edge_types)
            edge_filter = f".hasLabel({labels})"

        return f"""
        g.V().has('id', '{self._escape_string(center_id)}')
         .repeat(
           bothE(){edge_filter}.otherV().simplePath()
         )
         .times({depth})
         .path()
         .by(elementMap())
        """

    def find_paths(
        self,
        start_id: str,
        end_id: str,
        max_depth: int = 5,
        limit: int = 10,
    ) -> str:
        """Generate a query to find paths between two nodes.

        Args:
            start_id: Starting node ID
            end_id: Ending node ID
            max_depth: Maximum path length
            limit: Maximum paths to return

        Returns:
            Gremlin query string
        """
        return f"""
        g.V().has('id', '{self._escape_string(start_id)}')
         .repeat(both().simplePath())
         .until(has('id', '{self._escape_string(end_id)}').or().loops().is(gte({max_depth})))
         .has('id', '{self._escape_string(end_id)}')
         .path()
         .by('id')
         .limit({limit})
        """

    def find_common_neighbors(self, node_ids: list[str]) -> str:
        """Generate a query to find common neighbors of multiple nodes.

        Args:
            node_ids: List of node IDs

        Returns:
            Gremlin query string
        """
        if len(node_ids) < 2:
            return "g.V().limit(0)"

        # Start from first node's neighbors
        first_id = self._escape_string(node_ids[0])
        query = f"g.V().has('id', '{first_id}').both()"

        # Intersect with other nodes' neighbors
        for node_id in node_ids[1:]:
            safe_id = self._escape_string(node_id)
            query += f".where(both().has('id', '{safe_id}'))"

        query += ".dedup().elementMap()"
        return query

    # =========================================================================
    # Security-Specific Queries
    # =========================================================================

    def find_principals_by_ip(self, ip_address: str) -> str:
        """Find all principals that have accessed from a specific IP.

        Args:
            ip_address: The IP address

        Returns:
            Gremlin query string
        """
        ip_id = f"IPAddress:{self._escape_string(ip_address)}"
        return f"""
        g.V().has('id', '{ip_id}')
         .in('AUTHENTICATED_FROM')
         .hasLabel('Principal')
         .dedup()
         .elementMap()
        """

    def find_apis_by_principal(self, user_name: str) -> str:
        """Find all API operations called by a principal.

        Args:
            user_name: The user name

        Returns:
            Gremlin query string
        """
        principal_id = f"Principal:{self._escape_string(user_name)}"
        return f"""
        g.V().has('id', '{principal_id}')
         .out('CALLED_API')
         .hasLabel('APIOperation')
         .dedup()
         .elementMap()
        """

    def find_high_activity_principals(
        self,
        min_event_count: int = 100,
        limit: int = 10,
    ) -> str:
        """Find principals with high event counts.

        Args:
            min_event_count: Minimum event count threshold
            limit: Maximum results

        Returns:
            Gremlin query string
        """
        return f"""
        g.V().hasLabel('Principal')
         .has('event_count', gte({min_event_count}))
         .order().by('event_count', desc)
         .limit({limit})
         .project('principal', 'event_count', 'apis', 'ips')
           .by('id')
           .by('event_count')
           .by(out('CALLED_API').count())
           .by(out('AUTHENTICATED_FROM').count())
        """

    def find_failed_api_calls(self, limit: int = 100) -> str:
        """Find API operations with high failure counts.

        Args:
            limit: Maximum results

        Returns:
            Gremlin query string
        """
        return f"""
        g.V().hasLabel('APIOperation')
         .has('failure_count', gte(1))
         .order().by('failure_count', desc)
         .limit({limit})
         .project('operation', 'service', 'failures', 'principals')
           .by('operation')
           .by('service')
           .by('failure_count')
           .by(in('CALLED_API').values('id').fold())
        """

    def find_attack_paths(
        self,
        finding_id: str,
        max_depth: int = 5,
    ) -> str:
        """Find potential attack paths from a security finding.

        Args:
            finding_id: The security finding node ID
            max_depth: Maximum path depth

        Returns:
            Gremlin query string
        """
        return f"""
        g.V().has('id', '{self._escape_string(finding_id)}')
         .repeat(
           both().simplePath()
         )
         .times({max_depth})
         .emit()
         .path()
         .by(elementMap())
         .limit(100)
        """

    def get_investigation_summary(self, finding_id: str) -> str:
        """Get a summary of an investigation graph around a finding.

        Args:
            finding_id: The security finding node ID

        Returns:
            Gremlin query string
        """
        return f"""
        g.V().has('id', '{self._escape_string(finding_id)}')
         .project('finding', 'principals', 'ips', 'apis', 'resources')
           .by(elementMap())
           .by(
             both().hasLabel('Principal')
             .dedup().limit(10).elementMap().fold()
           )
           .by(
             both().repeat(both()).times(2).hasLabel('IPAddress')
             .dedup().limit(10).elementMap().fold()
           )
           .by(
             both().repeat(both()).times(2).hasLabel('APIOperation')
             .dedup().limit(10).elementMap().fold()
           )
           .by(
             both().repeat(both()).times(2).hasLabel('Resource')
             .dedup().limit(10).elementMap().fold()
           )
        """


# OpenCypher query templates (alternative to Gremlin)
class OpenCypherQueries:
    """Generate openCypher queries for Neptune operations.

    openCypher provides a more SQL-like syntax that may be preferred
    for complex queries.
    """

    @staticmethod
    def _escape_string(value: str) -> str:
        """Escape a string for openCypher."""
        return value.replace("\\", "\\\\").replace("'", "\\'")

    def find_principal_activity(self, user_name: str) -> str:
        """Find all activity for a principal.

        Args:
            user_name: The user name

        Returns:
            openCypher query string
        """
        return f"""
        MATCH (p:Principal {{id: 'Principal:{self._escape_string(user_name)}'}})-[r]->(n)
        RETURN p, type(r) as relationship, n
        ORDER BY r.last_seen DESC
        LIMIT 100
        """

    def find_lateral_movement_pattern(
        self,
        start_ip: str,
        time_window_hours: int = 24,
    ) -> str:
        """Find potential lateral movement from an IP.

        Args:
            start_ip: The starting IP address
            time_window_hours: Time window to search

        Returns:
            openCypher query string
        """
        return f"""
        MATCH path = (ip1:IPAddress {{ip_address: '{self._escape_string(start_ip)}'}})
            <-[:AUTHENTICATED_FROM]-(p:Principal)
            -[:AUTHENTICATED_FROM]->(ip2:IPAddress)
        WHERE ip1 <> ip2
        RETURN path
        LIMIT 50
        """

    def find_privilege_escalation_pattern(self) -> str:
        """Find potential privilege escalation patterns.

        Returns:
            openCypher query string
        """
        return """
        MATCH (p:Principal)-[:CALLED_API]->(api:APIOperation)
        WHERE api.service IN ['iam', 'sts']
          AND api.operation IN ['CreateUser', 'AttachUserPolicy', 'AssumeRole', 'CreateAccessKey']
        RETURN p.id as principal, collect(api.operation) as operations, count(*) as count
        ORDER BY count DESC
        LIMIT 20
        """
