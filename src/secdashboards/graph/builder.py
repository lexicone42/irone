"""Graph builder for security investigation.

This module provides the GraphBuilder class that constructs security
investigation graphs from detection results and enriches them with
related events from Security Lake.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import structlog

from secdashboards.connectors.security_lake import SecurityLakeConnector
from secdashboards.graph.enrichment import SecurityLakeEnricher
from secdashboards.graph.models import (
    APIOperationNode,
    EdgeType,
    EventNode,
    GraphEdge,
    IPAddressNode,
    PrincipalNode,
    SecurityFindingNode,
    SecurityGraph,
)

if TYPE_CHECKING:
    from secdashboards.detections.rule import DetectionResult
    from secdashboards.graph.connector import NeptuneConnector

from secdashboards.connectors.result import QueryResult

logger = structlog.get_logger()


class GraphBuilder:
    """Builds security graphs from detection results and Security Lake data.

    This class takes a triggered detection result, extracts key identifiers
    (users, IPs, operations), queries Security Lake for related events,
    and constructs a graph showing the relationships between entities.

    Example usage:
        ```python
        connector = catalog.get_connector("cloudtrail")
        builder = GraphBuilder(connector)

        # Build graph from a detection result
        graph = builder.build_from_detection(
            result,
            enrichment_window_minutes=60,
            max_related_events=500,
        )

        # Visualize the graph
        visualizer = GraphVisualizer()
        html = visualizer.to_html(graph)
        ```
    """

    def __init__(
        self,
        security_lake: SecurityLakeConnector,
        neptune: NeptuneConnector | None = None,
    ) -> None:
        """Initialize the graph builder.

        Args:
            security_lake: A configured SecurityLakeConnector for enrichment queries
            neptune: Optional NeptuneConnector for persisting graphs
        """
        self.security_lake = security_lake
        self.neptune = neptune
        self.enricher = SecurityLakeEnricher(security_lake)
        self._graph = SecurityGraph()

    def build_from_detection(
        self,
        result: DetectionResult,
        enrichment_window_minutes: int = 60,
        max_related_events: int = 500,
        include_events: bool = False,
    ) -> SecurityGraph:
        """Build a graph from a triggered detection with enrichment.

        This method:
        1. Creates a SecurityFinding node for the detection
        2. Extracts identifiers from the detection matches
        3. Queries Security Lake for related events
        4. Builds nodes and edges from all discovered relationships

        Args:
            result: The DetectionResult from a triggered detection
            enrichment_window_minutes: Time window for enrichment queries
            max_related_events: Maximum events to fetch per identifier
            include_events: Whether to include individual Event nodes

        Returns:
            A populated SecurityGraph with all discovered entities
        """
        self.reset()

        logger.info(
            "building_graph_from_detection",
            rule_id=result.rule_id,
            match_count=result.match_count,
            enrichment_window=enrichment_window_minutes,
        )

        # Create the security finding node
        finding_node = SecurityFindingNode(
            id=SecurityFindingNode.create_id(result.rule_id, result.executed_at),
            label=result.rule_name,
            rule_id=result.rule_id,
            rule_name=result.rule_name,
            severity=str(result.severity),
            triggered_at=result.executed_at,
            match_count=result.match_count,
        )
        self._graph.add_node(finding_node)

        # Store metadata
        self._graph.metadata = {
            "rule_id": result.rule_id,
            "rule_name": result.rule_name,
            "severity": str(result.severity),
            "triggered_at": result.executed_at.isoformat(),
            "match_count": result.match_count,
            "enrichment_window_minutes": enrichment_window_minutes,
        }

        # Extract identifiers from matches
        identifiers = self._extract_identifiers(result.matches)
        logger.debug(
            "extracted_identifiers",
            users=len(identifiers["users"]),
            ips=len(identifiers["ips"]),
            operations=len(identifiers["operations"]),
            services=len(identifiers["services"]),
        )

        # Process the original matches first
        self._process_matches(result.matches, finding_node, include_events)

        # Calculate enrichment time window
        end_time = result.executed_at
        start_time = end_time - timedelta(minutes=enrichment_window_minutes)

        # Enrich by users
        for user in list(identifiers["users"])[:10]:  # Limit users
            self._enrich_by_user(user, start_time, end_time, max_related_events, include_events)

        # Enrich by IPs
        for ip in list(identifiers["ips"])[:10]:  # Limit IPs
            self._enrich_by_ip(ip, start_time, end_time, max_related_events, include_events)

        logger.info(
            "graph_build_complete",
            nodes=self._graph.node_count(),
            edges=self._graph.edge_count(),
        )

        return self._graph

    def build_from_identifiers(
        self,
        users: list[str] | None = None,
        ips: list[str] | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        max_events: int = 500,
        include_events: bool = False,
    ) -> SecurityGraph:
        """Build a graph from specific identifiers without a detection.

        This is useful for ad-hoc investigations where you want to
        explore relationships starting from known entities.

        Args:
            users: List of user names to investigate
            ips: List of IP addresses to investigate
            start: Start of time window
            end: End of time window
            max_events: Maximum events to fetch per identifier
            include_events: Whether to include individual Event nodes

        Returns:
            A populated SecurityGraph
        """
        self.reset()

        end = end or datetime.now(UTC)
        start = start or (end - timedelta(hours=1))

        self._graph.metadata = {
            "investigation_type": "identifier_search",
            "users": users or [],
            "ips": ips or [],
            "time_window": {
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
        }

        # Enrich by users
        for user in (users or [])[:10]:
            self._enrich_by_user(user, start, end, max_events, include_events)

        # Enrich by IPs
        for ip in (ips or [])[:10]:
            self._enrich_by_ip(ip, start, end, max_events, include_events)

        return self._graph

    def _extract_identifiers(
        self,
        matches: list[dict[str, Any]],
    ) -> dict[str, set[str]]:
        """Extract key identifiers (users, IPs, resources) from matches.

        Args:
            matches: List of match dictionaries from detection result

        Returns:
            Dictionary with sets of users, ips, operations, services, resources
        """
        identifiers: dict[str, set[str]] = {
            "users": set(),
            "ips": set(),
            "resources": set(),
            "operations": set(),
            "services": set(),
        }

        for match in matches:
            # Extract users
            user = self._get_nested_value(match, "actor.user.name")
            if not user:
                user = match.get("user_name")
            if user:
                identifiers["users"].add(str(user))

            # Extract source IP
            src_ip = self._get_nested_value(match, "src_endpoint.ip")
            if not src_ip:
                src_ip = match.get("source_ip") or match.get("src_ip")
            if src_ip:
                identifiers["ips"].add(str(src_ip))

            # Extract destination IP
            dst_ip = self._get_nested_value(match, "dst_endpoint.ip")
            if dst_ip:
                identifiers["ips"].add(str(dst_ip))

            # Extract operation
            operation = self._get_nested_value(match, "api.operation")
            if not operation:
                operation = match.get("operation")
            if operation:
                identifiers["operations"].add(str(operation))

            # Extract service
            service = self._get_nested_value(match, "api.service.name")
            if not service:
                service = match.get("service")
            if service:
                identifiers["services"].add(str(service))

            # Extract resources (ARNs in request data)
            request_data = match.get("api.request.data") or match.get("request_data")
            if request_data and "arn:" in str(request_data):
                # Simple ARN extraction
                import re

                arns = re.findall(
                    r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d*:[a-zA-Z0-9/_-]+", str(request_data)
                )
                identifiers["resources"].update(arns)

        return identifiers

    def _get_nested_value(self, data: dict[str, Any], path: str) -> Any:
        """Get a value from a nested dictionary using dot notation.

        Args:
            data: The dictionary to search
            path: Dot-separated path like "actor.user.name"

        Returns:
            The value if found, None otherwise
        """
        # First try direct key (flattened OCSF)
        if path in data:
            return data[path]

        # Try nested structure
        parts = path.split(".")
        current = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current

    def _process_matches(
        self,
        matches: list[dict[str, Any]],
        finding_node: SecurityFindingNode,
        include_events: bool,
    ) -> None:
        """Process detection matches and add nodes/edges to the graph.

        Args:
            matches: List of match dictionaries
            finding_node: The security finding node to link events to
            include_events: Whether to create individual event nodes
        """
        for match in matches:
            event_time = self._parse_timestamp(match.get("time_dt"))

            # Create principal node
            principal = PrincipalNode.from_ocsf(match)
            if principal:
                principal.update_timestamps(event_time)
                self._graph.add_node(principal)

                # Link to finding
                edge = GraphEdge(
                    id=GraphEdge.create_id(EdgeType.RELATED_TO, principal.id, finding_node.id),
                    edge_type=EdgeType.RELATED_TO,
                    source_id=principal.id,
                    target_id=finding_node.id,
                    first_seen=event_time,
                    last_seen=event_time,
                )
                self._graph.add_edge(edge)

            # Create IP node
            ip_node = IPAddressNode.from_ocsf(match)
            if ip_node:
                ip_node.update_timestamps(event_time)
                self._graph.add_node(ip_node)

                # Link principal to IP
                if principal:
                    edge = GraphEdge(
                        id=GraphEdge.create_id(
                            EdgeType.AUTHENTICATED_FROM, principal.id, ip_node.id
                        ),
                        edge_type=EdgeType.AUTHENTICATED_FROM,
                        source_id=principal.id,
                        target_id=ip_node.id,
                        first_seen=event_time,
                        last_seen=event_time,
                    )
                    self._graph.add_edge(edge)

            # Create API operation node
            api_node = APIOperationNode.from_ocsf(match)
            if api_node:
                status = match.get("status", "Unknown")
                api_node.record_status(status)
                self._graph.add_node(api_node)

                # Link principal to API
                if principal:
                    edge = GraphEdge(
                        id=GraphEdge.create_id(EdgeType.CALLED_API, principal.id, api_node.id),
                        edge_type=EdgeType.CALLED_API,
                        source_id=principal.id,
                        target_id=api_node.id,
                        first_seen=event_time,
                        last_seen=event_time,
                    )
                    self._graph.add_edge(edge)

            # Create event node if requested
            if include_events:
                event_node = EventNode.from_ocsf(match)
                if event_node:
                    self._graph.add_node(event_node)

                    # Link event to finding
                    edge = GraphEdge(
                        id=GraphEdge.create_id(
                            EdgeType.TRIGGERED_BY, finding_node.id, event_node.id
                        ),
                        edge_type=EdgeType.TRIGGERED_BY,
                        source_id=finding_node.id,
                        target_id=event_node.id,
                        first_seen=event_time,
                        last_seen=event_time,
                    )
                    self._graph.add_edge(edge)

    def _enrich_by_user(
        self,
        user: str,
        start: datetime,
        end: datetime,
        limit: int,
        include_events: bool,
    ) -> None:
        """Enrich graph with events for a specific user.

        Args:
            user: The user name to enrich
            start: Start of time window
            end: End of time window
            limit: Maximum events to fetch
            include_events: Whether to include individual event nodes
        """
        try:
            df = self.enricher.enrich_by_user(user, start, end, limit=limit)
            if len(df) > 0:
                self._process_dataframe(df, include_events)
                logger.debug(
                    "enriched_by_user",
                    user=user,
                    events=len(df),
                )
        except Exception as e:
            logger.warning("enrich_by_user_failed", user=user, error=str(e))

    def _enrich_by_ip(
        self,
        ip: str,
        start: datetime,
        end: datetime,
        limit: int,
        include_events: bool,
    ) -> None:
        """Enrich graph with events for a specific IP.

        Args:
            ip: The IP address to enrich
            start: Start of time window
            end: End of time window
            limit: Maximum events to fetch
            include_events: Whether to include individual event nodes
        """
        try:
            df = self.enricher.enrich_by_ip(ip, start, end, limit=limit)
            if len(df) > 0:
                self._process_dataframe(df, include_events)
                logger.debug(
                    "enriched_by_ip",
                    ip=ip,
                    events=len(df),
                )
        except Exception as e:
            logger.warning("enrich_by_ip_failed", ip=ip, error=str(e))

    def _process_dataframe(
        self,
        df: QueryResult,
        include_events: bool,
    ) -> None:
        """Process a DataFrame of events and add to the graph.

        Args:
            df: DataFrame of events
            include_events: Whether to include individual event nodes
        """
        # Convert DataFrame to list of dicts for processing
        records = df.to_dicts()

        for record in records:
            event_time = self._parse_timestamp(record.get("time_dt"))

            # Create principal node
            principal = PrincipalNode.from_ocsf(record)
            if principal:
                principal.update_timestamps(event_time)
                self._graph.add_node(principal)

            # Create source IP node
            src_ip = IPAddressNode.from_ocsf(record, "src_endpoint.ip")
            if src_ip:
                src_ip.update_timestamps(event_time)
                self._graph.add_node(src_ip)

                # Link principal to IP
                if principal:
                    edge = GraphEdge(
                        id=GraphEdge.create_id(
                            EdgeType.AUTHENTICATED_FROM, principal.id, src_ip.id
                        ),
                        edge_type=EdgeType.AUTHENTICATED_FROM,
                        source_id=principal.id,
                        target_id=src_ip.id,
                        first_seen=event_time,
                        last_seen=event_time,
                    )
                    self._graph.add_edge(edge)

            # Create destination IP node (for network events)
            dst_ip = IPAddressNode.from_ocsf(record, "dst_endpoint.ip")
            if dst_ip and (not src_ip or dst_ip.id != src_ip.id):
                dst_ip.update_timestamps(event_time)
                self._graph.add_node(dst_ip)

                # Link source to destination
                if src_ip:
                    edge = GraphEdge(
                        id=GraphEdge.create_id(EdgeType.RELATED_TO, src_ip.id, dst_ip.id),
                        edge_type=EdgeType.RELATED_TO,
                        source_id=src_ip.id,
                        target_id=dst_ip.id,
                        first_seen=event_time,
                        last_seen=event_time,
                    )
                    self._graph.add_edge(edge)

            # Create API operation node
            api_node = APIOperationNode.from_ocsf(record)
            if api_node:
                status = record.get("status", "Unknown")
                api_node.record_status(status)
                self._graph.add_node(api_node)

                # Link principal to API
                if principal:
                    edge = GraphEdge(
                        id=GraphEdge.create_id(EdgeType.CALLED_API, principal.id, api_node.id),
                        edge_type=EdgeType.CALLED_API,
                        source_id=principal.id,
                        target_id=api_node.id,
                        first_seen=event_time,
                        last_seen=event_time,
                    )
                    self._graph.add_edge(edge)

            # Create event node if requested
            if include_events:
                event_node = EventNode.from_ocsf(record)
                if event_node:
                    self._graph.add_node(event_node)

                    if src_ip:
                        edge = GraphEdge(
                            id=GraphEdge.create_id(
                                EdgeType.ORIGINATED_FROM, event_node.id, src_ip.id
                            ),
                            edge_type=EdgeType.ORIGINATED_FROM,
                            source_id=event_node.id,
                            target_id=src_ip.id,
                            first_seen=event_time,
                            last_seen=event_time,
                        )
                        self._graph.add_edge(edge)

    def _parse_timestamp(self, value: datetime | str | None) -> datetime:
        """Parse a timestamp from various formats.

        Args:
            value: The timestamp value (string, datetime, or None)

        Returns:
            A datetime object
        """
        if value is None:
            return datetime.now(UTC)

        if isinstance(value, datetime):
            return value

        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass

        return datetime.now(UTC)

    def save_to_neptune(self) -> int:
        """Persist current graph to Neptune.

        Returns:
            Number of entities saved
        """
        if self.neptune:
            return self.neptune.save_graph(self._graph)
        return 0

    def get_graph(self) -> SecurityGraph:
        """Return the built graph.

        Returns:
            The current SecurityGraph
        """
        return self._graph

    def reset(self) -> None:
        """Reset the graph builder state."""
        self._graph = SecurityGraph()
