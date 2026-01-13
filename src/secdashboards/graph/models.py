"""Entity models for security investigation graphs.

This module defines the node and edge types used to represent security events,
actors, and resources in a graph format for Neptune storage and visualization.
"""

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    import networkx as nx

    from secdashboards.detections.rule import DetectionResult


class NodeType(StrEnum):
    """Types of nodes in the security graph."""

    PRINCIPAL = "Principal"  # Users, roles, service accounts
    IP_ADDRESS = "IPAddress"  # Source/destination IPs
    RESOURCE = "Resource"  # AWS resources (S3, EC2, Lambda, etc.)
    API_OPERATION = "APIOperation"  # API calls made
    SECURITY_FINDING = "SecurityFinding"  # Alerts, findings
    EVENT = "Event"  # Individual OCSF events


class EdgeType(StrEnum):
    """Types of relationships between nodes."""

    AUTHENTICATED_FROM = "AUTHENTICATED_FROM"  # Principal -> IPAddress
    CALLED_API = "CALLED_API"  # Principal -> APIOperation
    ACCESSED_RESOURCE = "ACCESSED_RESOURCE"  # Principal -> Resource
    ORIGINATED_FROM = "ORIGINATED_FROM"  # Event -> IPAddress
    RELATED_TO = "RELATED_TO"  # Generic relationship
    TRIGGERED_BY = "TRIGGERED_BY"  # SecurityFinding -> Event
    PERFORMED_BY = "PERFORMED_BY"  # APIOperation -> Principal
    TARGETED = "TARGETED"  # APIOperation -> Resource


class GraphNode(BaseModel):
    """Base class for all graph nodes."""

    id: str = Field(..., description="Unique node identifier")
    node_type: NodeType
    label: str = Field(..., description="Display label")
    properties: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    event_count: int = 0

    def update_timestamps(self, event_time: datetime) -> None:
        """Update first_seen/last_seen based on an event timestamp."""
        if self.first_seen is None or event_time < self.first_seen:
            self.first_seen = event_time
        if self.last_seen is None or event_time > self.last_seen:
            self.last_seen = event_time
        self.event_count += 1


class PrincipalNode(GraphNode):
    """User, role, or service account."""

    node_type: NodeType = NodeType.PRINCIPAL
    user_name: str
    user_type: str | None = None  # Root, IAMUser, AssumedRole, FederatedUser, AWSService
    arn: str | None = None
    account_id: str | None = None

    @classmethod
    def create_id(cls, user_name: str) -> str:
        """Create consistent node ID for a principal."""
        return f"Principal:{user_name}"

    @classmethod
    def from_ocsf(cls, event: dict[str, Any]) -> "PrincipalNode | None":
        """Create a PrincipalNode from OCSF event data."""
        user_name = (
            event.get("actor.user.name")
            or event.get("user_name")
            or event.get("actor", {}).get("user", {}).get("name")
        )
        if not user_name:
            return None

        user_type = (
            event.get("actor.user.type")
            or event.get("user_type")
            or event.get("actor", {}).get("user", {}).get("type")
        )
        arn = event.get("actor.user.uid") or event.get("actor", {}).get("user", {}).get("uid")
        account_id = (
            event.get("actor.user.account_uid")
            or event.get("cloud.account.uid")
            or event.get("cloud", {}).get("account", {}).get("uid")
        )

        return cls(
            id=cls.create_id(user_name),
            label=user_name,
            user_name=user_name,
            user_type=user_type,
            arn=arn,
            account_id=account_id,
        )


class IPAddressNode(GraphNode):
    """IP address entity."""

    node_type: NodeType = NodeType.IP_ADDRESS
    ip_address: str
    is_internal: bool = False
    geo_country: str | None = None
    geo_city: str | None = None
    asn: str | None = None

    @classmethod
    def create_id(cls, ip_address: str) -> str:
        """Create consistent node ID for an IP address."""
        return f"IPAddress:{ip_address}"

    @classmethod
    def from_ocsf(
        cls, event: dict[str, Any], field: str = "src_endpoint.ip"
    ) -> "IPAddressNode | None":
        """Create an IPAddressNode from OCSF event data."""
        ip_address: str | None = None

        # First check if the exact field name exists (flattened format)
        if field in event:
            ip_address = event[field]
        # Then try to navigate nested structure
        elif "." in field:
            parts = field.split(".")
            value: Any = event
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = None
                    break
            if isinstance(value, str):
                ip_address = value
        else:
            ip_address = event.get(field)

        # Also check common flattened field names
        if not ip_address:
            ip_address = event.get("source_ip") or event.get("src_ip")

        if not ip_address:
            return None

        # Determine if IP is internal (RFC1918)
        is_internal = False
        if ip_address.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.")) or ip_address.startswith(("172.20.", "172.21.", "172.22.", "172.23.")) or ip_address.startswith(("172.24.", "172.25.", "172.26.", "172.27.")) or ip_address.startswith(("172.28.", "172.29.", "172.30.", "172.31.")) or ip_address.startswith("192.168."):
            is_internal = True

        return cls(
            id=cls.create_id(ip_address),
            label=ip_address,
            ip_address=ip_address,
            is_internal=is_internal,
        )


class ResourceNode(GraphNode):
    """AWS resource entity."""

    node_type: NodeType = NodeType.RESOURCE
    resource_type: str  # s3_bucket, ec2_instance, lambda_function, etc.
    resource_id: str
    arn: str | None = None
    region: str | None = None
    account_id: str | None = None

    @classmethod
    def create_id(cls, resource_type: str, resource_id: str) -> str:
        """Create consistent node ID for a resource."""
        return f"Resource:{resource_type}:{resource_id}"

    @classmethod
    def from_arn(cls, arn: str) -> "ResourceNode | None":
        """Create a ResourceNode from an ARN."""
        if not arn or not arn.startswith("arn:"):
            return None

        parts = arn.split(":")
        if len(parts) < 6:
            return None

        # arn:partition:service:region:account:resource
        service = parts[2]
        region = parts[3] or None
        account_id = parts[4] or None
        resource_part = ":".join(parts[5:])

        # Determine resource type and ID from the resource part
        if "/" in resource_part:
            resource_type, resource_id = resource_part.split("/", 1)
        else:
            resource_type = service
            resource_id = resource_part

        return cls(
            id=cls.create_id(resource_type, resource_id),
            label=resource_id[:30] + "..." if len(resource_id) > 30 else resource_id,
            resource_type=resource_type,
            resource_id=resource_id,
            arn=arn,
            region=region,
            account_id=account_id,
        )


class APIOperationNode(GraphNode):
    """API operation performed."""

    node_type: NodeType = NodeType.API_OPERATION
    operation: str
    service: str
    success_count: int = 0
    failure_count: int = 0

    @classmethod
    def create_id(cls, service: str, operation: str) -> str:
        """Create consistent node ID for an API operation."""
        return f"APIOperation:{service}:{operation}"

    @classmethod
    def from_ocsf(cls, event: dict[str, Any]) -> "APIOperationNode | None":
        """Create an APIOperationNode from OCSF event data."""
        operation = (
            event.get("api.operation")
            or event.get("operation")
            or event.get("api", {}).get("operation")
        )
        service = (
            event.get("api.service.name")
            or event.get("service")
            or event.get("api", {}).get("service", {}).get("name")
        )

        if not operation or not service:
            return None

        # Normalize service name (remove .amazonaws.com suffix)
        if service.endswith(".amazonaws.com"):
            service = service.replace(".amazonaws.com", "")

        return cls(
            id=cls.create_id(service, operation),
            label=f"{service}:{operation}",
            operation=operation,
            service=service,
        )

    def record_status(self, status: str) -> None:
        """Record a success or failure for this operation."""
        if status.lower() in ("success", "succeeded", "ok"):
            self.success_count += 1
        else:
            self.failure_count += 1


class SecurityFindingNode(GraphNode):
    """Security detection or finding."""

    node_type: NodeType = NodeType.SECURITY_FINDING
    rule_id: str
    rule_name: str
    severity: str
    triggered_at: datetime
    match_count: int = 0
    investigation_status: str = "open"  # open, investigating, resolved

    @classmethod
    def create_id(cls, rule_id: str, triggered_at: datetime) -> str:
        """Create consistent node ID for a security finding."""
        ts = triggered_at.strftime("%Y%m%d%H%M%S")
        return f"Finding:{rule_id}:{ts}"

    @classmethod
    def from_detection_result(
        cls, result: "DetectionResult"  # noqa: F821 - imported at runtime
    ) -> "SecurityFindingNode":
        """Create a SecurityFindingNode from a DetectionResult."""
        return cls(
            id=cls.create_id(result.rule_id, result.executed_at),
            label=result.rule_name,
            rule_id=result.rule_id,
            rule_name=result.rule_name,
            severity=result.severity,
            triggered_at=result.executed_at,
            match_count=result.match_count,
        )


class EventNode(GraphNode):
    """Individual security event."""

    node_type: NodeType = NodeType.EVENT
    event_uid: str
    class_uid: int
    class_name: str
    timestamp: datetime
    status: str | None = None
    region: str | None = None
    raw_event: dict[str, Any] | None = None

    @classmethod
    def create_id(cls, event_uid: str) -> str:
        """Create consistent node ID for an event."""
        return f"Event:{event_uid}"

    @classmethod
    def from_ocsf(cls, event: dict[str, Any]) -> "EventNode | None":
        """Create an EventNode from OCSF event data."""
        event_uid = event.get("metadata.uid") or event.get("uid") or event.get("event_uid")
        if not event_uid:
            # Generate a synthetic UID from key fields
            import hashlib

            key_data = f"{event.get('time_dt', '')}-{event.get('class_uid', '')}"
            event_uid = hashlib.sha256(key_data.encode()).hexdigest()[:16]

        class_uid = event.get("class_uid", 0)
        if isinstance(class_uid, str):
            class_uid = int(class_uid)

        class_name = event.get("class_name", "Unknown")
        timestamp = event.get("time_dt")
        if isinstance(timestamp, str):
            from datetime import datetime as dt

            try:
                timestamp = dt.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                timestamp = dt.now()
        elif timestamp is None:
            from datetime import datetime as dt

            timestamp = dt.now()

        return cls(
            id=cls.create_id(event_uid),
            label=f"{class_name}:{event_uid[:8]}",
            event_uid=event_uid,
            class_uid=class_uid,
            class_name=class_name,
            timestamp=timestamp,
            status=event.get("status"),
            region=event.get("cloud.region") or event.get("region"),
        )


class GraphEdge(BaseModel):
    """Relationship between two nodes."""

    id: str
    edge_type: EdgeType
    source_id: str
    target_id: str
    properties: dict[str, Any] = Field(default_factory=dict)
    weight: float = 1.0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    event_count: int = 1

    @classmethod
    def create_id(cls, edge_type: EdgeType, source_id: str, target_id: str) -> str:
        """Create consistent edge ID."""
        return f"{edge_type.value}:{source_id}->{target_id}"

    def update_timestamps(self, event_time: datetime) -> None:
        """Update first_seen/last_seen based on an event timestamp."""
        if self.first_seen is None or event_time < self.first_seen:
            self.first_seen = event_time
        if self.last_seen is None or event_time > self.last_seen:
            self.last_seen = event_time
        self.event_count += 1


class SecurityGraph(BaseModel):
    """Container for the complete security investigation graph."""

    nodes: dict[str, GraphNode] = Field(default_factory=dict)
    edges: list[GraphEdge] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True}

    # Private instance variable for edge lookup (not a Pydantic field)
    _edge_index: dict[str, GraphEdge]

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        # Build edge index for fast lookup - using object.__setattr__ to bypass Pydantic
        object.__setattr__(self, "_edge_index", {edge.id: edge for edge in self.edges})

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the graph, merging if it already exists."""
        existing = self.nodes.get(node.id)
        if existing:
            # Merge: update timestamps and event count
            if node.first_seen:
                existing.update_timestamps(node.first_seen)
            if node.last_seen:
                existing.update_timestamps(node.last_seen)
        else:
            self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Add an edge to the graph, merging if it already exists."""
        existing = self._edge_index.get(edge.id)
        if existing:
            # Merge: update timestamps and event count
            if edge.first_seen:
                existing.update_timestamps(edge.first_seen)
            if edge.last_seen:
                existing.update_timestamps(edge.last_seen)
        else:
            self.edges.append(edge)
            self._edge_index[edge.id] = edge

    def get_node(self, node_id: str) -> GraphNode | None:
        """Get a node by ID."""
        return self.nodes.get(node_id)

    def get_edge(self, edge_id: str) -> GraphEdge | None:
        """Get an edge by ID."""
        return self._edge_index.get(edge_id)

    def get_neighbors(self, node_id: str, direction: str = "both") -> list[GraphNode]:
        """Get all nodes connected to the specified node.

        Args:
            node_id: The ID of the center node
            direction: "outgoing", "incoming", or "both"

        Returns:
            List of connected nodes
        """
        neighbor_ids: set[str] = set()

        for edge in self.edges:
            if direction in ("outgoing", "both") and edge.source_id == node_id:
                neighbor_ids.add(edge.target_id)
            if direction in ("incoming", "both") and edge.target_id == node_id:
                neighbor_ids.add(edge.source_id)

        return [self.nodes[nid] for nid in neighbor_ids if nid in self.nodes]

    def get_edges_for_node(
        self, node_id: str, direction: str = "both"
    ) -> list[GraphEdge]:
        """Get all edges connected to a node.

        Args:
            node_id: The ID of the node
            direction: "outgoing", "incoming", or "both"

        Returns:
            List of connected edges
        """
        result = []
        for edge in self.edges:
            if direction in ("outgoing", "both") and edge.source_id == node_id:
                result.append(edge)
            if direction in ("incoming", "both") and edge.target_id == node_id:
                result.append(edge)
        return result

    def get_nodes_by_type(self, node_type: NodeType) -> list[GraphNode]:
        """Get all nodes of a specific type."""
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def node_count(self) -> int:
        """Get the total number of nodes."""
        return len(self.nodes)

    def edge_count(self) -> int:
        """Get the total number of edges."""
        return len(self.edges)

    def to_networkx(self) -> "nx.DiGraph":  # noqa: F821
        """Convert to a NetworkX DiGraph for analysis."""
        import networkx as nx

        G = nx.DiGraph()

        # Add nodes with attributes
        for node_id, node in self.nodes.items():
            G.add_node(
                node_id,
                node_type=node.node_type.value,
                label=node.label,
                event_count=node.event_count,
                **node.properties,
            )

        # Add edges with attributes
        for edge in self.edges:
            G.add_edge(
                edge.source_id,
                edge.target_id,
                edge_type=edge.edge_type.value,
                weight=edge.weight,
                event_count=edge.event_count,
                **edge.properties,
            )

        return G

    def summary(self) -> dict[str, Any]:
        """Get a summary of the graph contents."""
        node_counts: dict[str, int] = {}
        for node in self.nodes.values():
            node_type = node.node_type.value
            node_counts[node_type] = node_counts.get(node_type, 0) + 1

        edge_counts: dict[str, int] = {}
        for edge in self.edges:
            edge_type = edge.edge_type.value
            edge_counts[edge_type] = edge_counts.get(edge_type, 0) + 1

        return {
            "total_nodes": self.node_count(),
            "total_edges": self.edge_count(),
            "nodes_by_type": node_counts,
            "edges_by_type": edge_counts,
            "metadata": self.metadata,
        }
