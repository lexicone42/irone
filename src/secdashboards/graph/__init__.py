"""Security investigation graph module.

This module provides tools for building, visualizing, and persisting
security investigation graphs using AWS Neptune.

Key Components:
- **Models**: Entity definitions (nodes, edges, graph container)
- **Builder**: Constructs graphs from detection results with enrichment
- **Visualization**: Interactive HTML graphs using pyvis
- **Connector**: Neptune database operations
- **Enrichment**: Security Lake query helpers for graph enrichment

Example usage:
    ```python
    from secdashboards.graph import (
        GraphBuilder,
        GraphVisualizer,
        NeptuneConnector,
        SecurityGraph,
    )

    # Build a graph from a detection result
    builder = GraphBuilder(security_lake_connector)
    graph = builder.build_from_detection(
        detection_result,
        enrichment_window_minutes=60,
    )

    # Visualize the graph
    visualizer = GraphVisualizer(height="700px")
    html = visualizer.to_html(graph)

    # Optionally persist to Neptune
    neptune = NeptuneConnector(
        endpoint="my-cluster.xxx.us-west-2.neptune.amazonaws.com",
    )
    neptune.save_graph(graph)
    ```
"""

from secdashboards.graph.builder import GraphBuilder
from secdashboards.graph.connector import NeptuneConnector
from secdashboards.graph.enrichment import SecurityLakeEnricher
from secdashboards.graph.models import (
    APIOperationNode,
    EdgeType,
    EventNode,
    GraphEdge,
    GraphNode,
    IPAddressNode,
    NodeType,
    PrincipalNode,
    ResourceNode,
    SecurityFindingNode,
    SecurityGraph,
)
from secdashboards.graph.persistence import InvestigationStore
from secdashboards.graph.queries import GremlinQueries, OpenCypherQueries
from secdashboards.graph.timeline import (
    EventTag,
    InvestigationTimeline,
    TimelineEvent,
    TimelineVisualizer,
    extract_timeline_from_graph,
    generate_timeline_summary_prompt,
)
from secdashboards.graph.visualization import (
    GraphVisualizer,
    create_investigation_visualization,
)

__all__ = [
    # Models - Node types
    "GraphNode",
    "PrincipalNode",
    "IPAddressNode",
    "ResourceNode",
    "APIOperationNode",
    "SecurityFindingNode",
    "EventNode",
    # Models - Edge and Graph
    "GraphEdge",
    "SecurityGraph",
    # Models - Enums
    "NodeType",
    "EdgeType",
    # Builder
    "GraphBuilder",
    # Enrichment
    "SecurityLakeEnricher",
    # Visualization
    "GraphVisualizer",
    "create_investigation_visualization",
    # Persistence
    "InvestigationStore",
    # Neptune
    "NeptuneConnector",
    "GremlinQueries",
    "OpenCypherQueries",
    # Timeline
    "TimelineEvent",
    "EventTag",
    "InvestigationTimeline",
    "TimelineVisualizer",
    "extract_timeline_from_graph",
    "generate_timeline_summary_prompt",
]
