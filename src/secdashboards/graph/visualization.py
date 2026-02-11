"""Graph visualization using pyvis.

This module provides the GraphVisualizer class for creating interactive
HTML visualizations of security investigation graphs.
"""

from pathlib import Path
from typing import Any

from pyvis.network import Network

from secdashboards.graph.models import EdgeType, NodeType, SecurityGraph

# Color scheme for node types
NODE_COLORS: dict[NodeType, str] = {
    NodeType.PRINCIPAL: "#FF6B6B",  # Red - users/roles
    NodeType.IP_ADDRESS: "#4ECDC4",  # Teal - network
    NodeType.RESOURCE: "#45B7D1",  # Blue - resources
    NodeType.API_OPERATION: "#96CEB4",  # Green - operations
    NodeType.SECURITY_FINDING: "#FF4757",  # Bright red - alerts
    NodeType.EVENT: "#A8A8A8",  # Gray - events
}

# Color scheme for edge types
EDGE_COLORS: dict[EdgeType, str] = {
    EdgeType.AUTHENTICATED_FROM: "#FF6B6B",
    EdgeType.CALLED_API: "#96CEB4",
    EdgeType.ACCESSED_RESOURCE: "#45B7D1",
    EdgeType.ORIGINATED_FROM: "#4ECDC4",
    EdgeType.RELATED_TO: "#888888",
    EdgeType.TRIGGERED_BY: "#FF4757",
    EdgeType.PERFORMED_BY: "#FF6B6B",
    EdgeType.TARGETED: "#45B7D1",
}

# Shape for node types
NODE_SHAPES: dict[NodeType, str] = {
    NodeType.PRINCIPAL: "dot",
    NodeType.IP_ADDRESS: "diamond",
    NodeType.RESOURCE: "square",
    NodeType.API_OPERATION: "triangle",
    NodeType.SECURITY_FINDING: "star",
    NodeType.EVENT: "dot",
}

# Icons for node types (Font Awesome)
NODE_ICONS: dict[NodeType, str] = {
    NodeType.PRINCIPAL: "fa-user",
    NodeType.IP_ADDRESS: "fa-network-wired",
    NodeType.RESOURCE: "fa-cube",
    NodeType.API_OPERATION: "fa-cog",
    NodeType.SECURITY_FINDING: "fa-exclamation-triangle",
    NodeType.EVENT: "fa-circle",
}


class GraphVisualizer:
    """Generate interactive visualizations from security graphs.

    This class uses pyvis to create interactive HTML graph visualizations
    that can be displayed in Marimo notebooks or exported as standalone
    HTML files.

    Example usage:
        ```python
        visualizer = GraphVisualizer(height="700px")
        graph = builder.build_from_detection(result)

        # Generate HTML
        html = visualizer.to_html(graph)

        # Or display in Marimo
        display = visualizer.display_in_marimo(graph)
        ```
    """

    def __init__(
        self,
        height: str = "600px",
        width: str = "100%",
        bgcolor: str = "#ffffff",
        font_color: str = "#333333",
    ) -> None:
        """Initialize the visualizer.

        Args:
            height: Height of the visualization
            width: Width of the visualization
            bgcolor: Background color
            font_color: Font color for labels
        """
        self.height = height
        self.width = width
        self.bgcolor = bgcolor
        self.font_color = font_color

    def create_network(
        self,
        graph: SecurityGraph,
        notebook: bool = True,
        physics: bool = True,
        show_labels: bool = True,
        hierarchical: bool = False,
    ) -> Network:
        """Create a pyvis Network from a SecurityGraph.

        Args:
            graph: The SecurityGraph to visualize
            notebook: Whether running in a notebook context
            physics: Enable physics simulation
            show_labels: Show node labels
            hierarchical: Use hierarchical layout

        Returns:
            A configured pyvis Network
        """
        net = Network(
            height=self.height,
            width=self.width,
            bgcolor=self.bgcolor,
            font_color=self.font_color,
            notebook=notebook,
            directed=True,
            cdn_resources="remote",
        )

        # Configure physics
        if physics:
            net.barnes_hut(
                gravity=-80000,
                central_gravity=0.3,
                spring_length=200,
                spring_strength=0.001,
                damping=0.09,
            )
        else:
            net.toggle_physics(False)

        # Configure hierarchical layout if requested
        if hierarchical:
            net.set_options("""
            {
                "layout": {
                    "hierarchical": {
                        "enabled": true,
                        "direction": "UD",
                        "sortMethod": "directed"
                    }
                }
            }
            """)

        # Add nodes
        for node_id, node in graph.nodes.items():
            net.add_node(
                node_id,
                label=node.label if show_labels else "",
                title=self._build_tooltip(node),
                color=NODE_COLORS.get(node.node_type, "#888888"),
                size=self._calculate_node_size(node),
                shape=NODE_SHAPES.get(node.node_type, "dot"),
                borderWidth=2,
                borderWidthSelected=4,
            )

        # Add edges
        for edge in graph.edges:
            net.add_edge(
                edge.source_id,
                edge.target_id,
                title=self._build_edge_tooltip(edge),
                color=EDGE_COLORS.get(edge.edge_type, "#888888"),
                width=self._calculate_edge_width(edge),
                arrows="to",
                smooth={"type": "curvedCW", "roundness": 0.2},
            )

        return net

    def _build_tooltip(self, node: Any) -> str:
        """Build HTML tooltip for node hover.

        Args:
            node: The graph node

        Returns:
            HTML string for tooltip
        """
        lines = [
            f"<b>{node.node_type.value}</b>",
            f"<b>ID:</b> {node.id}",
            f"<b>Label:</b> {node.label}",
        ]

        if node.event_count > 0:
            lines.append(f"<b>Events:</b> {node.event_count}")

        if node.first_seen:
            lines.append(f"<b>First seen:</b> {node.first_seen.isoformat()}")

        if node.last_seen:
            lines.append(f"<b>Last seen:</b> {node.last_seen.isoformat()}")

        # Add type-specific fields
        if node.node_type == NodeType.PRINCIPAL:
            if hasattr(node, "user_type") and node.user_type:
                lines.append(f"<b>User type:</b> {node.user_type}")
            if hasattr(node, "account_id") and node.account_id:
                lines.append(f"<b>Account:</b> {node.account_id}")

        elif node.node_type == NodeType.IP_ADDRESS:
            if hasattr(node, "is_internal"):
                lines.append(f"<b>Internal:</b> {node.is_internal}")
            if hasattr(node, "geo_country") and node.geo_country:
                lines.append(f"<b>Country:</b> {node.geo_country}")

        elif node.node_type == NodeType.API_OPERATION:
            if hasattr(node, "service"):
                lines.append(f"<b>Service:</b> {node.service}")
            if hasattr(node, "success_count"):
                lines.append(f"<b>Success:</b> {node.success_count}")
            if hasattr(node, "failure_count"):
                lines.append(f"<b>Failures:</b> {node.failure_count}")

        elif node.node_type == NodeType.SECURITY_FINDING:
            if hasattr(node, "severity"):
                lines.append(f"<b>Severity:</b> {node.severity}")
            if hasattr(node, "match_count"):
                lines.append(f"<b>Matches:</b> {node.match_count}")

        elif node.node_type == NodeType.RESOURCE:
            if hasattr(node, "resource_type"):
                lines.append(f"<b>Type:</b> {node.resource_type}")
            if hasattr(node, "region") and node.region:
                lines.append(f"<b>Region:</b> {node.region}")

        return "<br>".join(lines)

    def _build_edge_tooltip(self, edge: Any) -> str:
        """Build tooltip for edge hover.

        Args:
            edge: The graph edge

        Returns:
            HTML string for tooltip
        """
        lines = [
            f"<b>{edge.edge_type.value}</b>",
            f"<b>Events:</b> {edge.event_count}",
        ]

        if edge.first_seen:
            lines.append(f"<b>First:</b> {edge.first_seen.isoformat()}")
        if edge.last_seen:
            lines.append(f"<b>Last:</b> {edge.last_seen.isoformat()}")

        return "<br>".join(lines)

    def _calculate_node_size(self, node: Any) -> int:
        """Calculate node size based on event count.

        Args:
            node: The graph node

        Returns:
            Node size in pixels
        """
        base_size = 20

        # Security findings are always larger
        if node.node_type == NodeType.SECURITY_FINDING:
            return 40

        # Scale by event count
        if node.event_count > 0:
            return min(base_size + node.event_count // 5, 60)

        return base_size

    def _calculate_edge_width(self, edge: Any) -> int:
        """Calculate edge width based on event count.

        Args:
            edge: The graph edge

        Returns:
            Edge width in pixels
        """
        base_width = 1
        return min(base_width + edge.event_count // 10, 5)

    def to_html(
        self,
        graph: SecurityGraph,
        filename: str | Path | None = None,
        notebook: bool = True,
        physics: bool = True,
    ) -> str:
        """Generate HTML for the graph visualization.

        Args:
            graph: The SecurityGraph to visualize
            filename: Optional file path to save the HTML
            notebook: Whether running in notebook context
            physics: Enable physics simulation

        Returns:
            HTML string of the visualization
        """
        net = self.create_network(graph, notebook=notebook, physics=physics)

        if filename:
            path = Path(filename)
            net.save_graph(str(path))
            return str(path)

        # Generate HTML without saving to file
        return net.generate_html()

    def display_in_marimo(
        self,
        graph: SecurityGraph,
        physics: bool = True,
    ) -> Any:
        """Generate Marimo-compatible HTML display.

        Args:
            graph: The SecurityGraph to visualize
            physics: Enable physics simulation

        Returns:
            A Marimo Html object
        """
        try:
            import marimo as mo

            html_content = self.to_html(graph, notebook=True, physics=physics)
            return mo.Html(html_content)
        except ImportError:
            # If marimo not available, return raw HTML
            return self.to_html(graph, notebook=False, physics=physics)

    def generate_legend_html(self) -> str:
        """Generate HTML for a graph legend.

        Returns:
            HTML string for the legend
        """
        legend_items = []

        for node_type in NodeType:
            color = NODE_COLORS.get(node_type, "#888888")
            shape = NODE_SHAPES.get(node_type, "dot")
            legend_items.append(
                f'<div style="display: flex; align-items: center; margin: 5px;">'
                f'<div style="width: 20px; height: 20px; background-color: {color}; '
                f'border-radius: {"50%" if shape == "dot" else "0"}; margin-right: 10px;"></div>'
                f"<span>{node_type.value}</span>"
                f"</div>"
            )

        return f"""
        <div style="border: 1px solid #ccc; padding: 10px; background: white; border-radius: 5px;">
            <h4 style="margin: 0 0 10px 0;">Legend</h4>
            {"".join(legend_items)}
        </div>
        """

    def generate_summary_html(self, graph: SecurityGraph) -> str:
        """Generate HTML summary of the graph.

        Args:
            graph: The SecurityGraph to summarize

        Returns:
            HTML string with graph summary
        """
        summary = graph.summary()

        nodes_html = ""
        for node_type, count in summary["nodes_by_type"].items():
            color = NODE_COLORS.get(NodeType(node_type), "#888888")
            nodes_html += f'<li style="color: {color};">{node_type}: {count}</li>'

        edges_html = ""
        for edge_type, count in summary["edges_by_type"].items():
            edges_html += f"<li>{edge_type}: {count}</li>"

        return f"""
        <div style="border: 1px solid #ccc; padding: 15px; background: white; border-radius: 5px;">
            <h4 style="margin: 0 0 10px 0;">Graph Summary</h4>
            <p><b>Total Nodes:</b> {summary["total_nodes"]}</p>
            <p><b>Total Edges:</b> {summary["total_edges"]}</p>

            <h5>Nodes by Type:</h5>
            <ul style="margin: 0; padding-left: 20px;">
                {nodes_html}
            </ul>

            <h5>Edges by Type:</h5>
            <ul style="margin: 0; padding-left: 20px;">
                {edges_html}
            </ul>
        </div>
        """


def create_investigation_visualization(
    graph: SecurityGraph,
    height: str = "700px",
    show_legend: bool = True,
    show_summary: bool = True,
) -> str:
    """Create a complete investigation visualization with legend and summary.

    Args:
        graph: The SecurityGraph to visualize
        height: Height of the graph visualization
        show_legend: Include the legend
        show_summary: Include the summary

    Returns:
        Complete HTML string
    """
    visualizer = GraphVisualizer(height=height)

    graph_html = visualizer.to_html(graph, notebook=False)
    legend_html = visualizer.generate_legend_html() if show_legend else ""
    summary_html = visualizer.generate_summary_html(graph) if show_summary else ""

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Investigation Graph</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .container {{ display: flex; gap: 20px; }}
            .sidebar {{ width: 250px; }}
            .graph-container {{ flex: 1; }}
        </style>
    </head>
    <body>
        <h1>Security Investigation Graph</h1>
        <div class="container">
            <div class="sidebar">
                {legend_html}
                <br>
                {summary_html}
            </div>
            <div class="graph-container">
                {graph_html}
            </div>
        </div>
    </body>
    </html>
    """
