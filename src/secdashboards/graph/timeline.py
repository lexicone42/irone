"""Timeline visualization for security investigations.

Provides interactive timeline visualization with event tagging
and AI-generated summaries for incident investigation workflows.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from secdashboards.graph.connector import NeptuneConnector
    from secdashboards.graph.models import SecurityGraph


class EventTag(StrEnum):
    """Tags for categorizing timeline events during investigation."""

    UNREVIEWED = "unreviewed"
    IMPORTANT = "important"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    ATTACK_PHASE = "attack_phase"
    INITIAL_ACCESS = "initial_access"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    IMPACT = "impact"


# Color mapping for event tags
TAG_COLORS = {
    EventTag.UNREVIEWED: "#A0A0A0",  # Gray
    EventTag.IMPORTANT: "#FFD700",  # Gold
    EventTag.SUSPICIOUS: "#FF6B6B",  # Red
    EventTag.BENIGN: "#4ECDC4",  # Teal
    EventTag.ATTACK_PHASE: "#FF4757",  # Bright red
    EventTag.INITIAL_ACCESS: "#FF6348",  # Orange-red
    EventTag.PERSISTENCE: "#9B59B6",  # Purple
    EventTag.PRIVILEGE_ESCALATION: "#E74C3C",  # Dark red
    EventTag.LATERAL_MOVEMENT: "#F39C12",  # Orange
    EventTag.DATA_EXFILTRATION: "#C0392B",  # Crimson
    EventTag.IMPACT: "#8E44AD",  # Dark purple
}


class TimelineEvent(BaseModel):
    """A single event in the investigation timeline."""

    id: str = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(..., description="When the event occurred")
    title: str = Field(..., description="Short event description")
    description: str = Field(default="", description="Detailed event description")
    entity_type: str = Field(..., description="Type of entity (Principal, IP, etc.)")
    entity_id: str = Field(..., description="ID of the related entity")
    operation: str = Field(default="", description="API operation or action")
    status: str = Field(default="success", description="Event status")
    tag: EventTag = Field(default=EventTag.UNREVIEWED, description="Investigation tag")
    notes: str = Field(default="", description="Analyst notes")
    properties: dict[str, Any] = Field(default_factory=dict, description="Additional properties")

    @property
    def color(self) -> str:
        """Get the display color based on tag."""
        return TAG_COLORS.get(self.tag, "#A0A0A0")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "title": self.title,
            "description": self.description,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "operation": self.operation,
            "status": self.status,
            "tag": self.tag.value,
            "notes": self.notes,
            "properties": self.properties,
        }


class InvestigationTimeline(BaseModel):
    """Container for investigation timeline events with tagging support."""

    investigation_id: str = Field(default="", description="Investigation identifier")
    events: list[TimelineEvent] = Field(default_factory=list)
    ai_summary: str = Field(default="", description="AI-generated timeline summary")
    analyst_summary: str = Field(default="", description="Analyst-edited summary")
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

    def add_event(self, event: TimelineEvent) -> None:
        """Add an event to the timeline."""
        self.events.append(event)
        self.events.sort(key=lambda e: e.timestamp)
        self.updated_at = datetime.now()

    def tag_event(self, event_id: str, tag: EventTag, notes: str = "") -> bool:
        """Tag an event with a category and optional notes."""
        for event in self.events:
            if event.id == event_id:
                event.tag = tag
                if notes:
                    event.notes = notes
                self.updated_at = datetime.now()
                return True
        return False

    def get_events_by_tag(self, tag: EventTag) -> list[TimelineEvent]:
        """Get all events with a specific tag."""
        return [e for e in self.events if e.tag == tag]

    def get_unreviewed_events(self) -> list[TimelineEvent]:
        """Get all events that haven't been reviewed yet."""
        return self.get_events_by_tag(EventTag.UNREVIEWED)

    def get_suspicious_events(self) -> list[TimelineEvent]:
        """Get all events tagged as suspicious or attack-related."""
        suspicious_tags = {
            EventTag.SUSPICIOUS,
            EventTag.ATTACK_PHASE,
            EventTag.INITIAL_ACCESS,
            EventTag.PERSISTENCE,
            EventTag.PRIVILEGE_ESCALATION,
            EventTag.LATERAL_MOVEMENT,
            EventTag.DATA_EXFILTRATION,
            EventTag.IMPACT,
        }
        return [e for e in self.events if e.tag in suspicious_tags]

    def get_time_range(self) -> tuple[datetime | None, datetime | None]:
        """Get the time range of events in the timeline."""
        if not self.events:
            return None, None
        return self.events[0].timestamp, self.events[-1].timestamp

    def summary(self) -> dict[str, Any]:
        """Get a summary of the timeline."""
        tag_counts: dict[str, int] = {}
        for event in self.events:
            tag_counts[event.tag.value] = tag_counts.get(event.tag.value, 0) + 1

        start, end = self.get_time_range()
        duration = None
        if start and end:
            duration = (end - start).total_seconds()

        return {
            "total_events": len(self.events),
            "tag_counts": tag_counts,
            "time_range": {
                "start": start.isoformat() if start else None,
                "end": end.isoformat() if end else None,
                "duration_seconds": duration,
            },
            "has_ai_summary": bool(self.ai_summary),
            "has_analyst_summary": bool(self.analyst_summary),
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert timeline to dictionary for export."""
        return {
            "investigation_id": self.investigation_id,
            "events": [e.to_dict() for e in self.events],
            "ai_summary": self.ai_summary,
            "analyst_summary": self.analyst_summary,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "summary": self.summary(),
        }


def extract_timeline_from_graph(
    graph: SecurityGraph,
    include_nodes: bool = True,
    include_edges: bool = True,
) -> InvestigationTimeline:
    """Extract a timeline from a SecurityGraph.

    Converts graph nodes and edges with timestamps into timeline events.

    Args:
        graph: The security graph to extract timeline from
        include_nodes: Include node creation events
        include_edges: Include edge/relationship events

    Returns:
        InvestigationTimeline populated with events from the graph
    """
    from secdashboards.graph.models import NodeType

    timeline = InvestigationTimeline(investigation_id=graph.metadata.get("investigation_id", ""))

    # Map node types to entity descriptions
    type_descriptions = {
        NodeType.PRINCIPAL: "User/Role activity",
        NodeType.IP_ADDRESS: "Network activity",
        NodeType.RESOURCE: "Resource access",
        NodeType.API_OPERATION: "API call",
        NodeType.SECURITY_FINDING: "Security alert",
        NodeType.EVENT: "Security event",
    }

    if include_nodes:
        for node in graph.nodes.values():
            # Use first_seen or last_seen as event timestamp
            timestamp = node.first_seen or node.last_seen
            if not timestamp:
                continue

            # Determine operation based on node type
            operation = ""
            if node.node_type == NodeType.API_OPERATION:
                operation = node.properties.get("operation", node.label)
            elif node.node_type == NodeType.SECURITY_FINDING:
                operation = node.properties.get("rule_id", "detection")

            # Create title based on node type
            type_desc = type_descriptions.get(node.node_type, "Activity")
            title = f"{type_desc}: {node.label}"

            # Build description
            description_parts = []
            if node.node_type == NodeType.PRINCIPAL:
                if user_type := node.properties.get("user_type"):
                    description_parts.append(f"Type: {user_type}")
                if account := node.properties.get("account_id"):
                    description_parts.append(f"Account: {account}")
            elif node.node_type == NodeType.IP_ADDRESS:
                if is_internal := node.properties.get("is_internal"):
                    description_parts.append("Internal IP" if is_internal else "External IP")
                if geo := node.properties.get("geo_location"):
                    description_parts.append(f"Location: {geo}")
            elif node.node_type == NodeType.API_OPERATION:
                if success := node.properties.get("success_count"):
                    description_parts.append(f"Success: {success}")
                if failure := node.properties.get("failure_count"):
                    description_parts.append(f"Failures: {failure}")
            elif node.node_type == NodeType.RESOURCE:
                if resource_type := node.properties.get("resource_type"):
                    description_parts.append(f"Type: {resource_type}")
                if region := node.properties.get("region"):
                    description_parts.append(f"Region: {region}")
            elif node.node_type == NodeType.SECURITY_FINDING:
                if severity := node.properties.get("severity"):
                    description_parts.append(f"Severity: {severity}")
                if desc := node.properties.get("description"):
                    description_parts.append(desc)

            if node.event_count > 1:
                description_parts.append(f"Event count: {node.event_count}")

            event = TimelineEvent(
                id=f"node:{node.id}",
                timestamp=timestamp,
                title=title,
                description=" | ".join(description_parts) if description_parts else "",
                entity_type=node.node_type.value,
                entity_id=node.id,
                operation=operation,
                status="success",
                properties=node.properties,
            )

            # Auto-tag security findings
            if node.node_type == NodeType.SECURITY_FINDING:
                # Check model attribute first, then properties dict
                severity = getattr(node, "severity", None) or node.properties.get("severity", "")
                severity = severity.lower() if severity else ""
                if severity in ("critical", "high"):
                    event.tag = EventTag.SUSPICIOUS
                else:
                    event.tag = EventTag.IMPORTANT

            timeline.add_event(event)

    if include_edges:
        for edge in graph.edges:
            timestamp = edge.first_seen or edge.last_seen
            if not timestamp:
                continue

            # Create meaningful edge event descriptions
            source_node = graph.get_node(edge.source_id)
            target_node = graph.get_node(edge.target_id)

            source_label = source_node.label if source_node else edge.source_id
            target_label = target_node.label if target_node else edge.target_id

            title = f"{edge.edge_type.value}: {source_label} -> {target_label}"
            description = ""
            if edge.event_count > 1:
                description = f"Occurred {edge.event_count} times"

            event = TimelineEvent(
                id=f"edge:{edge.id}",
                timestamp=timestamp,
                title=title,
                description=description,
                entity_type="relationship",
                entity_id=edge.id,
                operation=edge.edge_type.value,
                status="success",
                properties=edge.properties,
            )
            timeline.add_event(event)

    return timeline


class TimelineVisualizer:
    """Generate interactive timeline visualizations using Plotly."""

    def __init__(self, height: str = "500px", width: str = "100%") -> None:
        """Initialize the visualizer.

        Args:
            height: Height of the timeline chart
            width: Width of the timeline chart
        """
        self.height = height
        self.width = width

    def create_plotly_figure(self, timeline: InvestigationTimeline) -> Any:
        """Create a Plotly figure for the timeline.

        Args:
            timeline: The investigation timeline to visualize

        Returns:
            Plotly figure object
        """
        import plotly.graph_objects as go

        if not timeline.events:
            # Return empty figure with message
            fig = go.Figure()
            fig.add_annotation(
                text="No events to display",
                xref="paper",
                yref="paper",
                x=0.5,
                y=0.5,
                showarrow=False,
                font={"size": 16},
            )
            fig.update_layout(
                height=int(self.height.replace("px", "")),
                showlegend=False,
            )
            return fig

        # Prepare data for plotting
        timestamps = [e.timestamp for e in timeline.events]
        colors = [e.color for e in timeline.events]
        hover_texts = []
        y_positions = []

        # Assign y positions based on entity type for visual separation
        entity_type_positions = {
            "Principal": 0,
            "IPAddress": 1,
            "APIOperation": 2,
            "Resource": 3,
            "SecurityFinding": 4,
            "Event": 5,
            "relationship": 6,
        }

        for event in timeline.events:
            y_pos = entity_type_positions.get(event.entity_type, 7)
            y_positions.append(y_pos)

            hover_text = (
                f"<b>{event.title}</b><br>"
                f"Time: {event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}<br>"
                f"Type: {event.entity_type}<br>"
                f"Tag: {event.tag.value}<br>"
            )
            if event.description:
                hover_text += f"Details: {event.description}<br>"
            if event.notes:
                hover_text += f"Notes: {event.notes}"
            hover_texts.append(hover_text)

        # Create the scatter plot
        fig = go.Figure()

        # Add events as scatter points
        fig.add_trace(
            go.Scatter(
                x=timestamps,
                y=y_positions,
                mode="markers",
                marker={
                    "size": 14,
                    "color": colors,
                    "line": {"width": 2, "color": "white"},
                    "symbol": "circle",
                },
                text=hover_texts,
                hoverinfo="text",
                name="Events",
            )
        )

        # Add connecting lines between consecutive events (faint)
        fig.add_trace(
            go.Scatter(
                x=timestamps,
                y=y_positions,
                mode="lines",
                line={"color": "rgba(150, 150, 150, 0.3)", "width": 1},
                hoverinfo="skip",
                showlegend=False,
            )
        )

        # Update layout
        y_labels = list(entity_type_positions.keys())
        fig.update_layout(
            title={
                "text": f"Investigation Timeline ({len(timeline.events)} events)",
                "font": {"size": 16},
            },
            xaxis={
                "title": "Time",
                "showgrid": True,
                "gridwidth": 1,
                "gridcolor": "rgba(200, 200, 200, 0.3)",
            },
            yaxis={
                "title": "Entity Type",
                "tickmode": "array",
                "tickvals": list(range(len(y_labels))),
                "ticktext": y_labels,
                "showgrid": True,
                "gridwidth": 1,
                "gridcolor": "rgba(200, 200, 200, 0.3)",
            },
            height=int(self.height.replace("px", "")),
            hovermode="closest",
            showlegend=False,
            plot_bgcolor="white",
            margin={"l": 100, "r": 50, "t": 60, "b": 50},
        )

        return fig

    def to_html(self, timeline: InvestigationTimeline) -> str:
        """Generate an HTML representation of the timeline.

        Args:
            timeline: The investigation timeline to visualize

        Returns:
            HTML string containing the interactive timeline
        """
        fig = self.create_plotly_figure(timeline)
        return fig.to_html(include_plotlyjs="cdn", full_html=False)

    def generate_legend_html(self) -> str:
        """Generate an HTML legend for event tags."""
        legend_items = []
        for tag in EventTag:
            color = TAG_COLORS.get(tag, "#A0A0A0")
            label = tag.value.replace("_", " ").title()
            legend_items.append(
                f'<span style="display: inline-block; margin-right: 12px;">'
                f'<span style="display: inline-block; width: 12px; height: 12px; '
                f'background-color: {color}; border-radius: 50%; margin-right: 4px;"></span>'
                f"{label}</span>"
            )

        return f"""
        <div style="padding:10px; background:#f5f5f5; border-radius:4px; margin-top:10px;">
            <strong>Event Tags:</strong><br>
            <div style="margin-top: 5px; line-height: 2;">
                {"".join(legend_items)}
            </div>
        </div>
        """


def generate_timeline_summary_prompt(timeline: InvestigationTimeline) -> str:
    """Generate a prompt for AI timeline summarization.

    Args:
        timeline: The investigation timeline to summarize

    Returns:
        Prompt string for the AI model
    """
    # Build event list for the prompt
    event_descriptions = []
    for event in timeline.events:
        tag_info = f" [{event.tag.value}]" if event.tag != EventTag.UNREVIEWED else ""
        event_descriptions.append(
            f"- {event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}: "
            f"{event.title}{tag_info}"
            f"{' - ' + event.description if event.description else ''}"
        )

    events_text = "\n".join(event_descriptions)

    summary = timeline.summary()
    tag_counts = summary.get("tag_counts", {})
    suspicious_count = sum(
        tag_counts.get(tag, 0)
        for tag in [
            "suspicious",
            "attack_phase",
            "initial_access",
            "persistence",
            "privilege_escalation",
            "lateral_movement",
            "data_exfiltration",
            "impact",
        ]
    )

    return f"""Analyze this security investigation timeline and provide a concise \
summary for an incident response report.

**Timeline Statistics:**
- Total events: {summary["total_events"]}
- Time range: {summary["time_range"]["start"]} to {summary["time_range"]["end"]}
- Suspicious/attack events: {suspicious_count}
- Tagged events breakdown: {tag_counts}

**Chronological Events:**
{events_text}

**Instructions:**
1. Summarize the key activities observed in chronological order
2. Identify any attack patterns or TTPs (Tactics, Techniques, and Procedures)
3. Highlight the most critical events and their implications
4. Note any gaps or missing information that would help the investigation
5. Provide recommendations for immediate response actions

Format as a professional incident summary for an analyst's report."""


# =============================================================================
# Neptune persistence for timelines
# =============================================================================


def save_timeline_to_neptune(
    timeline: InvestigationTimeline,
    connector: NeptuneConnector,
) -> int:
    """Save an InvestigationTimeline to Neptune graph database.

    Creates a Timeline vertex connected to TimelineEvent vertices.
    Events that reference existing graph nodes are linked via
    HAS_TIMELINE_EVENT edges.

    Args:
        timeline: The timeline to persist
        connector: A NeptuneConnector instance

    Returns:
        Number of entities (vertices + edges) written
    """
    count = 0
    tl_id = f"timeline:{timeline.investigation_id or 'default'}"

    # Upsert the timeline root vertex
    summary = timeline.summary()
    tl_query = (
        f"g.V('{_esc(tl_id)}')"
        f".fold().coalesce(unfold(), addV('Timeline').property(id, '{_esc(tl_id)}'))"
        f".property('investigation_id', '{_esc(timeline.investigation_id)}')"
        f".property('total_events', {len(timeline.events)})"
        f".property('ai_summary', '{_esc(timeline.ai_summary)}')"
        f".property('analyst_summary', '{_esc(timeline.analyst_summary)}')"
        f".property('created_at', '{timeline.created_at.isoformat()}')"
        f".property('updated_at', '{timeline.updated_at.isoformat()}')"
    )
    for tag, tag_count in summary.get("tag_counts", {}).items():
        tl_query += f".property('tag_{_esc(tag)}', {tag_count})"

    connector.execute_gremlin(tl_query)
    count += 1

    # Upsert each event as a vertex and connect to timeline
    for event in timeline.events:
        evt_id = f"tlevt:{_esc(event.id)}"

        evt_query = (
            f"g.V('{evt_id}')"
            f".fold().coalesce(unfold(), addV('TimelineEvent').property(id, '{evt_id}'))"
            f".property('timestamp', '{event.timestamp.isoformat()}')"
            f".property('title', '{_esc(event.title)}')"
            f".property('description', '{_esc(event.description)}')"
            f".property('entity_type', '{_esc(event.entity_type)}')"
            f".property('entity_id', '{_esc(event.entity_id)}')"
            f".property('operation', '{_esc(event.operation)}')"
            f".property('status', '{_esc(event.status)}')"
            f".property('tag', '{event.tag.value}')"
            f".property('notes', '{_esc(event.notes)}')"
        )
        connector.execute_gremlin(evt_query)
        count += 1

        # Edge: Timeline -> TimelineEvent
        edge_query = (
            f"g.V('{_esc(tl_id)}').as('tl')"
            f".V('{evt_id}').as('evt')"
            f".select('tl').outE('HAS_EVENT').where(inV().is(select('evt')))"
            f".fold().coalesce(unfold(), select('tl').addE('HAS_EVENT').to(select('evt')))"
        )
        connector.execute_gremlin(edge_query)
        count += 1

        # Edge: TimelineEvent -> referenced graph node (if it exists)
        if event.entity_id and not event.entity_id.startswith("tlevt:"):
            link_query = (
                f"g.V('{_esc(event.entity_id)}')"
                f".fold().coalesce("
                f"  unfold().as('target'),"
                f"  constant('missing')"
                f")"
                f".choose(is('missing'), identity(),"
                f"  V('{evt_id}').outE('REFERS_TO')"
                f"  .where(inV().is(select('target')))"
                f"  .fold().coalesce(unfold(),"
                f"    V('{evt_id}').addE('REFERS_TO').to(select('target'))"
                f"  )"
                f")"
            )
            try:
                connector.execute_gremlin(link_query)
                count += 1
            except Exception:
                pass  # Target node may not exist in graph

    return count


def load_timeline_from_neptune(
    investigation_id: str,
    connector: NeptuneConnector,
) -> InvestigationTimeline | None:
    """Load an InvestigationTimeline from Neptune.

    Args:
        investigation_id: The investigation ID to load
        connector: A NeptuneConnector instance

    Returns:
        InvestigationTimeline if found, None otherwise
    """
    tl_id = f"timeline:{_esc(investigation_id or 'default')}"

    # Check if timeline exists
    check = connector.execute_gremlin(f"g.V('{tl_id}').hasLabel('Timeline').count()")
    result_data = check.get("result", {}).get("data", [])
    if not result_data or result_data[0] == 0:
        return None

    # Load timeline properties
    tl_props = connector.execute_gremlin(f"g.V('{tl_id}').valueMap(true)")
    tl_data = tl_props.get("result", {}).get("data", [{}])[0]

    # Load events connected to this timeline
    events_result = connector.execute_gremlin(
        f"g.V('{tl_id}').out('HAS_EVENT')"
        f".hasLabel('TimelineEvent')"
        f".order().by('timestamp')"
        f".valueMap(true)"
    )
    events_data = events_result.get("result", {}).get("data", [])

    # Build timeline
    events = []
    for evt in events_data:
        events.append(
            TimelineEvent(
                id=_get_prop(evt, "id", ""),
                timestamp=datetime.fromisoformat(
                    _get_prop(evt, "timestamp", "2000-01-01T00:00:00")
                ),
                title=_get_prop(evt, "title", ""),
                description=_get_prop(evt, "description", ""),
                entity_type=_get_prop(evt, "entity_type", ""),
                entity_id=_get_prop(evt, "entity_id", ""),
                operation=_get_prop(evt, "operation", ""),
                status=_get_prop(evt, "status", "success"),
                tag=EventTag(_get_prop(evt, "tag", "unreviewed")),
                notes=_get_prop(evt, "notes", ""),
            )
        )

    return InvestigationTimeline(
        investigation_id=investigation_id,
        events=events,
        ai_summary=_get_prop(tl_data, "ai_summary", ""),
        analyst_summary=_get_prop(tl_data, "analyst_summary", ""),
        created_at=datetime.fromisoformat(
            _get_prop(tl_data, "created_at", datetime.now().isoformat())
        ),
        updated_at=datetime.fromisoformat(
            _get_prop(tl_data, "updated_at", datetime.now().isoformat())
        ),
    )


def delete_timeline_from_neptune(
    investigation_id: str,
    connector: NeptuneConnector,
) -> bool:
    """Delete a timeline and its events from Neptune.

    Args:
        investigation_id: The investigation ID to delete
        connector: A NeptuneConnector instance

    Returns:
        True if deleted, False if not found
    """
    tl_id = f"timeline:{_esc(investigation_id or 'default')}"

    # Delete events first, then timeline vertex
    connector.execute_gremlin(f"g.V('{tl_id}').out('HAS_EVENT').hasLabel('TimelineEvent').drop()")
    result = connector.execute_gremlin(f"g.V('{tl_id}').hasLabel('Timeline').drop()")
    return result is not None


def _esc(value: str) -> str:
    """Escape a string for Gremlin queries."""
    return str(value).replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')


def _get_prop(data: dict, key: str, default: str = "") -> str:
    """Extract a property from Neptune valueMap result.

    Neptune valueMap returns lists for property values.
    """
    val = data.get(key, default)
    if isinstance(val, list) and val:
        return str(val[0])
    return str(val) if val else default
