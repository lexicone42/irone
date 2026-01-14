"""Tests for timeline visualization functionality."""

from datetime import datetime, timedelta, timezone

import pytest

from secdashboards.graph import (
    EventTag,
    InvestigationTimeline,
    TimelineEvent,
    TimelineVisualizer,
    extract_timeline_from_graph,
    generate_timeline_summary_prompt,
)
from secdashboards.graph.models import (
    EdgeType,
    GraphEdge,
    NodeType,
    PrincipalNode,
    APIOperationNode,
    SecurityFindingNode,
    IPAddressNode,
    SecurityGraph,
)


class TestTimelineEvent:
    """Tests for TimelineEvent model."""

    def test_create_basic_event(self):
        """Test creating a basic timeline event."""
        event = TimelineEvent(
            id="test-001",
            timestamp=datetime.now(timezone.utc),
            title="Test Event",
            entity_type="Principal",
            entity_id="user:test",
        )
        assert event.id == "test-001"
        assert event.title == "Test Event"
        assert event.tag == EventTag.UNREVIEWED
        assert event.notes == ""

    def test_event_with_all_fields(self):
        """Test event with all fields populated."""
        timestamp = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        event = TimelineEvent(
            id="test-002",
            timestamp=timestamp,
            title="API Call",
            description="Created new IAM user",
            entity_type="APIOperation",
            entity_id="api:iam:CreateUser",
            operation="CreateUser",
            status="success",
            tag=EventTag.SUSPICIOUS,
            notes="Requires investigation",
            properties={"service": "iam"},
        )
        assert event.operation == "CreateUser"
        assert event.tag == EventTag.SUSPICIOUS
        assert event.notes == "Requires investigation"
        assert event.properties["service"] == "iam"

    def test_event_color_property(self):
        """Test that events have correct colors based on tag."""
        event_suspicious = TimelineEvent(
            id="e1",
            timestamp=datetime.now(timezone.utc),
            title="Test",
            entity_type="Test",
            entity_id="test",
            tag=EventTag.SUSPICIOUS,
        )
        assert event_suspicious.color == "#FF6B6B"  # Red

        event_benign = TimelineEvent(
            id="e2",
            timestamp=datetime.now(timezone.utc),
            title="Test",
            entity_type="Test",
            entity_id="test",
            tag=EventTag.BENIGN,
        )
        assert event_benign.color == "#4ECDC4"  # Teal

    def test_event_to_dict(self):
        """Test event serialization to dictionary."""
        timestamp = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        event = TimelineEvent(
            id="test-003",
            timestamp=timestamp,
            title="Test Event",
            entity_type="Principal",
            entity_id="user:test",
            tag=EventTag.IMPORTANT,
        )
        data = event.to_dict()
        assert data["id"] == "test-003"
        assert data["timestamp"] == "2024-01-15T10:30:00+00:00"
        assert data["tag"] == "important"


class TestInvestigationTimeline:
    """Tests for InvestigationTimeline container."""

    def test_create_empty_timeline(self):
        """Test creating an empty timeline."""
        timeline = InvestigationTimeline(investigation_id="INC-001")
        assert timeline.investigation_id == "INC-001"
        assert len(timeline.events) == 0
        assert timeline.ai_summary == ""
        assert timeline.analyst_summary == ""

    def test_add_events_sorted(self):
        """Test that events are sorted by timestamp when added."""
        timeline = InvestigationTimeline()

        # Add events out of order
        event2 = TimelineEvent(
            id="e2",
            timestamp=datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
            title="Second",
            entity_type="Test",
            entity_id="test",
        )
        event1 = TimelineEvent(
            id="e1",
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            title="First",
            entity_type="Test",
            entity_id="test",
        )
        event3 = TimelineEvent(
            id="e3",
            timestamp=datetime(2024, 1, 15, 14, 0, 0, tzinfo=timezone.utc),
            title="Third",
            entity_type="Test",
            entity_id="test",
        )

        timeline.add_event(event2)
        timeline.add_event(event1)
        timeline.add_event(event3)

        assert len(timeline.events) == 3
        assert timeline.events[0].id == "e1"
        assert timeline.events[1].id == "e2"
        assert timeline.events[2].id == "e3"

    def test_tag_event(self):
        """Test tagging an event."""
        timeline = InvestigationTimeline()
        event = TimelineEvent(
            id="e1",
            timestamp=datetime.now(timezone.utc),
            title="Test",
            entity_type="Test",
            entity_id="test",
        )
        timeline.add_event(event)

        # Tag the event
        success = timeline.tag_event("e1", EventTag.SUSPICIOUS, "Looks malicious")
        assert success is True
        assert timeline.events[0].tag == EventTag.SUSPICIOUS
        assert timeline.events[0].notes == "Looks malicious"

        # Try tagging non-existent event
        success = timeline.tag_event("e999", EventTag.BENIGN)
        assert success is False

    def test_get_events_by_tag(self):
        """Test filtering events by tag."""
        timeline = InvestigationTimeline()

        for i, tag in enumerate([EventTag.SUSPICIOUS, EventTag.BENIGN, EventTag.SUSPICIOUS]):
            event = TimelineEvent(
                id=f"e{i}",
                timestamp=datetime.now(timezone.utc) + timedelta(minutes=i),
                title=f"Event {i}",
                entity_type="Test",
                entity_id="test",
                tag=tag,
            )
            timeline.add_event(event)

        suspicious = timeline.get_events_by_tag(EventTag.SUSPICIOUS)
        assert len(suspicious) == 2

        benign = timeline.get_events_by_tag(EventTag.BENIGN)
        assert len(benign) == 1

    def test_get_suspicious_events(self):
        """Test getting all suspicious/attack-related events."""
        timeline = InvestigationTimeline()

        tags = [
            EventTag.SUSPICIOUS,
            EventTag.INITIAL_ACCESS,
            EventTag.PERSISTENCE,
            EventTag.BENIGN,
            EventTag.IMPORTANT,
        ]

        for i, tag in enumerate(tags):
            event = TimelineEvent(
                id=f"e{i}",
                timestamp=datetime.now(timezone.utc) + timedelta(minutes=i),
                title=f"Event {i}",
                entity_type="Test",
                entity_id="test",
                tag=tag,
            )
            timeline.add_event(event)

        suspicious = timeline.get_suspicious_events()
        assert len(suspicious) == 3  # SUSPICIOUS, INITIAL_ACCESS, PERSISTENCE

    def test_get_time_range(self):
        """Test getting the time range of events."""
        timeline = InvestigationTimeline()

        # Empty timeline
        start, end = timeline.get_time_range()
        assert start is None
        assert end is None

        # Add events
        t1 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2024, 1, 15, 14, 0, 0, tzinfo=timezone.utc)

        timeline.add_event(TimelineEvent(
            id="e1", timestamp=t1, title="First", entity_type="Test", entity_id="test"
        ))
        timeline.add_event(TimelineEvent(
            id="e2", timestamp=t2, title="Last", entity_type="Test", entity_id="test"
        ))

        start, end = timeline.get_time_range()
        assert start == t1
        assert end == t2

    def test_summary(self):
        """Test timeline summary generation."""
        timeline = InvestigationTimeline(investigation_id="INC-001")

        # Add events with different tags
        t1 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        timeline.add_event(TimelineEvent(
            id="e1", timestamp=t1, title="Event 1",
            entity_type="Test", entity_id="test",
            tag=EventTag.SUSPICIOUS,
        ))
        timeline.add_event(TimelineEvent(
            id="e2", timestamp=t2, title="Event 2",
            entity_type="Test", entity_id="test",
            tag=EventTag.BENIGN,
        ))
        timeline.ai_summary = "Test summary"

        summary = timeline.summary()
        assert summary["total_events"] == 2
        assert summary["tag_counts"]["suspicious"] == 1
        assert summary["tag_counts"]["benign"] == 1
        assert summary["time_range"]["duration_seconds"] == 7200  # 2 hours
        assert summary["has_ai_summary"] is True

    def test_to_dict(self):
        """Test timeline serialization."""
        timeline = InvestigationTimeline(investigation_id="INC-001")
        timeline.add_event(TimelineEvent(
            id="e1",
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            title="Test Event",
            entity_type="Principal",
            entity_id="user:test",
        ))
        timeline.ai_summary = "AI generated summary"
        timeline.analyst_summary = "Analyst edited summary"

        data = timeline.to_dict()
        assert data["investigation_id"] == "INC-001"
        assert len(data["events"]) == 1
        assert data["ai_summary"] == "AI generated summary"
        assert data["analyst_summary"] == "Analyst edited summary"
        assert "summary" in data


class TestExtractTimelineFromGraph:
    """Tests for graph-to-timeline extraction."""

    def create_test_graph(self):
        """Create a test graph with various node types."""
        graph = SecurityGraph(metadata={"investigation_id": "INC-001"})

        # Add principal node
        principal = PrincipalNode(
            id="Principal:test-user",
            label="test-user",
            user_name="test-user",
            user_type="IAMUser",
            account_id="123456789012",
            arn="arn:aws:iam::123456789012:user/test-user",
            first_seen=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, 14, 0, 0, tzinfo=timezone.utc),
            event_count=10,
        )
        graph.add_node(principal)

        # Add API operation node
        api_op = APIOperationNode(
            id="APIOperation:iam:CreateUser",
            label="iam:CreateUser",
            service="iam",
            operation="CreateUser",
            first_seen=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            event_count=1,
        )
        api_op.record_status("success")
        graph.add_node(api_op)

        # Add security finding
        finding = SecurityFindingNode(
            id="Finding:test-rule:2024-01-15T10:30:00",
            label="IAM User Created",
            rule_id="test-rule",
            rule_name="IAM User Created",
            severity="high",
            triggered_at=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            match_count=1,
            first_seen=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            event_count=1,
        )
        graph.add_node(finding)

        # Add IP address node
        ip_node = IPAddressNode(
            id="IPAddress:10.0.0.1",
            label="10.0.0.1",
            ip_address="10.0.0.1",
            is_internal=True,
            geo_location="Internal",
            first_seen=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            event_count=5,
        )
        graph.add_node(ip_node)

        return graph

    def test_extract_timeline_basic(self):
        """Test basic timeline extraction from graph."""
        graph = self.create_test_graph()
        timeline = extract_timeline_from_graph(graph)

        assert timeline.investigation_id == "INC-001"
        assert len(timeline.events) > 0

    def test_extract_timeline_nodes_only(self):
        """Test extracting timeline from nodes only."""
        graph = self.create_test_graph()
        timeline = extract_timeline_from_graph(
            graph, include_nodes=True, include_edges=False
        )

        # Should have events for each node with timestamp
        assert len(timeline.events) == 4

    def test_extract_timeline_includes_edges(self):
        """Test extracting timeline including edges."""
        graph = self.create_test_graph()

        # Add an edge with timestamp
        edge = GraphEdge(
            id="edge-1",
            source_id="Principal:test-user",
            target_id="APIOperation:iam:CreateUser",
            edge_type=EdgeType.CALLED_API,
            first_seen=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            event_count=1,
        )
        graph.add_edge(edge)

        timeline = extract_timeline_from_graph(
            graph, include_nodes=True, include_edges=True
        )

        # Should include the edge as an event
        edge_events = [e for e in timeline.events if e.entity_type == "relationship"]
        assert len(edge_events) == 1

    def test_security_finding_auto_tagged(self):
        """Test that high severity security findings are auto-tagged as suspicious."""
        graph = self.create_test_graph()
        timeline = extract_timeline_from_graph(graph)

        # Find the security finding event
        finding_events = [
            e for e in timeline.events
            if e.entity_type == "SecurityFinding"
        ]
        assert len(finding_events) == 1
        assert finding_events[0].tag == EventTag.SUSPICIOUS

    def test_events_sorted_chronologically(self):
        """Test that extracted events are sorted by timestamp."""
        graph = self.create_test_graph()
        timeline = extract_timeline_from_graph(graph)

        # Verify chronological order
        for i in range(1, len(timeline.events)):
            assert timeline.events[i].timestamp >= timeline.events[i-1].timestamp


class TestTimelineVisualizer:
    """Tests for timeline visualization."""

    def test_create_visualizer(self):
        """Test creating a visualizer instance."""
        vis = TimelineVisualizer(height="600px", width="100%")
        assert vis.height == "600px"
        assert vis.width == "100%"

    def test_empty_timeline_figure(self):
        """Test creating figure for empty timeline."""
        vis = TimelineVisualizer()
        timeline = InvestigationTimeline()

        fig = vis.create_plotly_figure(timeline)
        assert fig is not None

    def test_timeline_figure_with_events(self):
        """Test creating figure with events."""
        vis = TimelineVisualizer()
        timeline = InvestigationTimeline()

        for i in range(5):
            timeline.add_event(TimelineEvent(
                id=f"e{i}",
                timestamp=datetime.now(timezone.utc) + timedelta(hours=i),
                title=f"Event {i}",
                entity_type="Principal",
                entity_id="test",
                tag=EventTag.SUSPICIOUS if i % 2 == 0 else EventTag.BENIGN,
            ))

        fig = vis.create_plotly_figure(timeline)
        assert fig is not None
        # Should have traces for events and connecting lines
        assert len(fig.data) >= 1

    def test_to_html(self):
        """Test HTML generation."""
        vis = TimelineVisualizer()
        timeline = InvestigationTimeline()
        timeline.add_event(TimelineEvent(
            id="e1",
            timestamp=datetime.now(timezone.utc),
            title="Test Event",
            entity_type="Principal",
            entity_id="test",
        ))

        html = vis.to_html(timeline)
        assert "<div" in html
        assert "plotly" in html.lower()

    def test_legend_html(self):
        """Test legend HTML generation."""
        vis = TimelineVisualizer()
        legend = vis.generate_legend_html()

        assert "Event Tags" in legend
        assert "Suspicious" in legend
        assert "Benign" in legend
        assert "#FF6B6B" in legend  # Suspicious color


class TestTimelineSummaryPrompt:
    """Tests for AI summary prompt generation."""

    def test_generate_prompt_empty_timeline(self):
        """Test prompt generation for empty timeline."""
        timeline = InvestigationTimeline()
        prompt = generate_timeline_summary_prompt(timeline)

        assert "Total events: 0" in prompt
        assert "Chronological Events:" in prompt

    def test_generate_prompt_with_events(self):
        """Test prompt generation with events."""
        timeline = InvestigationTimeline(investigation_id="INC-001")

        timeline.add_event(TimelineEvent(
            id="e1",
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            title="User Login",
            description="From external IP",
            entity_type="Principal",
            entity_id="test",
            tag=EventTag.SUSPICIOUS,
        ))
        timeline.add_event(TimelineEvent(
            id="e2",
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            title="IAM CreateUser",
            entity_type="APIOperation",
            entity_id="test",
            tag=EventTag.INITIAL_ACCESS,
        ))

        prompt = generate_timeline_summary_prompt(timeline)

        assert "Total events: 2" in prompt
        assert "User Login" in prompt
        assert "IAM CreateUser" in prompt
        assert "[suspicious]" in prompt
        assert "[initial_access]" in prompt
        assert "Suspicious/attack events: 2" in prompt
        assert "TTPs" in prompt  # Instructions mention TTPs
