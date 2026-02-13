"""Tests for InvestigationStore — DuckDB-backed investigation persistence."""

from datetime import UTC, datetime

import pytest

from secdashboards.graph.models import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    SecurityGraph,
)
from secdashboards.graph.persistence import InvestigationStore
from secdashboards.graph.timeline import (
    EventTag,
    InvestigationTimeline,
    TimelineEvent,
)


@pytest.fixture
def store():
    """In-memory InvestigationStore for testing."""
    s = InvestigationStore(":memory:")
    yield s
    s.close()


@pytest.fixture
def sample_graph() -> SecurityGraph:
    """Graph with 2 nodes and 1 edge."""
    graph = SecurityGraph()
    graph.add_node(
        GraphNode(
            id="principal:admin",
            node_type=NodeType.PRINCIPAL,
            label="admin@example.com",
            first_seen=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
            last_seen=datetime(2024, 6, 1, 13, 0, tzinfo=UTC),
            event_count=5,
            properties={"user_type": "IAMUser", "account_id": "123456789"},
        )
    )
    graph.add_node(
        GraphNode(
            id="ip:10.0.0.1",
            node_type=NodeType.IP_ADDRESS,
            label="10.0.0.1",
            first_seen=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
            event_count=3,
            properties={"is_internal": True},
        )
    )
    graph.add_edge(
        GraphEdge(
            id=GraphEdge.create_id(EdgeType.AUTHENTICATED_FROM, "principal:admin", "ip:10.0.0.1"),
            edge_type=EdgeType.AUTHENTICATED_FROM,
            source_id="principal:admin",
            target_id="ip:10.0.0.1",
            weight=5.0,
            first_seen=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
            last_seen=datetime(2024, 6, 1, 13, 0, tzinfo=UTC),
            event_count=5,
            properties={"sessions": 3},
        )
    )
    return graph


@pytest.fixture
def sample_timeline() -> InvestigationTimeline:
    """Timeline with 2 events."""
    return InvestigationTimeline(
        investigation_id="inv-test",
        events=[
            TimelineEvent(
                id="evt-1",
                timestamp=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
                title="Login from admin",
                description="IAMUser login",
                entity_type="Principal",
                entity_id="principal:admin",
                operation="ConsoleLogin",
                tag=EventTag.IMPORTANT,
            ),
            TimelineEvent(
                id="evt-2",
                timestamp=datetime(2024, 6, 1, 12, 30, tzinfo=UTC),
                title="S3 access",
                description="GetObject on sensitive-bucket",
                entity_type="Resource",
                entity_id="resource:s3:sensitive-bucket",
                operation="GetObject",
                tag=EventTag.SUSPICIOUS,
                notes="Analyst: unusual access pattern",
                properties={"bucket": "sensitive-bucket"},
            ),
        ],
    )


class TestSchemaManagement:
    def test_schema_idempotent(self, store) -> None:
        """Calling _ensure_schema twice should not raise."""
        store._ensure_schema()
        store._ensure_schema()

    def test_fresh_store_has_no_investigations(self, store) -> None:
        assert store.list_investigations() == []


class TestInvestigationCRUD:
    def test_save_and_load_empty_graph(self, store) -> None:
        graph = SecurityGraph()
        store.save_investigation("inv-1", "Empty Investigation", graph)
        loaded = store.load_investigation("inv-1")

        assert loaded is not None
        assert loaded["name"] == "Empty Investigation"
        assert loaded["graph"].node_count() == 0
        assert loaded["graph"].edge_count() == 0
        assert loaded["status"] == "active"

    def test_save_and_load_with_nodes_edges(self, store, sample_graph) -> None:
        store.save_investigation(
            "inv-2",
            "Admin Investigation",
            sample_graph,
            created_at=datetime(2024, 6, 1, tzinfo=UTC),
        )
        loaded = store.load_investigation("inv-2")

        assert loaded is not None
        assert loaded["name"] == "Admin Investigation"
        assert loaded["created_at"] == "2024-06-01T00:00:00+00:00"

        graph = loaded["graph"]
        assert graph.node_count() == 2
        assert graph.edge_count() == 1

        admin_node = graph.get_node("principal:admin")
        assert admin_node is not None
        assert admin_node.label == "admin@example.com"
        assert admin_node.node_type == NodeType.PRINCIPAL
        assert admin_node.event_count == 5
        assert admin_node.properties["user_type"] == "IAMUser"

        ip_node = graph.get_node("ip:10.0.0.1")
        assert ip_node is not None
        assert ip_node.properties["is_internal"] is True

        edge = graph.edges[0]
        assert edge.edge_type == EdgeType.AUTHENTICATED_FROM
        assert edge.weight == 5.0
        assert edge.event_count == 5
        assert edge.properties["sessions"] == 3

    def test_load_nonexistent_returns_none(self, store) -> None:
        assert store.load_investigation("doesnt-exist") is None

    def test_save_with_iso_string_created_at(self, store) -> None:
        """Accept ISO format strings for created_at (from in-memory dict)."""
        graph = SecurityGraph()
        store.save_investigation(
            "inv-3", "String Date", graph, created_at="2024-06-01T12:00:00+00:00"
        )
        loaded = store.load_investigation("inv-3")
        assert loaded is not None
        assert "2024-06-01" in loaded["created_at"]

    def test_list_investigations(self, store, sample_graph) -> None:
        store.save_investigation("inv-a", "First", SecurityGraph())
        store.save_investigation("inv-b", "Second", sample_graph)

        inv_list = store.list_investigations()
        assert len(inv_list) == 2
        # Find the one with nodes
        second = next(i for i in inv_list if i["id"] == "inv-b")
        assert second["name"] == "Second"
        assert second["node_count"] == 2
        assert second["edge_count"] == 1

    def test_delete_investigation(self, store, sample_graph) -> None:
        store.save_investigation("inv-del", "To Delete", sample_graph)
        assert store.load_investigation("inv-del") is not None

        store.delete_investigation("inv-del")
        assert store.load_investigation("inv-del") is None
        assert store.list_investigations() == []

    def test_update_status(self, store) -> None:
        store.save_investigation("inv-s", "Status Test", SecurityGraph())
        store.update_status("inv-s", "closed")
        loaded = store.load_investigation("inv-s")
        assert loaded is not None
        assert loaded["status"] == "closed"

    def test_save_overwrites_existing(self, store) -> None:
        """Re-saving with same ID replaces the investigation."""
        store.save_investigation("inv-ow", "Original", SecurityGraph())
        store.save_investigation("inv-ow", "Updated", SecurityGraph())
        loaded = store.load_investigation("inv-ow")
        assert loaded is not None
        assert loaded["name"] == "Updated"


class TestGraphPersistence:
    def test_properties_json_roundtrip(self, store) -> None:
        """Nested dicts, lists, and special types survive JSON roundtrip."""
        graph = SecurityGraph()
        graph.add_node(
            GraphNode(
                id="node-1",
                node_type=NodeType.RESOURCE,
                label="test-resource",
                properties={
                    "nested": {"key": "value"},
                    "list_val": [1, 2, 3],
                    "bool_val": True,
                    "null_val": None,
                },
            )
        )
        store.save_graph("inv-json", graph)
        loaded = store.load_graph("inv-json")

        props = loaded.get_node("node-1").properties
        assert props["nested"] == {"key": "value"}
        assert props["list_val"] == [1, 2, 3]
        assert props["bool_val"] is True
        assert props["null_val"] is None

    def test_timestamp_preservation(self, store) -> None:
        """Datetime values survive roundtrip."""
        ts = datetime(2024, 6, 15, 10, 30, 0, tzinfo=UTC)
        graph = SecurityGraph()
        graph.add_node(
            GraphNode(
                id="n-ts",
                node_type=NodeType.EVENT,
                label="ts-test",
                first_seen=ts,
                last_seen=ts,
            )
        )
        store.save_graph("inv-ts", graph)
        loaded = store.load_graph("inv-ts")
        node = loaded.get_node("n-ts")
        assert node.first_seen == ts
        assert node.last_seen == ts

    def test_save_graph_replaces_all(self, store, sample_graph) -> None:
        """Re-saving a graph replaces all nodes/edges."""
        store.save_graph("inv-rep", sample_graph)
        assert store.load_graph("inv-rep").node_count() == 2

        new_graph = SecurityGraph()
        new_graph.add_node(GraphNode(id="only-one", node_type=NodeType.PRINCIPAL, label="sole"))
        store.save_graph("inv-rep", new_graph)
        loaded = store.load_graph("inv-rep")
        assert loaded.node_count() == 1
        assert loaded.get_node("only-one") is not None


class TestTimelinePersistence:
    def test_save_and_load_timeline(self, store, sample_timeline) -> None:
        store.save_timeline("inv-tl", sample_timeline)
        loaded = store.load_timeline("inv-tl")

        assert loaded is not None
        assert len(loaded.events) == 2
        assert loaded.events[0].id == "evt-1"
        assert loaded.events[0].tag == EventTag.IMPORTANT
        assert loaded.events[1].notes == "Analyst: unusual access pattern"
        assert loaded.events[1].properties["bucket"] == "sensitive-bucket"

    def test_load_timeline_empty(self, store) -> None:
        assert store.load_timeline("inv-empty") is None

    def test_tag_event(self, store, sample_timeline) -> None:
        store.save_timeline("inv-tag", sample_timeline)
        result = store.tag_event("inv-tag", "evt-1", "suspicious", "Flagged by analyst")
        assert result is True

        loaded = store.load_timeline("inv-tag")
        evt = next(e for e in loaded.events if e.id == "evt-1")
        assert evt.tag == EventTag.SUSPICIOUS
        assert evt.notes == "Flagged by analyst"

    def test_tag_event_nonexistent(self, store) -> None:
        assert store.tag_event("inv-no", "evt-no", "suspicious") is False

    def test_timeline_tags_in_loaded_investigation(self, store, sample_timeline) -> None:
        """load_investigation() includes timeline_tags dict from persisted events."""
        store.save_investigation("inv-tt", "Tagged", SecurityGraph())
        store.save_timeline("inv-tt", sample_timeline)

        loaded = store.load_investigation("inv-tt")
        assert loaded is not None
        tags = loaded["timeline_tags"]
        assert tags["evt-1"] == "important"
        assert tags["evt-2"] == "suspicious"


class TestArtifactCaching:
    def test_save_and_load_artifact(self, store) -> None:
        html = "<html><body>Graph Viz</body></html>"
        store.save_artifact("inv-a", "graph_html", html)
        loaded = store.load_artifact("inv-a", "graph_html")
        assert loaded == html

    def test_load_missing_artifact(self, store) -> None:
        assert store.load_artifact("inv-no", "graph_html") is None

    def test_save_artifact_overwrites(self, store) -> None:
        store.save_artifact("inv-a", "graph_html", "v1")
        store.save_artifact("inv-a", "graph_html", "v2")
        assert store.load_artifact("inv-a", "graph_html") == "v2"

    def test_delete_artifacts(self, store) -> None:
        store.save_artifact("inv-d", "graph_html", "graph")
        store.save_artifact("inv-d", "timeline_html", "timeline")
        store.delete_artifacts("inv-d")
        assert store.load_artifact("inv-d", "graph_html") is None
        assert store.load_artifact("inv-d", "timeline_html") is None


class TestConcurrentInvestigations:
    def test_multiple_investigations_isolated(self, store, sample_graph) -> None:
        """Data for different investigations doesn't leak."""
        store.save_investigation("inv-x", "X", sample_graph)
        store.save_investigation("inv-y", "Y", SecurityGraph())

        x = store.load_investigation("inv-x")
        y = store.load_investigation("inv-y")
        assert x["graph"].node_count() == 2
        assert y["graph"].node_count() == 0

    def test_delete_one_preserves_other(self, store, sample_graph) -> None:
        store.save_investigation("inv-keep", "Keep", sample_graph)
        store.save_investigation("inv-drop", "Drop", sample_graph)

        store.delete_investigation("inv-drop")
        assert store.load_investigation("inv-drop") is None
        assert store.load_investigation("inv-keep") is not None
        assert store.load_investigation("inv-keep")["graph"].node_count() == 2


class TestFullRoundtrip:
    def test_investigation_with_graph_and_timeline(
        self, store, sample_graph, sample_timeline
    ) -> None:
        """Full create → persist graph → persist timeline → load roundtrip."""
        store.save_investigation(
            "inv-full",
            "Full Roundtrip",
            sample_graph,
            created_at=datetime(2024, 6, 1, tzinfo=UTC),
            metadata={"source": "test"},
        )
        store.save_timeline("inv-full", sample_timeline)
        store.save_artifact("inv-full", "graph_html", "<html>graph</html>")

        loaded = store.load_investigation("inv-full")
        assert loaded["name"] == "Full Roundtrip"
        assert loaded["graph"].node_count() == 2
        assert loaded["graph"].edge_count() == 1
        assert loaded["timeline_tags"]["evt-1"] == "important"
        assert loaded["timeline_tags"]["evt-2"] == "suspicious"

        timeline = store.load_timeline("inv-full")
        assert len(timeline.events) == 2

        artifact = store.load_artifact("inv-full", "graph_html")
        assert artifact == "<html>graph</html>"

        inv_list = store.list_investigations()
        assert len(inv_list) == 1
        assert inv_list[0]["node_count"] == 2
