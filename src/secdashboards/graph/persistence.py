"""DuckDB-backed persistence for security investigations.

Provides durable storage for investigation metadata, graph data (nodes/edges),
timeline events, and cached visualization artifacts. Designed for write-through
use alongside the in-memory ``AppState.investigations`` dict.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import duckdb

if TYPE_CHECKING:
    from secdashboards.graph.models import SecurityGraph
    from secdashboards.graph.timeline import InvestigationTimeline

logger = logging.getLogger(__name__)

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS investigations (
    id              VARCHAR PRIMARY KEY,
    name            VARCHAR NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    status          VARCHAR NOT NULL DEFAULT 'active',
    metadata_json   VARCHAR NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS graph_nodes (
    investigation_id VARCHAR NOT NULL,
    node_id          VARCHAR NOT NULL,
    node_type        VARCHAR NOT NULL,
    label            VARCHAR NOT NULL,
    first_seen       TIMESTAMPTZ,
    last_seen        TIMESTAMPTZ,
    event_count      INTEGER NOT NULL DEFAULT 0,
    properties_json  VARCHAR NOT NULL DEFAULT '{}',
    PRIMARY KEY (investigation_id, node_id)
);

CREATE TABLE IF NOT EXISTS graph_edges (
    investigation_id VARCHAR NOT NULL,
    edge_id          VARCHAR NOT NULL,
    edge_type        VARCHAR NOT NULL,
    source_id        VARCHAR NOT NULL,
    target_id        VARCHAR NOT NULL,
    weight           DOUBLE NOT NULL DEFAULT 1.0,
    first_seen       TIMESTAMPTZ,
    last_seen        TIMESTAMPTZ,
    event_count      INTEGER NOT NULL DEFAULT 1,
    properties_json  VARCHAR NOT NULL DEFAULT '{}',
    PRIMARY KEY (investigation_id, edge_id)
);

CREATE TABLE IF NOT EXISTS timeline_events (
    investigation_id VARCHAR NOT NULL,
    event_id         VARCHAR NOT NULL,
    timestamp        TIMESTAMPTZ NOT NULL,
    title            VARCHAR NOT NULL,
    description      VARCHAR NOT NULL DEFAULT '',
    entity_type      VARCHAR NOT NULL,
    entity_id        VARCHAR NOT NULL,
    operation        VARCHAR NOT NULL DEFAULT '',
    status           VARCHAR NOT NULL DEFAULT 'success',
    tag              VARCHAR NOT NULL DEFAULT 'unreviewed',
    notes            VARCHAR NOT NULL DEFAULT '',
    properties_json  VARCHAR NOT NULL DEFAULT '{}',
    PRIMARY KEY (investigation_id, event_id)
);

CREATE TABLE IF NOT EXISTS artifacts (
    investigation_id VARCHAR NOT NULL,
    artifact_type    VARCHAR NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    content          VARCHAR NOT NULL,
    PRIMARY KEY (investigation_id, artifact_type)
);
"""


def _json_dumps(obj: Any) -> str:
    """Serialize to JSON, coercing non-serializable types via ``str``."""
    return json.dumps(obj, default=str)


class InvestigationStore:
    """DuckDB-backed persistence for investigations, graphs, and timelines.

    Parameters
    ----------
    db_path:
        Path to the DuckDB file, or ``":memory:"`` for an ephemeral store.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._conn = duckdb.connect(db_path)
        self._conn.execute("SET TimeZone = 'UTC'")
        self._ensure_schema()

    # ------------------------------------------------------------------
    # Schema management
    # ------------------------------------------------------------------

    def _ensure_schema(self) -> None:
        """Create tables if they don't exist (idempotent)."""
        for stmt in _SCHEMA_SQL.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                self._conn.execute(stmt)

    # ------------------------------------------------------------------
    # Investigation CRUD
    # ------------------------------------------------------------------

    def save_investigation(
        self,
        inv_id: str,
        name: str,
        graph: SecurityGraph,
        created_at: str | datetime | None = None,
        metadata: dict[str, Any] | None = None,
        status: str = "active",
    ) -> None:
        """Upsert investigation metadata and persist the full graph."""
        now = datetime.now(UTC)
        if isinstance(created_at, str):
            # Accept ISO format strings from the in-memory dict
            created_at = datetime.fromisoformat(created_at)
        created_at = created_at or now

        self._conn.execute(
            """
            INSERT OR REPLACE INTO investigations
                (id, name, created_at, updated_at, status, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [inv_id, name, created_at, now, status, _json_dumps(metadata or {})],
        )
        self.save_graph(inv_id, graph)

    def load_investigation(self, inv_id: str) -> dict[str, Any] | None:
        """Load a full investigation dict matching the in-memory shape.

        Returns ``None`` if the investigation does not exist.

        Shape::

            {"name", "graph", "created_at", "timeline_tags", "status"}
        """
        row = self._conn.execute(
            "SELECT name, created_at, status, metadata_json FROM investigations WHERE id = ?",
            [inv_id],
        ).fetchone()
        if not row:
            return None

        name, created_at, status, metadata_json = row
        graph = self.load_graph(inv_id)
        timeline = self.load_timeline(inv_id)

        # Build timeline_tags dict from persisted events
        timeline_tags: dict[str, str] = {}
        if timeline:
            for ev in timeline.events:
                if ev.tag.value != "unreviewed":
                    timeline_tags[ev.id] = ev.tag.value

        return {
            "name": name,
            "graph": graph,
            "created_at": (
                created_at.isoformat() if isinstance(created_at, datetime) else str(created_at)
            ),
            "timeline_tags": timeline_tags,
            "status": status,
        }

    def list_investigations(self) -> list[dict[str, Any]]:
        """Return a lightweight list of all investigations."""
        rows = self._conn.execute(
            """
            SELECT
                i.id, i.name, i.created_at, i.status,
                (SELECT COUNT(*) FROM graph_nodes n WHERE n.investigation_id = i.id) AS node_count,
                (SELECT COUNT(*) FROM graph_edges e WHERE e.investigation_id = i.id) AS edge_count
            FROM investigations i
            ORDER BY i.created_at DESC
            """
        ).fetchall()
        return [
            {
                "id": r[0],
                "name": r[1],
                "created_at": r[2].isoformat() if isinstance(r[2], datetime) else str(r[2]),
                "status": r[3],
                "node_count": r[4],
                "edge_count": r[5],
            }
            for r in rows
        ]

    def delete_investigation(self, inv_id: str) -> None:
        """Cascade-delete an investigation and all related data."""
        for table in ("artifacts", "timeline_events", "graph_edges", "graph_nodes"):
            self._conn.execute(f"DELETE FROM {table} WHERE investigation_id = ?", [inv_id])  # noqa: S608
        self._conn.execute("DELETE FROM investigations WHERE id = ?", [inv_id])

    def update_status(self, inv_id: str, status: str) -> None:
        """Update investigation status (e.g. 'active' → 'closed')."""
        self._conn.execute(
            "UPDATE investigations SET status = ?, updated_at = ? WHERE id = ?",
            [status, datetime.now(UTC), inv_id],
        )

    # ------------------------------------------------------------------
    # Graph persistence
    # ------------------------------------------------------------------

    def save_graph(self, inv_id: str, graph: SecurityGraph) -> None:
        """Replace all nodes/edges for an investigation in a transaction."""
        self._conn.execute("BEGIN TRANSACTION")
        try:
            self._conn.execute("DELETE FROM graph_nodes WHERE investigation_id = ?", [inv_id])
            self._conn.execute("DELETE FROM graph_edges WHERE investigation_id = ?", [inv_id])

            for node in graph.nodes.values():
                self._conn.execute(
                    """
                    INSERT INTO graph_nodes
                        (investigation_id, node_id, node_type, label,
                         first_seen, last_seen, event_count, properties_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        inv_id,
                        node.id,
                        node.node_type.value,
                        node.label,
                        node.first_seen,
                        node.last_seen,
                        node.event_count,
                        _json_dumps(node.properties),
                    ],
                )

            for edge in graph.edges:
                self._conn.execute(
                    """
                    INSERT INTO graph_edges
                        (investigation_id, edge_id, edge_type, source_id, target_id,
                         weight, first_seen, last_seen, event_count, properties_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        inv_id,
                        edge.id,
                        edge.edge_type.value,
                        edge.source_id,
                        edge.target_id,
                        edge.weight,
                        edge.first_seen,
                        edge.last_seen,
                        edge.event_count,
                        _json_dumps(edge.properties),
                    ],
                )

            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def load_graph(self, inv_id: str) -> SecurityGraph:
        """Reconstruct a ``SecurityGraph`` from persisted rows."""
        from secdashboards.graph.models import GraphEdge, GraphNode, NodeType, SecurityGraph

        nodes: dict[str, GraphNode] = {}
        for row in self._conn.execute(
            """
            SELECT node_id, node_type, label, first_seen, last_seen,
                   event_count, properties_json
            FROM graph_nodes WHERE investigation_id = ?
            """,
            [inv_id],
        ).fetchall():
            node_id, node_type, label, first_seen, last_seen, event_count, props_json = row
            nodes[node_id] = GraphNode(
                id=node_id,
                node_type=NodeType(node_type),
                label=label,
                first_seen=first_seen,
                last_seen=last_seen,
                event_count=event_count,
                properties=json.loads(props_json) if props_json else {},
            )

        from secdashboards.graph.models import EdgeType

        edges: list[GraphEdge] = []
        for row in self._conn.execute(
            """
            SELECT edge_id, edge_type, source_id, target_id, weight,
                   first_seen, last_seen, event_count, properties_json
            FROM graph_edges WHERE investigation_id = ?
            """,
            [inv_id],
        ).fetchall():
            (
                edge_id,
                edge_type,
                source_id,
                target_id,
                weight,
                first_seen,
                last_seen,
                event_count,
                props_json,
            ) = row
            edges.append(
                GraphEdge(
                    id=edge_id,
                    edge_type=EdgeType(edge_type),
                    source_id=source_id,
                    target_id=target_id,
                    weight=weight,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    event_count=event_count,
                    properties=json.loads(props_json) if props_json else {},
                )
            )

        return SecurityGraph(nodes=nodes, edges=edges)

    # ------------------------------------------------------------------
    # Timeline persistence
    # ------------------------------------------------------------------

    def save_timeline(self, inv_id: str, timeline: InvestigationTimeline) -> None:
        """Replace all timeline events for an investigation."""
        self._conn.execute("DELETE FROM timeline_events WHERE investigation_id = ?", [inv_id])
        for ev in timeline.events:
            self._conn.execute(
                """
                INSERT INTO timeline_events
                    (investigation_id, event_id, timestamp, title, description,
                     entity_type, entity_id, operation, status, tag, notes, properties_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    inv_id,
                    ev.id,
                    ev.timestamp,
                    ev.title,
                    ev.description,
                    ev.entity_type,
                    ev.entity_id,
                    ev.operation,
                    ev.status,
                    ev.tag.value,
                    ev.notes,
                    _json_dumps(ev.properties),
                ],
            )

    def load_timeline(self, inv_id: str) -> InvestigationTimeline | None:
        """Load timeline events, returning ``None`` if no events exist."""
        from secdashboards.graph.timeline import EventTag, InvestigationTimeline, TimelineEvent

        rows = self._conn.execute(
            """
            SELECT event_id, timestamp, title, description, entity_type,
                   entity_id, operation, status, tag, notes, properties_json
            FROM timeline_events
            WHERE investigation_id = ?
            ORDER BY timestamp
            """,
            [inv_id],
        ).fetchall()

        if not rows:
            return None

        events = []
        for row in rows:
            (
                event_id,
                timestamp,
                title,
                description,
                entity_type,
                entity_id,
                operation,
                status,
                tag,
                notes,
                props_json,
            ) = row
            events.append(
                TimelineEvent(
                    id=event_id,
                    timestamp=timestamp,
                    title=title,
                    description=description,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    operation=operation,
                    status=status,
                    tag=EventTag(tag),
                    notes=notes,
                    properties=json.loads(props_json) if props_json else {},
                )
            )

        return InvestigationTimeline(investigation_id=inv_id, events=events)

    def tag_event(self, inv_id: str, event_id: str, tag: str, notes: str = "") -> bool:
        """Update the tag and notes on a single timeline event.

        Returns ``True`` if the event existed, ``False`` otherwise.
        """
        exists = self._conn.execute(
            "SELECT 1 FROM timeline_events WHERE investigation_id = ? AND event_id = ?",
            [inv_id, event_id],
        ).fetchone()
        if not exists:
            return False
        self._conn.execute(
            """
            UPDATE timeline_events
            SET tag = ?, notes = ?
            WHERE investigation_id = ? AND event_id = ?
            """,
            [tag, notes, inv_id, event_id],
        )
        return True

    # ------------------------------------------------------------------
    # Artifact caching
    # ------------------------------------------------------------------

    def save_artifact(self, inv_id: str, artifact_type: str, content: str) -> None:
        """Store (or replace) a cached visualization artifact."""
        self._conn.execute(
            """
            INSERT OR REPLACE INTO artifacts
                (investigation_id, artifact_type, created_at, content)
            VALUES (?, ?, ?, ?)
            """,
            [inv_id, artifact_type, datetime.now(UTC), content],
        )

    def load_artifact(self, inv_id: str, artifact_type: str) -> str | None:
        """Load a cached artifact, returning ``None`` if not found."""
        row = self._conn.execute(
            "SELECT content FROM artifacts WHERE investigation_id = ? AND artifact_type = ?",
            [inv_id, artifact_type],
        ).fetchone()
        return row[0] if row else None

    def delete_artifacts(self, inv_id: str) -> None:
        """Remove all cached artifacts for an investigation (cache invalidation)."""
        self._conn.execute("DELETE FROM artifacts WHERE investigation_id = ?", [inv_id])

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the DuckDB connection."""
        self._conn.close()
