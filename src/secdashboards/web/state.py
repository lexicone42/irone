"""Application state management and FastAPI dependency injection."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import Request

from secdashboards.catalog.models import DataSource, DataSourceType
from secdashboards.catalog.registry import DataCatalog
from secdashboards.connectors.duckdb import DuckDBConnector
from secdashboards.detections.runner import DetectionRunner
from secdashboards.graph.persistence import InvestigationStore
from secdashboards.web.config import WebConfig


@dataclass
class AppState:
    """Shared application state injected into route handlers."""

    config: WebConfig
    catalog: DataCatalog
    runner: DetectionRunner
    duckdb: DuckDBConnector
    investigation_store: InvestigationStore | None = None
    investigations: dict[str, Any] = field(default_factory=dict)
    operations: dict[str, dict[str, Any]] = field(default_factory=dict)


def create_app_state(config: WebConfig | None = None) -> AppState:
    """Build application state from config.

    Creates the data catalog, registers a DuckDB source, and loads
    detection rules from the configured rules directory.
    """
    config = config or WebConfig()

    # Build catalog
    catalog_path = Path(config.catalog_path) if config.catalog_path else None
    catalog = DataCatalog(catalog_path)

    # Register DuckDB source
    duckdb_source = DataSource(
        name="duckdb-local",
        type=DataSourceType.DUCKDB,
        description="Local DuckDB engine",
        connector_config={"db_path": config.duckdb_path},
        tags=["local", "duckdb"],
    )
    catalog.add_source(duckdb_source)
    duckdb_conn = catalog.get_connector("duckdb-local")
    assert isinstance(duckdb_conn, DuckDBConnector)

    # Build detection runner and load rules
    runner = DetectionRunner(catalog)
    if config.rules_dir:
        rules_path = Path(config.rules_dir)
        if rules_path.exists():
            runner.load_rules_from_directory(rules_path)

    # Investigation persistence (optional — empty path = no persistence)
    inv_store: InvestigationStore | None = None
    if config.investigations_db_path:
        inv_store = InvestigationStore(db_path=config.investigations_db_path)

    return AppState(
        config=config,
        catalog=catalog,
        runner=runner,
        duckdb=duckdb_conn,
        investigation_store=inv_store,
    )


def get_state(request: Request) -> AppState:
    """FastAPI dependency that extracts AppState from the request."""
    return request.app.state.secdash
