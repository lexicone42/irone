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
    health_cache: Any = None  # HealthCacheClient (optional, avoids hard dep)
    investigations: dict[str, Any] = field(default_factory=dict)
    operations: dict[str, dict[str, Any]] = field(default_factory=dict)


_SECURITY_LAKE_TABLES: list[tuple[str, str, str]] = [
    ("cloudtrail", "cloud_trail_mgmt_2_0", "CloudTrail management events"),
    ("vpc-flow", "vpc_flow_2_0", "VPC Flow Logs"),
    ("route53", "route53_2_0", "Route53 DNS resolver logs"),
    ("security-hub", "sh_findings_2_0", "Security Hub findings"),
    ("lambda-execution", "lambda_execution_2_0", "Lambda execution logs"),
]


def _resolve_account_id(config: WebConfig) -> str:
    """Resolve AWS account ID from config or STS.

    Returns empty string if auto-detection fails (e.g. no credentials).
    """
    if config.account_id:
        return config.account_id
    try:
        import boto3

        sts = boto3.client("sts", region_name=config.region)
        return sts.get_caller_identity()["Account"]
    except Exception:
        return ""


def _register_default_security_lake_sources(catalog: DataCatalog, config: WebConfig) -> None:
    """Auto-register well-known Security Lake tables when no catalog file provides them.

    When ``use_direct_query`` is True and an account ID is available, sources
    are registered with the ``security_lake_direct`` type (DuckDB+Iceberg).
    Otherwise falls back to the Athena-based ``security_lake`` type.
    """
    region_underscore = config.region.replace("-", "_")

    # Determine connector type and config
    use_direct = config.use_direct_query
    account_id = ""
    if use_direct:
        account_id = _resolve_account_id(config)
        if not account_id:
            use_direct = False  # Fall back to Athena if no account ID

    if use_direct:
        source_type = DataSourceType.SECURITY_LAKE_DIRECT
        connector_config: dict[str, str] = {"account_id": account_id}
    else:
        source_type = DataSourceType.SECURITY_LAKE
        connector_config = {}
        if config.athena_output:
            connector_config["output_location"] = config.athena_output

    for name, table_suffix, description in _SECURITY_LAKE_TABLES:
        table = f"amazon_security_lake_table_{region_underscore}_{table_suffix}"
        source = DataSource(
            name=name,
            type=source_type,
            database=config.security_lake_db,
            table=table,
            region=config.region,
            description=description,
            tags=["security-lake", "ocsf"],
            connector_config=connector_config,
        )
        catalog.add_source(source)


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

    # Auto-register Security Lake sources when DB is configured but no catalog provides them
    if config.security_lake_db and not catalog.list_sources(tag="security-lake"):
        _register_default_security_lake_sources(catalog, config)

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

    # Health cache (optional — empty table name = no caching)
    health_cache = None
    if config.health_cache_table:
        from secdashboards.health.cache import HealthCacheClient

        health_cache = HealthCacheClient(
            table_name=config.health_cache_table,
            region_name=config.region,
        )

    return AppState(
        config=config,
        catalog=catalog,
        runner=runner,
        duckdb=duckdb_conn,
        investigation_store=inv_store,
        health_cache=health_cache,
    )


def get_state(request: Request) -> AppState:
    """FastAPI dependency that extracts AppState from the request."""
    return request.app.state.secdash
