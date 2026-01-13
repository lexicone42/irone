"""Data catalog registry for managing data sources."""

from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from pydantic import TypeAdapter

from secdashboards.catalog.models import CatalogConfig, DataSource, DataSourceType

if TYPE_CHECKING:
    from secdashboards.connectors.base import DataConnector


class DataCatalog:
    """Registry for data sources with easy connector instantiation."""

    def __init__(self, config_path: Path | None = None) -> None:
        self._sources: dict[str, DataSource] = {}
        self._connectors: dict[str, type[DataConnector]] = {}
        self._register_builtin_connectors()

        if config_path and config_path.exists():
            self.load_from_file(config_path)

    def _register_builtin_connectors(self) -> None:
        """Register built-in connector types."""
        from secdashboards.connectors.athena import AthenaConnector
        from secdashboards.connectors.security_lake import SecurityLakeConnector

        self._connectors[DataSourceType.SECURITY_LAKE] = SecurityLakeConnector
        self._connectors[DataSourceType.ATHENA] = AthenaConnector

    def register_connector(
        self, source_type: DataSourceType | str, connector_class: type["DataConnector"]
    ) -> None:
        """Register a custom connector class for a source type."""
        self._connectors[str(source_type)] = connector_class

    def add_source(self, source: DataSource) -> None:
        """Add a data source to the catalog."""
        self._sources[source.name] = source

    def get_source(self, name: str) -> DataSource | None:
        """Get a data source by name."""
        return self._sources.get(name)

    def list_sources(self, tag: str | None = None) -> list[DataSource]:
        """List all data sources, optionally filtered by tag."""
        sources = list(self._sources.values())
        if tag:
            sources = [s for s in sources if tag in s.tags]
        return sources

    def get_connector(self, source_name: str) -> "DataConnector":
        """Get a connector instance for a data source."""
        source = self._sources.get(source_name)
        if not source:
            raise ValueError(f"Unknown data source: {source_name}")

        connector_class = self._connectors.get(str(source.type))
        if not connector_class:
            raise ValueError(f"No connector registered for source type: {source.type}")

        return connector_class(source)

    def load_from_file(self, path: Path) -> None:
        """Load catalog configuration from a YAML file."""
        with path.open() as f:
            data = yaml.safe_load(f)

        config = TypeAdapter(CatalogConfig).validate_python(data)
        for source in config.sources:
            self.add_source(source)

    def save_to_file(self, path: Path) -> None:
        """Save catalog configuration to a YAML file."""
        config = CatalogConfig(sources=list(self._sources.values()))
        with path.open("w") as f:
            yaml.dump(config.model_dump(mode="json"), f, default_flow_style=False, sort_keys=False)

    def create_security_lake_source(
        self,
        name: str,
        database: str = "amazon_security_lake_glue_db_us_west_2",
        table: str = "amazon_security_lake_table_us_west_2_cloud_trail_mgmt_2_0",
        region: str = "us-west-2",
        **kwargs: object,
    ) -> DataSource:
        """Helper to create a Security Lake data source with common defaults."""
        source = DataSource(
            name=name,
            type=DataSourceType.SECURITY_LAKE,
            database=database,
            table=table,
            region=region,
            tags=["security-lake", "ocsf"],
            **kwargs,  # type: ignore[arg-type]
        )
        self.add_source(source)
        return source
