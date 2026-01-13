"""Tests for the data catalog module."""

import tempfile
from pathlib import Path

import pytest

from secdashboards.catalog.models import DataSource, DataSourceType
from secdashboards.catalog.registry import DataCatalog


class TestDataSource:
    """Tests for DataSource model."""

    def test_create_security_lake_source(self) -> None:
        source = DataSource(
            name="test-source",
            type=DataSourceType.SECURITY_LAKE,
            database="test_db",
            table="test_table",
            region="us-west-2",
        )
        assert source.name == "test-source"
        assert source.type == DataSourceType.SECURITY_LAKE
        assert source.region == "us-west-2"

    def test_default_values(self) -> None:
        source = DataSource(name="minimal", type=DataSourceType.ATHENA)
        assert source.region == "us-west-2"
        assert source.expected_freshness_minutes == 60
        assert source.tags == []


class TestDataCatalog:
    """Tests for DataCatalog registry."""

    def test_add_and_get_source(self) -> None:
        catalog = DataCatalog()
        source = DataSource(
            name="test",
            type=DataSourceType.SECURITY_LAKE,
            database="db",
            table="tbl",
        )
        catalog.add_source(source)

        retrieved = catalog.get_source("test")
        assert retrieved is not None
        assert retrieved.name == "test"
        assert retrieved.database == "db"

    def test_list_sources(self) -> None:
        catalog = DataCatalog()
        catalog.add_source(
            DataSource(name="source1", type=DataSourceType.ATHENA, tags=["tag1"])
        )
        catalog.add_source(
            DataSource(name="source2", type=DataSourceType.S3, tags=["tag2"])
        )

        all_sources = catalog.list_sources()
        assert len(all_sources) == 2

        tagged = catalog.list_sources(tag="tag1")
        assert len(tagged) == 1
        assert tagged[0].name == "source1"

    def test_create_security_lake_source_helper(self) -> None:
        catalog = DataCatalog()
        source = catalog.create_security_lake_source(
            name="cloudtrail",
            database="sl_db",
            table="cloudtrail_table",
            region="us-west-2",
        )

        assert source.name == "cloudtrail"
        assert source.type == DataSourceType.SECURITY_LAKE
        assert "security-lake" in source.tags
        assert catalog.get_source("cloudtrail") is not None

    def test_save_and_load_catalog(self) -> None:
        catalog = DataCatalog()
        catalog.add_source(
            DataSource(
                name="test-source",
                type=DataSourceType.SECURITY_LAKE,
                database="test_db",
                table="test_table",
                description="Test description",
            )
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "catalog.yaml"
            catalog.save_to_file(config_path)

            # Load into new catalog
            new_catalog = DataCatalog(config_path)
            source = new_catalog.get_source("test-source")

            assert source is not None
            assert source.database == "test_db"
            assert source.description == "Test description"

    def test_get_nonexistent_source(self) -> None:
        catalog = DataCatalog()
        assert catalog.get_source("nonexistent") is None

    def test_get_connector_unknown_source(self) -> None:
        catalog = DataCatalog()
        with pytest.raises(ValueError, match="Unknown data source"):
            catalog.get_connector("nonexistent")
