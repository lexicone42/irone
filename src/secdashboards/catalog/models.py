"""Data source models for the catalog."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DataSourceType(StrEnum):
    """Types of data sources supported."""

    SECURITY_LAKE = "security_lake"
    ATHENA = "athena"
    S3 = "s3"
    CLOUDWATCH_LOGS = "cloudwatch_logs"
    CUSTOM = "custom"


class DataSource(BaseModel):
    """A data source definition in the catalog."""

    name: str = Field(..., description="Unique name for this data source")
    type: DataSourceType = Field(..., description="Type of data source")
    description: str = Field(default="", description="Human-readable description")

    # Connection settings
    database: str | None = Field(default=None, description="Database name")
    table: str | None = Field(default=None, description="Table name")
    s3_location: str | None = Field(default=None, description="S3 location for data")
    region: str = Field(default="us-west-2", description="AWS region")

    # Schema info
    schema_fields: dict[str, str] = Field(
        default_factory=dict, description="Field name to type mapping"
    )

    # Custom connector settings
    connector_class: str | None = Field(
        default=None, description="Fully qualified connector class name for custom sources"
    )
    connector_config: dict[str, Any] = Field(
        default_factory=dict, description="Additional connector configuration"
    )

    # Health check settings
    health_check_query: str | None = Field(
        default=None, description="Query to run for health checks"
    )
    expected_freshness_minutes: int = Field(
        default=60, description="Expected data freshness in minutes"
    )

    # Tags for organization
    tags: list[str] = Field(default_factory=list, description="Tags for categorization")


class CatalogConfig(BaseModel):
    """Configuration for the data catalog."""

    sources: list[DataSource] = Field(default_factory=list)
    default_region: str = Field(default="us-west-2")
