"""Base connector interface for data sources."""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any

import polars as pl

from secdashboards.catalog.models import DataSource


class DataConnector(ABC):
    """Base class for data source connectors."""

    def __init__(self, source: DataSource) -> None:
        self.source = source

    @abstractmethod
    def query(self, sql: str) -> pl.DataFrame:
        """Execute a SQL query and return results as a Polars DataFrame."""
        ...

    @abstractmethod
    def get_schema(self) -> dict[str, str]:
        """Get the schema of the data source."""
        ...

    @abstractmethod
    def check_health(self) -> "HealthCheckResult":
        """Check if the data source is healthy and producing data."""
        ...

    def query_time_range(
        self,
        time_column: str,
        start: datetime,
        end: datetime,
        columns: list[str] | None = None,
        additional_filters: str | None = None,
    ) -> pl.DataFrame:
        """Query data within a time range."""
        cols = ", ".join(columns) if columns else "*"
        table = f'"{self.source.database}"."{self.source.table}"'

        sql = f"""
        SELECT {cols}
        FROM {table}
        WHERE {time_column} >= TIMESTAMP '{start.isoformat()}'
          AND {time_column} < TIMESTAMP '{end.isoformat()}'
        """

        if additional_filters:
            sql += f" AND ({additional_filters})"

        return self.query(sql)

    def get_recent_data(
        self,
        time_column: str,
        minutes: int = 60,
        columns: list[str] | None = None,
    ) -> pl.DataFrame:
        """Get data from the last N minutes."""
        end = datetime.utcnow()
        start = end - timedelta(minutes=minutes)
        return self.query_time_range(time_column, start, end, columns)


class HealthCheckResult:
    """Result of a health check on a data source."""

    def __init__(
        self,
        source_name: str,
        healthy: bool,
        last_data_time: datetime | None = None,
        record_count: int = 0,
        latency_seconds: float = 0.0,
        error: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.source_name = source_name
        self.healthy = healthy
        self.last_data_time = last_data_time
        self.record_count = record_count
        self.latency_seconds = latency_seconds
        self.error = error
        self.details = details or {}
        self.checked_at = datetime.utcnow()

    @property
    def data_age_minutes(self) -> float | None:
        """Get the age of the most recent data in minutes."""
        if not self.last_data_time:
            return None
        delta = datetime.utcnow() - self.last_data_time
        return delta.total_seconds() / 60

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "source_name": self.source_name,
            "healthy": self.healthy,
            "last_data_time": self.last_data_time.isoformat() if self.last_data_time else None,
            "data_age_minutes": self.data_age_minutes,
            "record_count": self.record_count,
            "latency_seconds": self.latency_seconds,
            "error": self.error,
            "details": self.details,
            "checked_at": self.checked_at.isoformat(),
        }
