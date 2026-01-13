"""Detection rule definitions and models."""

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import polars as pl
from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Detection severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionResult(BaseModel):
    """Result of running a detection rule."""

    rule_id: str
    rule_name: str
    triggered: bool = False
    severity: Severity = Severity.INFO
    match_count: int = 0
    matches: list[dict[str, Any]] = Field(default_factory=list)
    message: str = ""
    executed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    execution_time_ms: float = 0.0
    error: str | None = None

    def to_alert_dict(self) -> dict[str, Any]:
        """Convert to alert payload for notifications."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "match_count": self.match_count,
            "message": self.message,
            "executed_at": self.executed_at.isoformat(),
            "sample_matches": self.matches[:5],  # Limit for payload size
        }


class DetectionMetadata(BaseModel):
    """Metadata for a detection rule."""

    id: str = Field(..., description="Unique identifier for the rule")
    name: str = Field(..., description="Human-readable name")
    description: str = Field(default="", description="Detailed description")
    author: str = Field(default="", description="Rule author")
    severity: Severity = Field(default=Severity.MEDIUM)
    tags: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    data_sources: list[str] = Field(default_factory=list, description="Required data source names")
    schedule: str = Field(default="rate(5 minutes)", description="CloudWatch schedule expression")
    enabled: bool = Field(default=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DetectionRule(ABC):
    """Base class for detection rules."""

    def __init__(self, metadata: DetectionMetadata) -> None:
        self.metadata = metadata

    @property
    def id(self) -> str:
        return self.metadata.id

    @property
    def name(self) -> str:
        return self.metadata.name

    @abstractmethod
    def get_query(self, start: datetime, end: datetime) -> str:
        """Get the SQL query for this detection.

        Args:
            start: Start of the time window to analyze
            end: End of the time window to analyze

        Returns:
            SQL query string
        """
        ...

    @abstractmethod
    def evaluate(self, df: pl.DataFrame) -> DetectionResult:
        """Evaluate query results and determine if detection triggered.

        Args:
            df: Query results as a Polars DataFrame

        Returns:
            DetectionResult with findings
        """
        ...

    def to_dict(self) -> dict[str, Any]:
        """Serialize rule metadata to dictionary."""
        return self.metadata.model_dump(mode="json")


class SQLDetectionRule(DetectionRule):
    """A detection rule defined primarily by a SQL query."""

    def __init__(
        self,
        metadata: DetectionMetadata,
        query_template: str,
        threshold: int = 1,
        group_by_fields: list[str] | None = None,
    ) -> None:
        super().__init__(metadata)
        self.query_template = query_template
        self.threshold = threshold
        self.group_by_fields = group_by_fields or []

    @staticmethod
    def _format_timestamp(dt: datetime) -> str:
        """Format datetime for Athena TIMESTAMP literal.

        Athena requires format: 'YYYY-MM-DD HH:MM:SS.ffffff'
        Python's isoformat() returns: 'YYYY-MM-DDTHH:MM:SS.ffffff+00:00'
        """
        # Remove timezone info and format with space separator
        dt_naive = dt.replace(tzinfo=None) if dt.tzinfo else dt
        return dt_naive.strftime("%Y-%m-%d %H:%M:%S.%f")

    def get_query(self, start: datetime, end: datetime) -> str:
        """Render the query template with time bounds."""
        return self.query_template.format(
            start_time=self._format_timestamp(start),
            end_time=self._format_timestamp(end),
        )

    def evaluate(self, df: pl.DataFrame) -> DetectionResult:
        """Evaluate if detection threshold is met."""
        start_time = datetime.now(UTC)

        match_count = len(df)
        triggered = match_count >= self.threshold

        # Convert matches to list of dicts
        matches = df.head(100).to_dicts() if triggered else []

        # Generate message
        if triggered:
            message = (
                f"Detection '{self.name}' triggered with "
                f"{match_count} matches (threshold: {self.threshold})"
            )
        else:
            message = (
                f"Detection '{self.name}' did not trigger "
                f"({match_count} matches, threshold: {self.threshold})"
            )

        execution_time = (datetime.now(UTC) - start_time).total_seconds() * 1000

        return DetectionResult(
            rule_id=self.id,
            rule_name=self.name,
            triggered=triggered,
            severity=self.metadata.severity,
            match_count=match_count,
            matches=matches,
            message=message,
            execution_time_ms=execution_time,
        )
