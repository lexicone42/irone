"""Base notification models and channel interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from secdashboards.detections.rule import Severity

if TYPE_CHECKING:
    from secdashboards.detections.rule import DetectionResult


class SecurityAlert(BaseModel):
    """Normalized alert payload for notification delivery."""

    rule_id: str
    rule_name: str
    severity: Severity = Severity.MEDIUM
    message: str = ""
    match_count: int = 0
    triggered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    sample_matches: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_detection_result(cls, result: DetectionResult) -> SecurityAlert:
        """Create a SecurityAlert from a DetectionResult."""
        return cls(
            rule_id=result.rule_id,
            rule_name=result.rule_name,
            severity=result.severity,
            message=result.message,
            match_count=result.match_count,
            triggered_at=result.executed_at,
            sample_matches=result.matches[:5],
        )


@dataclass
class NotificationResult:
    """Result of sending a notification through a channel."""

    success: bool
    channel: str
    error: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class NotificationChannel(ABC):
    """Abstract base class for notification delivery channels."""

    @property
    @abstractmethod
    def channel_name(self) -> str:
        """Unique name identifying this channel."""
        ...

    @abstractmethod
    def send(self, alert: SecurityAlert) -> NotificationResult:
        """Send an alert through this channel."""
        ...
