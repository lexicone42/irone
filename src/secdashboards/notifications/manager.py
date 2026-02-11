"""Notification manager for routing alerts to multiple channels."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from secdashboards.detections.rule import Severity
from secdashboards.notifications.base import (
    NotificationChannel,
    NotificationResult,
    SecurityAlert,
)

if TYPE_CHECKING:
    from secdashboards.detections.rule import DetectionResult

logger = logging.getLogger(__name__)

# Severity ordering for threshold filtering
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class NotificationManager:
    """Route security alerts to one or more notification channels.

    Optionally filters alerts below a minimum severity threshold.
    """

    def __init__(
        self,
        channels: list[NotificationChannel] | None = None,
        severity_filter: Severity | None = None,
    ) -> None:
        self._channels: dict[str, NotificationChannel] = {}
        for ch in channels or []:
            self._channels[ch.channel_name] = ch
        self._severity_filter = severity_filter

    def add_channel(self, channel: NotificationChannel) -> None:
        """Register a notification channel."""
        self._channels[channel.channel_name] = channel

    def remove_channel(self, name: str) -> None:
        """Remove a notification channel by name."""
        self._channels.pop(name, None)

    @property
    def channels(self) -> list[NotificationChannel]:
        return list(self._channels.values())

    def _passes_filter(self, alert: SecurityAlert) -> bool:
        """Check if alert severity meets the minimum threshold."""
        if self._severity_filter is None:
            return True
        return _SEVERITY_ORDER.get(alert.severity, 0) >= _SEVERITY_ORDER.get(
            self._severity_filter, 0
        )

    def notify(self, alert: SecurityAlert) -> list[NotificationResult]:
        """Send an alert to all registered channels.

        Returns a list of results, one per channel. Channels that fail
        do not prevent delivery to other channels.
        """
        if not self._passes_filter(alert):
            logger.debug(
                "Alert %s filtered out (severity %s below threshold %s)",
                alert.rule_id,
                alert.severity,
                self._severity_filter,
            )
            return []

        results: list[NotificationResult] = []
        for channel in self._channels.values():
            result = channel.send(alert)
            results.append(result)
            if not result.success:
                logger.warning(
                    "Channel %s failed for alert %s: %s",
                    channel.channel_name,
                    alert.rule_id,
                    result.error,
                )
        return results

    def notify_detection(self, result: DetectionResult) -> list[NotificationResult]:
        """Convenience: convert a DetectionResult and notify all channels."""
        alert = SecurityAlert.from_detection_result(result)
        return self.notify(alert)
