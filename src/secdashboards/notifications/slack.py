"""Slack webhook notification channel."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from secdashboards.detections.rule import Severity
from secdashboards.notifications.base import (
    NotificationChannel,
    NotificationResult,
    SecurityAlert,
)

logger = logging.getLogger(__name__)

# Severity → Slack attachment color (hex)
SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#dc3545",
    Severity.HIGH: "#dc3545",
    Severity.MEDIUM: "#ffc107",
    Severity.LOW: "#17a2b8",
    Severity.INFO: "#6c757d",
}

# Severity → emoji prefix
SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "\U0001f6a8",  # 🚨
    Severity.HIGH: "\U0001f6a8",  # 🚨
    Severity.MEDIUM: "\u26a0\ufe0f",  # ⚠️
    Severity.LOW: "\u2139\ufe0f",  # ℹ️
    Severity.INFO: "\U0001f4e2",  # 📢
}


class SlackNotifier(NotificationChannel):
    """Send security alerts to a Slack incoming webhook."""

    def __init__(self, webhook_url: str, channel: str | None = None) -> None:
        if not webhook_url.startswith("https://"):
            raise ValueError("webhook_url must use HTTPS")
        self._webhook_url = webhook_url
        self._channel = channel

    @property
    def channel_name(self) -> str:
        return "slack"

    def _format_slack_payload(self, alert: SecurityAlert) -> dict[str, Any]:
        """Build Slack attachment payload with severity color-coding."""
        color = SEVERITY_COLORS.get(alert.severity, "#6c757d")
        emoji = SEVERITY_EMOJI.get(alert.severity, "\U0001f4e2")

        fields = [
            {"title": "Rule", "value": alert.rule_id, "short": True},
            {"title": "Severity", "value": alert.severity.value.upper(), "short": True},
            {"title": "Matches", "value": str(alert.match_count), "short": True},
        ]

        attachment: dict[str, Any] = {
            "color": color,
            "title": f"{emoji} {alert.rule_name}",
            "text": alert.message,
            "fields": fields,
            "footer": "secdashboards",
            "ts": int(alert.triggered_at.timestamp()),
        }

        payload: dict[str, Any] = {"attachments": [attachment]}
        if self._channel:
            payload["channel"] = self._channel
        return payload

    def send(self, alert: SecurityAlert) -> NotificationResult:
        """Post alert to the Slack webhook."""
        try:
            payload = self._format_slack_payload(alert)
            response = httpx.post(self._webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            return NotificationResult(success=True, channel=self.channel_name)
        except Exception as e:
            logger.error("Slack webhook failed: %s", e)
            return NotificationResult(success=False, channel=self.channel_name, error=str(e))
