"""SNS notification channel."""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3

from secdashboards.notifications.base import (
    NotificationChannel,
    NotificationResult,
    SecurityAlert,
)

logger = logging.getLogger(__name__)


class SNSNotifier(NotificationChannel):
    """Send security alerts to an AWS SNS topic."""

    def __init__(self, topic_arn: str, region: str = "us-west-2") -> None:
        self._topic_arn = topic_arn
        self._region = region
        self._client: Any = None

    @property
    def channel_name(self) -> str:
        return "sns"

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = boto3.client("sns", region_name=self._region)
        return self._client

    def _format_subject(self, alert: SecurityAlert) -> str:
        """Format SNS subject with severity prefix.

        SNS subjects are limited to 100 characters.
        """
        severity_tag = alert.severity.value.upper()
        subject = f"[{severity_tag}] Security Detection: {alert.rule_name}"
        return subject[:100]

    def send(self, alert: SecurityAlert) -> NotificationResult:
        """Publish alert as JSON to the SNS topic."""
        try:
            message = json.dumps(alert.model_dump(mode="json"), indent=2)
            self.client.publish(
                TopicArn=self._topic_arn,
                Subject=self._format_subject(alert),
                Message=message,
            )
            return NotificationResult(success=True, channel=self.channel_name)
        except Exception as e:
            logger.error("SNS publish failed: %s", e)
            return NotificationResult(success=False, channel=self.channel_name, error=str(e))
