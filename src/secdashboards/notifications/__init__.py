"""Alert notification integrations for security detections."""

from secdashboards.notifications.base import (
    NotificationChannel,
    NotificationResult,
    SecurityAlert,
)
from secdashboards.notifications.manager import NotificationManager
from secdashboards.notifications.slack import SlackNotifier
from secdashboards.notifications.sns import SNSNotifier

__all__ = [
    "SecurityAlert",
    "NotificationResult",
    "NotificationChannel",
    "SNSNotifier",
    "SlackNotifier",
    "NotificationManager",
]
