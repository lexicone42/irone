"""Tests for the notifications module."""

import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import httpx
import pytest

from secdashboards.detections.rule import DetectionResult, Severity
from secdashboards.notifications.base import (
    NotificationChannel,
    NotificationResult,
    SecurityAlert,
)
from secdashboards.notifications.manager import NotificationManager
from secdashboards.notifications.slack import (
    SEVERITY_COLORS,
    SlackNotifier,
)
from secdashboards.notifications.sns import SNSNotifier

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_detection_result(**overrides) -> DetectionResult:
    """Create a DetectionResult with sensible defaults."""
    defaults = {
        "rule_id": "detect-001",
        "rule_name": "Suspicious Login",
        "triggered": True,
        "severity": Severity.HIGH,
        "match_count": 3,
        "matches": [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}, {"ip": "10.0.0.3"}],
        "message": "3 suspicious logins detected",
    }
    defaults.update(overrides)
    return DetectionResult(**defaults)


def _make_alert(**overrides) -> SecurityAlert:
    """Create a SecurityAlert with sensible defaults."""
    defaults = {
        "rule_id": "detect-001",
        "rule_name": "Suspicious Login",
        "severity": Severity.HIGH,
        "message": "3 suspicious logins detected",
        "match_count": 3,
        "sample_matches": [{"ip": "10.0.0.1"}],
    }
    defaults.update(overrides)
    return SecurityAlert(**defaults)


class _FakeChannel(NotificationChannel):
    """Stub channel for manager tests."""

    def __init__(self, name: str = "fake", succeed: bool = True) -> None:
        self._name = name
        self._succeed = succeed
        self.sent: list[SecurityAlert] = []

    @property
    def channel_name(self) -> str:
        return self._name

    def send(self, alert: SecurityAlert) -> NotificationResult:
        self.sent.append(alert)
        if self._succeed:
            return NotificationResult(success=True, channel=self._name)
        return NotificationResult(success=False, channel=self._name, error="boom")


# ---------------------------------------------------------------------------
# TestSecurityAlert
# ---------------------------------------------------------------------------


class TestSecurityAlert:
    """Tests for the SecurityAlert Pydantic model."""

    def test_create_alert(self) -> None:
        alert = _make_alert()
        assert alert.rule_id == "detect-001"
        assert alert.severity == Severity.HIGH
        assert alert.match_count == 3

    def test_default_triggered_at(self) -> None:
        alert = SecurityAlert(rule_id="r", rule_name="R")
        assert isinstance(alert.triggered_at, datetime)
        assert alert.triggered_at.tzinfo is not None

    def test_from_detection_result(self) -> None:
        result = _make_detection_result()
        alert = SecurityAlert.from_detection_result(result)

        assert alert.rule_id == result.rule_id
        assert alert.rule_name == result.rule_name
        assert alert.severity == result.severity
        assert alert.message == result.message
        assert alert.match_count == result.match_count
        assert alert.triggered_at == result.executed_at
        assert len(alert.sample_matches) <= 5

    def test_from_detection_result_limits_matches(self) -> None:
        matches = [{"i": i} for i in range(20)]
        result = _make_detection_result(matches=matches)
        alert = SecurityAlert.from_detection_result(result)
        assert len(alert.sample_matches) == 5

    def test_serialization_roundtrip(self) -> None:
        alert = _make_alert()
        data = alert.model_dump(mode="json")
        restored = SecurityAlert.model_validate(data)
        assert restored.rule_id == alert.rule_id
        assert restored.severity == alert.severity


# ---------------------------------------------------------------------------
# TestSNSNotifier
# ---------------------------------------------------------------------------


class TestSNSNotifier:
    """Tests for the SNS notification channel."""

    def test_channel_name(self) -> None:
        notifier = SNSNotifier(topic_arn="arn:aws:sns:us-west-2:123:alerts")
        assert notifier.channel_name == "sns"

    def test_send_success(self) -> None:
        notifier = SNSNotifier(topic_arn="arn:aws:sns:us-west-2:123:alerts")
        mock_client = MagicMock()
        notifier._client = mock_client

        alert = _make_alert()
        result = notifier.send(alert)

        assert result.success is True
        assert result.channel == "sns"
        mock_client.publish.assert_called_once()
        call_kwargs = mock_client.publish.call_args[1]
        assert call_kwargs["TopicArn"] == "arn:aws:sns:us-west-2:123:alerts"
        assert "[HIGH]" in call_kwargs["Subject"]
        # Message is valid JSON
        json.loads(call_kwargs["Message"])

    def test_send_failure(self) -> None:
        notifier = SNSNotifier(topic_arn="arn:aws:sns:us-west-2:123:alerts")
        mock_client = MagicMock()
        mock_client.publish.side_effect = Exception("access denied")
        notifier._client = mock_client

        result = notifier.send(_make_alert())

        assert result.success is False
        assert "access denied" in result.error

    def test_subject_formatting(self) -> None:
        notifier = SNSNotifier(topic_arn="arn:aws:sns:us-west-2:123:alerts")

        for severity in Severity:
            alert = _make_alert(severity=severity)
            subject = notifier._format_subject(alert)
            assert subject.startswith(f"[{severity.value.upper()}]")
            assert len(subject) <= 100

    def test_subject_truncation(self) -> None:
        notifier = SNSNotifier(topic_arn="arn:aws:sns:us-west-2:123:alerts")
        alert = _make_alert(rule_name="A" * 200)
        subject = notifier._format_subject(alert)
        assert len(subject) <= 100

    def test_lazy_client(self) -> None:
        notifier = SNSNotifier(topic_arn="arn:aws:sns:us-west-2:123:alerts")
        assert notifier._client is None
        with patch("secdashboards.notifications.sns.boto3") as mock_boto3:
            _ = notifier.client
            mock_boto3.client.assert_called_once_with("sns", region_name="us-west-2")

    def test_rejects_invalid_arn(self) -> None:
        with pytest.raises(ValueError, match="valid SNS ARN"):
            SNSNotifier(topic_arn="not-an-arn")

    def test_rejects_non_sns_arn(self) -> None:
        with pytest.raises(ValueError, match="valid SNS ARN"):
            SNSNotifier(topic_arn="arn:aws:sqs:us-west-2:123:my-queue")


# ---------------------------------------------------------------------------
# TestSlackNotifier
# ---------------------------------------------------------------------------


class TestSlackNotifier:
    """Tests for the Slack webhook notification channel."""

    def test_channel_name(self) -> None:
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/test")
        assert notifier.channel_name == "slack"

    def test_rejects_http_url(self) -> None:
        with pytest.raises(ValueError, match="HTTPS"):
            SlackNotifier(webhook_url="http://hooks.slack.com/test")

    def test_rejects_non_url(self) -> None:
        with pytest.raises(ValueError, match="HTTPS"):
            SlackNotifier(webhook_url="not-a-url")

    def test_send_success(self) -> None:
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/test")
        alert = _make_alert()

        with patch("secdashboards.notifications.slack.httpx.post") as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_post.return_value = mock_response

            result = notifier.send(alert)

        assert result.success is True
        assert result.channel == "slack"
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        payload = call_kwargs["json"]
        assert "attachments" in payload
        assert payload["attachments"][0]["color"] == "#dc3545"  # HIGH color

    def test_send_failure(self) -> None:
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/test")

        with patch("secdashboards.notifications.slack.httpx.post") as mock_post:
            mock_post.side_effect = httpx.HTTPStatusError(
                "403", request=MagicMock(), response=MagicMock()
            )
            result = notifier.send(_make_alert())

        assert result.success is False
        assert result.error is not None

    def test_payload_structure(self) -> None:
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/test", channel="#alerts")
        alert = _make_alert()
        payload = notifier._format_slack_payload(alert)

        assert payload["channel"] == "#alerts"
        attachment = payload["attachments"][0]
        assert "color" in attachment
        assert "title" in attachment
        assert "text" in attachment
        assert "fields" in attachment
        assert attachment["footer"] == "secdashboards"

        # Check fields content
        field_titles = [f["title"] for f in attachment["fields"]]
        assert "Rule" in field_titles
        assert "Severity" in field_titles
        assert "Matches" in field_titles

    def test_color_mapping(self) -> None:
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/test")
        for severity in Severity:
            alert = _make_alert(severity=severity)
            payload = notifier._format_slack_payload(alert)
            color = payload["attachments"][0]["color"]
            assert color == SEVERITY_COLORS[severity]

    def test_no_channel_override(self) -> None:
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/test")
        payload = notifier._format_slack_payload(_make_alert())
        assert "channel" not in payload


# ---------------------------------------------------------------------------
# TestNotificationManager
# ---------------------------------------------------------------------------


class TestNotificationManager:
    """Tests for multi-channel alert routing."""

    def test_add_and_remove_channel(self) -> None:
        mgr = NotificationManager()
        ch = _FakeChannel("test")
        mgr.add_channel(ch)
        assert len(mgr.channels) == 1

        mgr.remove_channel("test")
        assert len(mgr.channels) == 0

    def test_init_with_channels(self) -> None:
        mgr = NotificationManager(channels=[_FakeChannel("a"), _FakeChannel("b")])
        assert len(mgr.channels) == 2

    def test_notify_sends_to_all(self) -> None:
        ch1 = _FakeChannel("ch1")
        ch2 = _FakeChannel("ch2")
        mgr = NotificationManager(channels=[ch1, ch2])

        alert = _make_alert()
        results = mgr.notify(alert)

        assert len(results) == 2
        assert all(r.success for r in results)
        assert len(ch1.sent) == 1
        assert len(ch2.sent) == 1

    def test_severity_filter_blocks(self) -> None:
        ch = _FakeChannel("ch")
        mgr = NotificationManager(channels=[ch], severity_filter=Severity.HIGH)

        low_alert = _make_alert(severity=Severity.LOW)
        results = mgr.notify(low_alert)

        assert results == []
        assert len(ch.sent) == 0

    def test_severity_filter_passes(self) -> None:
        ch = _FakeChannel("ch")
        mgr = NotificationManager(channels=[ch], severity_filter=Severity.MEDIUM)

        high_alert = _make_alert(severity=Severity.HIGH)
        results = mgr.notify(high_alert)

        assert len(results) == 1
        assert len(ch.sent) == 1

    def test_severity_filter_exact_threshold(self) -> None:
        ch = _FakeChannel("ch")
        mgr = NotificationManager(channels=[ch], severity_filter=Severity.MEDIUM)

        medium_alert = _make_alert(severity=Severity.MEDIUM)
        results = mgr.notify(medium_alert)

        assert len(results) == 1

    def test_partial_failure(self) -> None:
        good = _FakeChannel("good", succeed=True)
        bad = _FakeChannel("bad", succeed=False)
        mgr = NotificationManager(channels=[good, bad])

        results = mgr.notify(_make_alert())

        assert len(results) == 2
        successes = [r for r in results if r.success]
        failures = [r for r in results if not r.success]
        assert len(successes) == 1
        assert len(failures) == 1
        # Good channel still received the alert
        assert len(good.sent) == 1

    def test_notify_detection(self) -> None:
        ch = _FakeChannel("ch")
        mgr = NotificationManager(channels=[ch])

        detection = _make_detection_result()
        results = mgr.notify_detection(detection)

        assert len(results) == 1
        assert ch.sent[0].rule_id == detection.rule_id


# ---------------------------------------------------------------------------
# TestIntegration
# ---------------------------------------------------------------------------


class TestIntegration:
    """End-to-end: DetectionResult → SecurityAlert → Manager → Channels."""

    def test_full_pipeline(self) -> None:
        """Detection result flows through manager to multiple mocked channels."""
        detection = _make_detection_result(
            severity=Severity.CRITICAL,
            match_count=10,
            matches=[{"ip": f"10.0.0.{i}"} for i in range(10)],
        )

        sns_channel = _FakeChannel("sns")
        slack_channel = _FakeChannel("slack")
        mgr = NotificationManager(channels=[sns_channel, slack_channel])

        results = mgr.notify_detection(detection)

        assert len(results) == 2
        assert all(r.success for r in results)

        # Both channels received the same alert
        sns_alert = sns_channel.sent[0]
        slack_alert = slack_channel.sent[0]
        assert sns_alert.rule_id == slack_alert.rule_id == "detect-001"
        assert sns_alert.severity == Severity.CRITICAL
        assert sns_alert.match_count == 10
        # Sample matches capped at 5
        assert len(sns_alert.sample_matches) == 5

    def test_filtered_pipeline(self) -> None:
        """Low-severity detection is filtered out by manager."""
        detection = _make_detection_result(severity=Severity.LOW)
        ch = _FakeChannel("ch")
        mgr = NotificationManager(channels=[ch], severity_filter=Severity.HIGH)

        results = mgr.notify_detection(detection)

        assert results == []
        assert len(ch.sent) == 0

    def test_sns_notifier_with_detection_result(self) -> None:
        """SNS notifier receives properly formatted alert from DetectionResult."""
        notifier = SNSNotifier(topic_arn="arn:aws:sns:us-west-2:123:alerts")
        mock_client = MagicMock()
        notifier._client = mock_client

        detection = _make_detection_result()
        alert = SecurityAlert.from_detection_result(detection)
        result = notifier.send(alert)

        assert result.success is True
        call_kwargs = mock_client.publish.call_args[1]
        message_body = json.loads(call_kwargs["Message"])
        assert message_body["rule_id"] == "detect-001"
        assert message_body["severity"] == "high"
