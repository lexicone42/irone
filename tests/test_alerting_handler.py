"""Tests for the alerting Lambda handler (alerting_handler.py).

Covers:
- Detection runner integration via run_detections()
- Alert generation for triggered detection results
- Error handling for failed detections
- Event payload filtering (rule_ids, lookback_minutes)
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from secdashboards.detections.rule import (
    DetectionMetadata,
    DetectionResult,
    Severity,
    SQLDetectionRule,
)


@pytest.fixture()
def sample_rule() -> SQLDetectionRule:
    """A sample SQL detection rule."""
    metadata = DetectionMetadata(
        id="test-root-login",
        name="Root User Login",
        description="Detect root user console logins",
        severity=Severity.HIGH,
        schedule="rate(15 minutes)",
        enabled=True,
        tags=["iam"],
        mitre_attack=["T1078"],
    )
    return SQLDetectionRule(
        metadata=metadata,
        query_template=(
            "SELECT * FROM {database}.{table} "
            "WHERE actor_user = 'root' "
            "AND time_dt >= TIMESTAMP '{start_time}' "
            "AND time_dt < TIMESTAMP '{end_time}'"
        ),
        threshold=1,
    )


def _reload_handler(**env_overrides):
    """Reload the handler module with patched environment variables."""
    import importlib

    import secdashboards.health.alerting_handler as handler_mod

    importlib.reload(handler_mod)
    return handler_mod


class TestRunDetections:
    """Tests for the run_detections function."""

    @patch("secdashboards.detections.runner.DetectionRunner")
    @patch("secdashboards.detections.rule_store.S3RuleStore")
    @patch("secdashboards.catalog.registry.DataCatalog")
    def test_triggered_detection_produces_alert(
        self, mock_catalog_cls, mock_store_cls, mock_runner_cls, sample_rule
    ):
        """Triggered detections produce DETECTION alert dicts."""
        triggered = DetectionResult(
            rule_id="test-root-login",
            rule_name="Root User Login",
            triggered=True,
            severity=Severity.HIGH,
            match_count=2,
            matches=[{"actor_user": "root"}],
            message="Root user login detected",
        )

        mock_store = MagicMock()
        mock_store.load_all_rules.return_value = [(sample_rule, MagicMock())]
        mock_store_cls.return_value = mock_store

        mock_runner = MagicMock()
        mock_runner.run_all.return_value = [triggered]
        mock_runner.list_rules.return_value = ["test-root-login"]
        mock_runner_cls.return_value = mock_runner

        mock_catalog = MagicMock()
        mock_catalog.get_connector.return_value = MagicMock()
        mock_catalog_cls.return_value = mock_catalog

        with patch.dict(
            "os.environ",
            {
                "RULES_BUCKET": "my-rules-bucket",
                "RULES_PREFIX": "rules/",
                "SECURITY_LAKE_DB": "test_db",
                "ATHENA_OUTPUT": "s3://test-output/",
            },
        ):
            handler_mod = _reload_handler()
            alerts = handler_mod.run_detections({"check_type": "detections"})

        assert len(alerts) == 1
        assert alerts[0]["type"] == "DETECTION"
        assert alerts[0]["severity"] == "high"
        assert alerts[0]["source"] == "test-root-login"
        assert alerts[0]["match_count"] == 2

    @patch("secdashboards.detections.runner.DetectionRunner")
    @patch("secdashboards.detections.rule_store.S3RuleStore")
    @patch("secdashboards.catalog.registry.DataCatalog")
    def test_not_triggered_produces_no_alerts(
        self, mock_catalog_cls, mock_store_cls, mock_runner_cls, sample_rule
    ):
        """Non-triggered detections produce no alerts."""
        not_triggered = DetectionResult(
            rule_id="test-root-login",
            rule_name="Root User Login",
            triggered=False,
            severity=Severity.HIGH,
            match_count=0,
        )

        mock_store = MagicMock()
        mock_store.load_all_rules.return_value = [(sample_rule, MagicMock())]
        mock_store_cls.return_value = mock_store

        mock_runner = MagicMock()
        mock_runner.run_all.return_value = [not_triggered]
        mock_runner_cls.return_value = mock_runner

        mock_catalog = MagicMock()
        mock_catalog.get_connector.return_value = MagicMock()
        mock_catalog_cls.return_value = mock_catalog

        with patch.dict(
            "os.environ",
            {
                "RULES_BUCKET": "my-rules-bucket",
                "SECURITY_LAKE_DB": "test_db",
                "ATHENA_OUTPUT": "s3://test-output/",
            },
        ):
            handler_mod = _reload_handler()
            alerts = handler_mod.run_detections({"check_type": "detections"})

        assert len(alerts) == 0

    @patch("secdashboards.detections.runner.DetectionRunner")
    @patch("secdashboards.detections.rule_store.S3RuleStore")
    @patch("secdashboards.catalog.registry.DataCatalog")
    def test_error_result_produces_detection_error_alert(
        self, mock_catalog_cls, mock_store_cls, mock_runner_cls, sample_rule
    ):
        """Detection errors produce DETECTION_ERROR alerts."""
        error_result = DetectionResult(
            rule_id="test-broken",
            rule_name="Broken Rule",
            triggered=False,
            error="Column not found",
        )

        mock_store = MagicMock()
        mock_store.load_all_rules.return_value = [(sample_rule, MagicMock())]
        mock_store_cls.return_value = mock_store

        mock_runner = MagicMock()
        mock_runner.run_all.return_value = [error_result]
        mock_runner_cls.return_value = mock_runner

        mock_catalog = MagicMock()
        mock_catalog.get_connector.return_value = MagicMock()
        mock_catalog_cls.return_value = mock_catalog

        with patch.dict(
            "os.environ",
            {
                "RULES_BUCKET": "my-rules-bucket",
                "SECURITY_LAKE_DB": "test_db",
                "ATHENA_OUTPUT": "s3://test-output/",
            },
        ):
            handler_mod = _reload_handler()
            alerts = handler_mod.run_detections({"check_type": "detections"})

        assert len(alerts) == 1
        assert alerts[0]["type"] == "DETECTION_ERROR"
        assert alerts[0]["severity"] == "low"
        assert "Column not found" in alerts[0]["message"]

    @patch("secdashboards.catalog.registry.DataCatalog")
    def test_no_rules_bucket_returns_empty(self, mock_catalog_cls):
        """Returns empty list when no RULES_BUCKET is configured."""
        mock_catalog = MagicMock()
        mock_catalog.get_connector.return_value = MagicMock()
        mock_catalog_cls.return_value = mock_catalog

        with patch.dict(
            "os.environ",
            {
                "RULES_BUCKET": "",
                "SECURITY_LAKE_DB": "test_db",
                "ATHENA_OUTPUT": "s3://test-output/",
            },
        ):
            handler_mod = _reload_handler()
            alerts = handler_mod.run_detections({"check_type": "detections"})

        assert alerts == []

    @patch("secdashboards.detections.runner.DetectionRunner")
    @patch("secdashboards.detections.rule_store.S3RuleStore")
    @patch("secdashboards.catalog.registry.DataCatalog")
    def test_lookback_override_from_event(
        self, mock_catalog_cls, mock_store_cls, mock_runner_cls, sample_rule
    ):
        """Custom lookback_minutes from event overrides environment default."""
        mock_store = MagicMock()
        mock_store.load_all_rules.return_value = [(sample_rule, MagicMock())]
        mock_store_cls.return_value = mock_store

        mock_runner = MagicMock()
        mock_runner.run_all.return_value = []
        mock_runner_cls.return_value = mock_runner

        mock_catalog = MagicMock()
        mock_catalog.get_connector.return_value = MagicMock()
        mock_catalog_cls.return_value = mock_catalog

        with patch.dict(
            "os.environ",
            {
                "RULES_BUCKET": "my-rules-bucket",
                "SECURITY_LAKE_DB": "test_db",
                "ATHENA_OUTPUT": "s3://test-output/",
            },
        ):
            handler_mod = _reload_handler()
            handler_mod.run_detections({"lookback_minutes": 60})

        mock_runner.run_all.assert_called_once()
        _, kwargs = mock_runner.run_all.call_args
        assert kwargs["lookback_minutes"] == 60

    @patch("secdashboards.detections.runner.DetectionRunner")
    @patch("secdashboards.detections.rule_store.S3RuleStore")
    @patch("secdashboards.catalog.registry.DataCatalog")
    def test_rule_id_filter(self, mock_catalog_cls, mock_store_cls, mock_runner_cls, sample_rule):
        """Filters to specific rule_ids when provided in event."""
        mock_store = MagicMock()
        mock_store.load_all_rules.return_value = [(sample_rule, MagicMock())]
        mock_store_cls.return_value = mock_store

        mock_runner = MagicMock()
        mock_runner.run_all.return_value = []
        mock_runner._rules = {"test-root-login": sample_rule, "other-rule": MagicMock()}
        mock_runner.list_rules.return_value = ["test-root-login", "other-rule"]
        mock_runner_cls.return_value = mock_runner

        mock_catalog = MagicMock()
        mock_catalog.get_connector.return_value = MagicMock()
        mock_catalog_cls.return_value = mock_catalog

        with patch.dict(
            "os.environ",
            {
                "RULES_BUCKET": "my-rules-bucket",
                "SECURITY_LAKE_DB": "test_db",
                "ATHENA_OUTPUT": "s3://test-output/",
            },
        ):
            handler_mod = _reload_handler()
            handler_mod.run_detections({"rule_ids": ["test-root-login"]})

        assert "other-rule" not in mock_runner._rules


class TestHandlerDetectionIntegration:
    """Test that handler() properly delegates to run_detections()."""

    @patch("secdashboards.health.alerting_handler.send_alert")
    @patch("secdashboards.health.alerting_handler.run_detections")
    def test_handler_calls_run_detections(self, mock_run, mock_send):
        """Handler invokes run_detections for check_type='detections'."""
        from secdashboards.health.alerting_handler import handler

        mock_run.return_value = [
            {
                "type": "DETECTION",
                "severity": "high",
                "source": "rule-1",
                "message": "Detection triggered",
            }
        ]

        result = handler({"check_type": "detections"}, None)

        mock_run.assert_called_once_with({"check_type": "detections"})
        mock_send.assert_called_once()
        body = json.loads(result["body"])
        assert body["check_type"] == "detections"
        assert body["alerts_sent"] == 1

    @patch("secdashboards.health.alerting_handler.send_alert")
    @patch("secdashboards.health.alerting_handler.run_detections")
    def test_handler_detections_no_alerts(self, mock_run, mock_send):
        """Handler returns 0 alerts when no detections trigger."""
        from secdashboards.health.alerting_handler import handler

        mock_run.return_value = []

        result = handler({"check_type": "detections"}, None)

        mock_send.assert_not_called()
        body = json.loads(result["body"])
        assert body["alerts_sent"] == 0
