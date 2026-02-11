"""Tests for the detection rules module."""

from datetime import datetime
from unittest.mock import MagicMock

import polars as pl
import pytest

from secdashboards.catalog.registry import DataCatalog
from secdashboards.detections.rule import (
    DetectionMetadata,
    DetectionResult,
    Severity,
    SQLDetectionRule,
)
from secdashboards.detections.runner import DetectionRunner


class TestDetectionMetadata:
    """Tests for DetectionMetadata model."""

    def test_create_metadata(self) -> None:
        metadata = DetectionMetadata(
            id="test-rule",
            name="Test Rule",
            description="A test detection rule",
            severity=Severity.HIGH,
            tags=["test", "example"],
            mitre_attack=["T1078"],
        )

        assert metadata.id == "test-rule"
        assert metadata.name == "Test Rule"
        assert metadata.severity == Severity.HIGH
        assert "test" in metadata.tags

    def test_default_values(self) -> None:
        metadata = DetectionMetadata(id="minimal", name="Minimal Rule")

        assert metadata.severity == Severity.MEDIUM
        assert metadata.enabled is True
        assert metadata.schedule == "rate(5 minutes)"


class TestDetectionResult:
    """Tests for DetectionResult model."""

    def test_triggered_result(self) -> None:
        result = DetectionResult(
            rule_id="test",
            rule_name="Test Rule",
            triggered=True,
            severity=Severity.HIGH,
            match_count=5,
            matches=[{"field": "value"}],
            message="Detection triggered",
        )

        assert result.triggered is True
        assert result.match_count == 5
        assert len(result.matches) == 1

    def test_to_alert_dict(self) -> None:
        result = DetectionResult(
            rule_id="test",
            rule_name="Test Rule",
            triggered=True,
            severity=Severity.HIGH,
            match_count=10,
            matches=[{"id": i} for i in range(10)],
            message="Alert message",
        )

        alert = result.to_alert_dict()
        assert alert["rule_id"] == "test"
        assert alert["severity"] == Severity.HIGH
        assert len(alert["sample_matches"]) == 5  # Limited to 5


class TestSQLDetectionRule:
    """Tests for SQLDetectionRule."""

    def test_get_query(self) -> None:
        metadata = DetectionMetadata(id="test", name="Test")
        rule = SQLDetectionRule(
            metadata=metadata,
            query_template="SELECT * FROM table WHERE time >= '{start_time}' AND time < '{end_time}'",
            threshold=1,
        )

        start = datetime(2024, 1, 1, 0, 0, 0)
        end = datetime(2024, 1, 1, 1, 0, 0)

        query = rule.get_query(start, end)
        # Timestamps should be Athena-compatible format (space-separated, no T)
        assert "2024-01-01 00:00:00" in query
        assert "2024-01-01 01:00:00" in query

    def test_evaluate_triggered(self) -> None:
        metadata = DetectionMetadata(id="test", name="Test", severity=Severity.HIGH)
        rule = SQLDetectionRule(
            metadata=metadata,
            query_template="SELECT * FROM table",
            threshold=2,
        )

        # DataFrame with 3 rows should trigger (threshold=2)
        df = pl.DataFrame({"col1": [1, 2, 3], "col2": ["a", "b", "c"]})
        result = rule.evaluate(df)

        assert result.triggered is True
        assert result.match_count == 3
        assert result.severity == Severity.HIGH
        assert len(result.matches) == 3

    def test_evaluate_not_triggered(self) -> None:
        metadata = DetectionMetadata(id="test", name="Test")
        rule = SQLDetectionRule(
            metadata=metadata,
            query_template="SELECT * FROM table",
            threshold=5,
        )

        # DataFrame with 2 rows should not trigger (threshold=5)
        df = pl.DataFrame({"col1": [1, 2]})
        result = rule.evaluate(df)

        assert result.triggered is False
        assert result.match_count == 2
        assert len(result.matches) == 0  # No matches when not triggered

    def test_evaluate_empty_dataframe(self) -> None:
        metadata = DetectionMetadata(id="test", name="Test")
        rule = SQLDetectionRule(
            metadata=metadata,
            query_template="SELECT * FROM table",
            threshold=1,
        )

        df = pl.DataFrame({"col1": []})
        result = rule.evaluate(df)

        assert result.triggered is False
        assert result.match_count == 0

    def test_to_dict(self) -> None:
        metadata = DetectionMetadata(
            id="test-rule",
            name="Test Rule",
            description="Description",
            severity=Severity.MEDIUM,
        )
        rule = SQLDetectionRule(
            metadata=metadata,
            query_template="SELECT * FROM table",
            threshold=1,
        )

        data = rule.to_dict()
        assert data["id"] == "test-rule"
        assert data["name"] == "Test Rule"
        assert data["severity"] == "medium"


def _make_rule(rule_id: str = "test-rule", name: str = "Test Rule", **kwargs) -> SQLDetectionRule:
    """Helper to create a test detection rule."""
    return SQLDetectionRule(
        metadata=DetectionMetadata(
            id=rule_id,
            name=name,
            severity=kwargs.pop("severity", Severity.HIGH),
            **kwargs,
        ),
        query_template="SELECT * FROM t WHERE time >= '{start_time}' AND time < '{end_time}'",
        threshold=1,
    )


class TestDetectionRunnerLifecycle:
    """Tests for creating, registering, listing, and deleting detection rules via DetectionRunner."""

    @pytest.fixture()
    def catalog(self) -> DataCatalog:
        return DataCatalog()

    @pytest.fixture()
    def runner(self, catalog: DataCatalog) -> DetectionRunner:
        return DetectionRunner(catalog=catalog)

    def test_register_rule(self, runner: DetectionRunner) -> None:
        rule = _make_rule("detect-root-login", "Root Login")
        runner.register_rule(rule)

        assert runner.get_rule("detect-root-login") is rule
        assert len(runner.list_rules()) == 1

    def test_register_multiple_rules(self, runner: DetectionRunner) -> None:
        rules = [
            _make_rule("rule-1", "Rule One"),
            _make_rule("rule-2", "Rule Two"),
            _make_rule("rule-3", "Rule Three"),
        ]
        for r in rules:
            runner.register_rule(r)

        assert len(runner.list_rules()) == 3
        assert {r.id for r in runner.list_rules()} == {"rule-1", "rule-2", "rule-3"}

    def test_register_overwrites_existing(self, runner: DetectionRunner) -> None:
        rule_v1 = _make_rule("same-id", "Version 1")
        rule_v2 = _make_rule("same-id", "Version 2")

        runner.register_rule(rule_v1)
        runner.register_rule(rule_v2)

        assert len(runner.list_rules()) == 1
        assert runner.get_rule("same-id").name == "Version 2"

    def test_get_rule_not_found(self, runner: DetectionRunner) -> None:
        assert runner.get_rule("nonexistent") is None

    def test_delete_rule(self, runner: DetectionRunner) -> None:
        rule = _make_rule("to-delete", "Deletable Rule")
        runner.register_rule(rule)
        assert runner.get_rule("to-delete") is not None

        del runner._rules["to-delete"]

        assert runner.get_rule("to-delete") is None
        assert len(runner.list_rules()) == 0

    def test_delete_rule_among_others(self, runner: DetectionRunner) -> None:
        runner.register_rule(_make_rule("keep-1", "Keep One"))
        runner.register_rule(_make_rule("remove", "Remove Me"))
        runner.register_rule(_make_rule("keep-2", "Keep Two"))

        del runner._rules["remove"]

        assert len(runner.list_rules()) == 2
        assert runner.get_rule("remove") is None
        assert runner.get_rule("keep-1") is not None
        assert runner.get_rule("keep-2") is not None

    def test_list_rules_enabled_only(self, runner: DetectionRunner) -> None:
        enabled = _make_rule("enabled", "Enabled Rule")
        disabled = _make_rule("disabled", "Disabled Rule", enabled=False)
        runner.register_rule(enabled)
        runner.register_rule(disabled)

        assert len(runner.list_rules(enabled_only=True)) == 1
        assert len(runner.list_rules(enabled_only=False)) == 2

    def test_run_rule_not_found(self, runner: DetectionRunner) -> None:
        connector = MagicMock()
        result = runner.run_rule("nonexistent", connector)

        assert result.triggered is False
        assert result.error is not None
        assert "not found" in result.error.lower()

    def test_run_registered_rule(self, runner: DetectionRunner) -> None:
        rule = _make_rule("test-run", "Runnable Rule")
        runner.register_rule(rule)

        mock_connector = MagicMock()
        mock_connector.query.return_value = pl.DataFrame({"user": ["root"], "ip": ["1.2.3.4"]})

        result = runner.run_rule("test-run", mock_connector)

        assert result.triggered is True
        assert result.match_count == 1
        assert result.rule_id == "test-run"
        mock_connector.query.assert_called_once()

    def test_run_rule_not_triggered(self, runner: DetectionRunner) -> None:
        rule = SQLDetectionRule(
            metadata=DetectionMetadata(id="high-thresh", name="High Threshold"),
            query_template="SELECT * FROM t WHERE time >= '{start_time}' AND time < '{end_time}'",
            threshold=100,
        )
        runner.register_rule(rule)

        mock_connector = MagicMock()
        mock_connector.query.return_value = pl.DataFrame({"col": [1, 2, 3]})

        result = runner.run_rule("high-thresh", mock_connector)

        assert result.triggered is False
        assert result.match_count == 3

    def test_run_all_rules(self, runner: DetectionRunner) -> None:
        runner.register_rule(_make_rule("rule-a", "Rule A"))
        runner.register_rule(_make_rule("rule-b", "Rule B"))

        mock_connector = MagicMock()
        mock_connector.query.return_value = pl.DataFrame({"event": ["login"]})

        results = runner.run_all(mock_connector, lookback_minutes=60)

        assert len(results) == 2
        assert all(r.triggered for r in results)

    def test_run_rule_with_connector_error(self, runner: DetectionRunner) -> None:
        rule = _make_rule("error-rule", "Error Rule")
        runner.register_rule(rule)

        mock_connector = MagicMock()
        mock_connector.query.side_effect = Exception("Athena timeout")

        result = runner.run_rule("error-rule", mock_connector)

        assert result.triggered is False
        assert result.error is not None
        assert "Athena timeout" in result.error

    def test_export_rules_to_dict(self, runner: DetectionRunner) -> None:
        runner.register_rule(_make_rule("rule-x", "Rule X", severity=Severity.CRITICAL))
        runner.register_rule(_make_rule("rule-y", "Rule Y", severity=Severity.LOW))

        exported = runner.export_rules_to_dict()

        assert len(exported) == 2
        ids = {r["id"] for r in exported}
        assert ids == {"rule-x", "rule-y"}

    def test_create_delete_roundtrip(self, runner: DetectionRunner) -> None:
        """Full lifecycle: create, verify, run, delete, verify gone."""
        rule = _make_rule("lifecycle-test", "Lifecycle Rule")

        # Create
        runner.register_rule(rule)
        assert runner.get_rule("lifecycle-test") is not None

        # Run
        mock_connector = MagicMock()
        mock_connector.query.return_value = pl.DataFrame({"col": []})
        result = runner.run_rule("lifecycle-test", mock_connector)
        assert result.rule_id == "lifecycle-test"

        # Delete
        del runner._rules["lifecycle-test"]
        assert runner.get_rule("lifecycle-test") is None
        assert len(runner.list_rules()) == 0

        # Run after delete should return error
        result = runner.run_rule("lifecycle-test", mock_connector)
        assert result.triggered is False
        assert "not found" in result.error.lower()
