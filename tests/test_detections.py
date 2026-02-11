"""Tests for the detection rules module."""

from datetime import datetime

import polars as pl

from secdashboards.detections.rule import (
    DetectionMetadata,
    DetectionResult,
    Severity,
    SQLDetectionRule,
)


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
