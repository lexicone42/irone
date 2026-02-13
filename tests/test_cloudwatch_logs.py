"""Tests for CloudWatch Logs connector and ETL pipeline."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from secdashboards.catalog.models import DataSource, DataSourceType
from secdashboards.connectors.cloudwatch_logs import (
    CloudWatchLogsConnector,
    LogSourceType,
)
from secdashboards.connectors.log_etl import (
    ALBLogTransformer,
    CloudflareLogTransformer,
    EKSLogTransformer,
    LambdaLogTransformer,
    LogETLPipeline,
    OCSFClass,
    OCSFSeverity,
)
from secdashboards.connectors.result import QueryResult


class TestCloudWatchLogsConnector:
    """Tests for CloudWatchLogsConnector."""

    @pytest.fixture
    def source(self) -> DataSource:
        """Create a test data source."""
        return DataSource(
            name="test-lambda-logs",
            type=DataSourceType.CLOUDWATCH_LOGS,
            region="us-west-2",
            connector_config={
                "source_type": "lambda",
                "log_groups": ["/aws/lambda/test-function"],
            },
        )

    @pytest.fixture
    def connector(self, source: DataSource) -> CloudWatchLogsConnector:
        """Create a test connector with mocked boto3 client."""
        with patch("boto3.client"):
            connector = CloudWatchLogsConnector(source)
            connector._client = MagicMock()
            return connector

    def test_init_sets_properties(self, source: DataSource) -> None:
        """Test connector initialization sets correct properties."""
        with patch("boto3.client"):
            connector = CloudWatchLogsConnector(source)
            assert connector.source_type == LogSourceType.LAMBDA
            assert connector.log_groups == ["/aws/lambda/test-function"]

    def test_discover_log_groups(self, connector: CloudWatchLogsConnector) -> None:
        """Test log group discovery."""
        connector._client.get_paginator.return_value.paginate.return_value = [
            {
                "logGroups": [
                    {
                        "logGroupName": "/aws/lambda/func-1",
                        "arn": "arn:aws:logs:us-west-2:123456789012:log-group:/aws/lambda/func-1",
                        "storedBytes": 1000,
                        "retentionInDays": 30,
                    },
                    {
                        "logGroupName": "/aws/lambda/func-2",
                        "arn": "arn:aws:logs:us-west-2:123456789012:log-group:/aws/lambda/func-2",
                        "storedBytes": 2000,
                    },
                ]
            }
        ]

        groups = connector.discover_log_groups(pattern="/aws/lambda/*")

        assert len(groups) == 2
        assert groups[0]["name"] == "/aws/lambda/func-1"
        assert groups[0]["retention_days"] == 30
        assert groups[1]["stored_bytes"] == 2000

    def test_query_insights_success(self, connector: CloudWatchLogsConnector) -> None:
        """Test successful Logs Insights query."""
        # Mock start_query response
        connector._client.start_query.return_value = {"queryId": "test-query-id"}

        # Mock get_query_results response
        connector._client.get_query_results.return_value = {
            "status": "Complete",
            "results": [
                [
                    {"field": "@timestamp", "value": "2024-01-15T10:00:00Z"},
                    {"field": "@message", "value": "Test log message"},
                    {"field": "@logStream", "value": "2024/01/15/[$LATEST]test-stream"},
                ],
                [
                    {"field": "@timestamp", "value": "2024-01-15T10:01:00Z"},
                    {"field": "@message", "value": "Another message"},
                    {"field": "@logStream", "value": "2024/01/15/[$LATEST]test-stream"},
                ],
            ],
        }

        df = connector.query_insights(
            "fields @timestamp, @message | limit 10",
            start=datetime(2024, 1, 15, 9, 0, tzinfo=UTC),
            end=datetime(2024, 1, 15, 11, 0, tzinfo=UTC),
        )

        assert len(df) == 2
        assert "@timestamp" in df.columns
        assert "@message" in df.columns
        assert df["@message"][0] == "Test log message"

    def test_query_insights_empty_log_groups(self, source: DataSource) -> None:
        """Test query with no log groups configured returns empty DataFrame."""
        source.connector_config["log_groups"] = []
        with patch("boto3.client"):
            connector = CloudWatchLogsConnector(source)
            df = connector.query_insights("fields @timestamp | limit 10")
            assert len(df) == 0

    def test_query_insights_timeout(self, connector: CloudWatchLogsConnector) -> None:
        """Test query timeout handling."""
        connector._client.start_query.return_value = {"queryId": "test-query-id"}
        connector._client.get_query_results.return_value = {"status": "Running"}

        df = connector.query_insights(
            "fields @timestamp | limit 10",
            timeout=1,  # Very short timeout
        )

        # Should return empty DataFrame on timeout
        assert len(df) == 0

    def test_parse_results_filters_ptr_field(self, connector: CloudWatchLogsConnector) -> None:
        """Test that @ptr field is filtered from results."""
        results = [
            [
                {"field": "@timestamp", "value": "2024-01-15T10:00:00Z"},
                {"field": "@ptr", "value": "internal-pointer"},
                {"field": "@message", "value": "Test message"},
            ]
        ]

        df = connector._parse_results(results)

        assert "@ptr" not in df.columns
        assert "@timestamp" in df.columns
        assert "@message" in df.columns

    def test_get_schema_lambda(self, connector: CloudWatchLogsConnector) -> None:
        """Test schema retrieval for Lambda logs."""
        schema = connector.get_schema()

        # Common fields
        assert "@timestamp" in schema
        assert "@message" in schema

        # Lambda-specific fields
        assert "@requestId" in schema
        assert "@duration" in schema
        assert "@billedDuration" in schema

    def test_check_health_success(self, connector: CloudWatchLogsConnector) -> None:
        """Test health check success."""
        connector._client.start_query.return_value = {"queryId": "health-query-id"}
        connector._client.get_query_results.return_value = {
            "status": "Complete",
            "results": [
                [
                    {"field": "event_count", "value": "100"},
                    {"field": "latest_time", "value": datetime.now(UTC).isoformat()},
                ]
            ],
        }

        result = connector.check_health()

        assert result.healthy is True
        assert result.record_count == 100
        assert result.error is None

    def test_check_health_no_data(self, connector: CloudWatchLogsConnector) -> None:
        """Test health check with no data."""
        connector._client.start_query.return_value = {"queryId": "health-query-id"}
        connector._client.get_query_results.return_value = {
            "status": "Complete",
            "results": [],
        }

        result = connector.check_health()

        assert result.healthy is False

    def test_query_lambda_errors(self, connector: CloudWatchLogsConnector) -> None:
        """Test Lambda error query helper."""
        connector._client.start_query.return_value = {"queryId": "error-query-id"}
        connector._client.get_query_results.return_value = {
            "status": "Complete",
            "results": [
                [
                    {"field": "@timestamp", "value": "2024-01-15T10:00:00Z"},
                    {"field": "@message", "value": "ERROR: Something went wrong"},
                    {"field": "@logStream", "value": "test-stream"},
                ]
            ],
        }

        df = connector.query_lambda_errors(function_name="test-function", hours=24)

        assert len(df) == 1
        # Verify query was constructed correctly
        call_args = connector._client.start_query.call_args
        assert "ERROR" in call_args.kwargs.get("queryString", call_args[1].get("queryString", ""))


class TestLogETLPipeline:
    """Tests for the ETL pipeline and OCSF transformers."""

    @pytest.fixture
    def pipeline(self) -> LogETLPipeline:
        """Create a test pipeline."""
        return LogETLPipeline()

    def test_pipeline_has_default_transformers(self, pipeline: LogETLPipeline) -> None:
        """Test pipeline has built-in transformers."""
        transformers = pipeline.list_transformers()
        assert "lambda" in transformers
        assert "alb" in transformers
        assert "cloudflare" in transformers
        assert "eks" in transformers

    def test_register_custom_transformer(self, pipeline: LogETLPipeline) -> None:
        """Test registering a custom transformer."""

        class CustomTransformer(LambdaLogTransformer):
            pass

        pipeline.register_transformer("custom", CustomTransformer())
        assert "custom" in pipeline.list_transformers()


class TestLambdaLogTransformer:
    """Tests for Lambda log transformer."""

    @pytest.fixture
    def transformer(self) -> LambdaLogTransformer:
        """Create a test transformer."""
        return LambdaLogTransformer()

    def test_class_uid(self, transformer: LambdaLogTransformer) -> None:
        """Test OCSF class UID is correct."""
        assert transformer.class_uid == OCSFClass.APPLICATION_LIFECYCLE
        assert transformer.class_name == "Application Lifecycle"

    def test_transform_basic_record(self, transformer: LambdaLogTransformer) -> None:
        """Test transforming a basic Lambda log record."""
        records = [
            {
                "@timestamp": "2024-01-15T10:00:00Z",
                "@message": "INFO: Processing request",
                "@logStream": "2024/01/15/[$LATEST]test-function",
            }
        ]

        ocsf_records = transformer.transform(records)

        assert len(ocsf_records) == 1
        record = ocsf_records[0]
        assert record["class_uid"] == OCSFClass.APPLICATION_LIFECYCLE
        assert record["severity_id"] == OCSFSeverity.INFO
        assert "app" in record
        assert record["app"]["type"] == "AWS Lambda"

    def test_transform_error_severity(self, transformer: LambdaLogTransformer) -> None:
        """Test error messages get high severity."""
        records = [
            {
                "@timestamp": "2024-01-15T10:00:00Z",
                "@message": "ERROR: Connection failed",
                "@logStream": "test-stream",
            }
        ]

        ocsf_records = transformer.transform(records)

        assert ocsf_records[0]["severity_id"] == OCSFSeverity.HIGH

    def test_transform_report_line(self, transformer: LambdaLogTransformer) -> None:
        """Test parsing Lambda REPORT lines."""
        records = [
            {
                "@timestamp": "2024-01-15T10:00:00Z",
                "@message": "REPORT RequestId: abc123 Duration: 150.50 ms Billed Duration: 200 ms Memory Size: 128 MB Max Memory Used: 64 MB",
                "@logStream": "test-stream",
            }
        ]

        ocsf_records = transformer.transform(records)

        unmapped = ocsf_records[0]["unmapped"]
        assert unmapped["duration_ms"] == 150.50
        assert unmapped["billed_duration_ms"] == 200.0
        assert unmapped["memory_size_mb"] == 128.0
        assert unmapped["max_memory_used_mb"] == 64.0

    def test_extract_function_name(self, transformer: LambdaLogTransformer) -> None:
        """Test function name extraction from log stream."""
        name = transformer._extract_function_name("2024/01/15/[$LATEST]my-function")
        assert name == "my-function"


class TestALBLogTransformer:
    """Tests for ALB log transformer."""

    @pytest.fixture
    def transformer(self) -> ALBLogTransformer:
        """Create a test transformer."""
        return ALBLogTransformer()

    def test_class_uid(self, transformer: ALBLogTransformer) -> None:
        """Test OCSF class UID is correct."""
        assert transformer.class_uid == OCSFClass.HTTP_ACTIVITY
        assert transformer.class_name == "HTTP Activity"

    def test_transform_success_request(self, transformer: ALBLogTransformer) -> None:
        """Test transforming a successful ALB request."""
        records = [
            {
                "@timestamp": "2024-01-15T10:00:00Z",
                "elb_status_code": 200,
                "target_status_code": 200,
                "request": "GET /api/users HTTP/1.1",
                "client_ip": "10.0.0.1",
                "client_port": 45678,
                "target_ip": "10.0.1.1",
                "target_port": 8080,
                "user_agent": "Mozilla/5.0",
            }
        ]

        ocsf_records = transformer.transform(records)

        record = ocsf_records[0]
        assert record["class_uid"] == OCSFClass.HTTP_ACTIVITY
        assert record["severity_id"] == OCSFSeverity.INFO
        assert record["status_id"] == 1  # Success
        assert record["http_response"]["code"] == 200
        assert record["src_endpoint"]["ip"] == "10.0.0.1"

    def test_transform_error_request(self, transformer: ALBLogTransformer) -> None:
        """Test transforming an error ALB request."""
        records = [
            {
                "@timestamp": "2024-01-15T10:00:00Z",
                "elb_status_code": 500,
                "request": "POST /api/data HTTP/1.1",
            }
        ]

        ocsf_records = transformer.transform(records)

        record = ocsf_records[0]
        assert record["severity_id"] == OCSFSeverity.HIGH
        assert record["status_id"] == 2  # Failure


class TestCloudflareLogTransformer:
    """Tests for Cloudflare log transformer."""

    @pytest.fixture
    def transformer(self) -> CloudflareLogTransformer:
        """Create a test transformer."""
        return CloudflareLogTransformer()

    def test_transform_waf_block(self, transformer: CloudflareLogTransformer) -> None:
        """Test transforming a WAF block event."""
        records = [
            {
                "@timestamp": "2024-01-15T10:00:00Z",
                "ClientIP": "192.168.1.1",
                "ClientRequestHost": "example.com",
                "ClientRequestURI": "/api/admin",
                "ClientRequestMethod": "POST",
                "EdgeResponseStatus": 403,
                "WAFAction": "block",
                "WAFRuleID": "100001",
                "RayID": "ray123",
            }
        ]

        ocsf_records = transformer.transform(records)

        record = ocsf_records[0]
        assert record["severity_id"] == OCSFSeverity.HIGH
        assert record["src_endpoint"]["ip"] == "192.168.1.1"
        assert len(record["security_controls"]) == 1
        assert record["security_controls"][0]["type"] == "WAF"
        assert record["security_controls"][0]["state"] == "block"


class TestEKSLogTransformer:
    """Tests for EKS log transformer."""

    @pytest.fixture
    def transformer(self) -> EKSLogTransformer:
        """Create a test transformer."""
        return EKSLogTransformer()

    def test_transform_container_log(self, transformer: EKSLogTransformer) -> None:
        """Test transforming an EKS container log."""
        records = [
            {
                "@timestamp": "2024-01-15T10:00:00Z",
                "@message": "Application started successfully",
                "kubernetes.pod_name": "my-app-pod-abc123",
                "kubernetes.namespace_name": "production",
                "kubernetes.container_name": "my-app",
            }
        ]

        ocsf_records = transformer.transform(records)

        record = ocsf_records[0]
        assert record["class_uid"] == OCSFClass.APPLICATION_LIFECYCLE
        assert record["app"]["name"] == "my-app"
        assert record["unmapped"]["pod_name"] == "my-app-pod-abc123"
        assert record["unmapped"]["namespace"] == "production"

    def test_transform_oom_killed(self, transformer: EKSLogTransformer) -> None:
        """Test OOMKilled gets critical severity."""
        records = [
            {
                "@timestamp": "2024-01-15T10:00:00Z",
                "@message": "Container was OOMKilled",
                "kubernetes.pod_name": "memory-hog",
            }
        ]

        ocsf_records = transformer.transform(records)

        assert ocsf_records[0]["severity_id"] == OCSFSeverity.HIGH


class TestDualTargetDetectionRule:
    """Tests for dual-target detection rules."""

    def test_dual_target_rule_creation(self) -> None:
        """Test creating a dual-target rule."""
        from secdashboards.detections.rule import (
            DetectionMetadata,
            DualTargetDetectionRule,
            QueryTarget,
        )

        metadata = DetectionMetadata(
            id="test-rule",
            name="Test Rule",
        )

        rule = DualTargetDetectionRule(
            metadata=metadata,
            queries={
                "cloudwatch": "fields @timestamp | filter @message like /ERROR/",
                "athena": "SELECT * FROM table WHERE severity = 'ERROR'",
            },
        )

        assert rule.has_target(QueryTarget.CLOUDWATCH)
        assert rule.has_target(QueryTarget.ATHENA)
        assert QueryTarget.CLOUDWATCH in rule.supported_targets
        assert QueryTarget.ATHENA in rule.supported_targets

    def test_get_query_for_target(self) -> None:
        """Test getting query for specific target."""
        from secdashboards.detections.rule import (
            DetectionMetadata,
            DualTargetDetectionRule,
            QueryTarget,
        )

        metadata = DetectionMetadata(id="test-rule", name="Test Rule")
        rule = DualTargetDetectionRule(
            metadata=metadata,
            queries={
                "cloudwatch": "fields @timestamp | limit 100",
                "athena": """
                SELECT * FROM table
                WHERE time >= TIMESTAMP '{start_time}'
                """,
            },
        )

        cw_query = rule.get_query_for_target(
            QueryTarget.CLOUDWATCH,
            datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            datetime(2024, 1, 15, 11, 0, tzinfo=UTC),
        )
        assert "fields @timestamp" in cw_query

        athena_query = rule.get_query_for_target(
            QueryTarget.ATHENA,
            datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            datetime(2024, 1, 15, 11, 0, tzinfo=UTC),
        )
        assert "2024-01-15 10:00:00" in athena_query

    def test_unsupported_target_raises(self) -> None:
        """Test that requesting unsupported target raises ValueError."""
        from secdashboards.detections.rule import (
            DetectionMetadata,
            DualTargetDetectionRule,
            QueryTarget,
        )

        metadata = DetectionMetadata(id="test-rule", name="Test Rule")
        rule = DualTargetDetectionRule(
            metadata=metadata,
            queries={"cloudwatch": "fields @timestamp"},  # Only CloudWatch
        )

        with pytest.raises(ValueError, match="does not support target"):
            rule.get_query_for_target(
                QueryTarget.ATHENA,
                datetime.now(UTC),
                datetime.now(UTC),
            )

    def test_evaluate_threshold(self) -> None:
        """Test detection threshold evaluation."""
        from secdashboards.detections.rule import (
            DetectionMetadata,
            DualTargetDetectionRule,
        )

        metadata = DetectionMetadata(id="test-rule", name="Test Rule")
        rule = DualTargetDetectionRule(
            metadata=metadata,
            queries={"cloudwatch": "fields @timestamp"},
            threshold=5,
        )

        # Below threshold
        df_low = QueryResult.from_dicts([{"count": 1}, {"count": 2}, {"count": 3}])
        result_low = rule.evaluate(df_low)
        assert result_low.triggered is False
        assert result_low.match_count == 3

        # At/above threshold
        df_high = QueryResult.from_dicts([{"count": i} for i in range(10)])
        result_high = rule.evaluate(df_high)
        assert result_high.triggered is True
        assert result_high.match_count == 10
