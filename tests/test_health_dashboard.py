"""Tests for the health dashboard Lambda handler.

Uses moto to mock AWS services (Athena, CloudWatch, S3, Cost Explorer).
This allows testing the handler logic without making real AWS calls.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

# Set environment variables before importing handler
os.environ["AWS_REGION"] = "us-west-2"
os.environ["SECURITY_LAKE_DB"] = "test_security_lake_db"
os.environ["ATHENA_OUTPUT"] = "s3://test-athena-output/"
os.environ["CACHE_BUCKET"] = "test-cache-bucket"
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-west-2"


class TestHealthDashboardHandler:
    """Tests for the main Lambda handler."""

    @pytest.fixture
    def mock_event_get_health(self) -> dict[str, Any]:
        """HTTP API event for GET /health."""
        return {
            "routeKey": "GET /health",
            "rawPath": "/health",
            "requestContext": {
                "http": {"method": "GET"},
                "stage": "prod",
            },
            "headers": {
                "origin": "https://health.lexicone.com",
            },
            "queryStringParameters": None,
        }

    @pytest.fixture
    def mock_event_get_history(self) -> dict[str, Any]:
        """HTTP API event for GET /health/history."""
        return {
            "routeKey": "GET /health/history",
            "rawPath": "/health/history",
            "requestContext": {
                "http": {"method": "GET"},
                "stage": "prod",
            },
            "headers": {
                "origin": "https://health.lexicone.com",
            },
            "queryStringParameters": {"hours": "24"},
        }

    @pytest.fixture
    def mock_scheduled_event(self) -> dict[str, Any]:
        """EventBridge scheduled event for cache collection."""
        return {
            "source": "aws.events",
            "detail-type": "Scheduled Event",
            "detail": {},
        }

    def test_options_returns_cors_headers(self) -> None:
        """OPTIONS requests should return proper CORS headers."""
        from secdashboards.health.dashboard_handler import handler

        event = {
            "routeKey": "OPTIONS /health",
            "requestContext": {"http": {"method": "OPTIONS"}},
            "headers": {"origin": "https://health.lexicone.com"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 200
        assert "Access-Control-Allow-Origin" in response["headers"]
        assert response["headers"]["Access-Control-Allow-Credentials"] == "true"

    def test_cors_origin_validation(self) -> None:
        """CORS should only allow specific origins."""
        from secdashboards.health.dashboard_handler import handler

        # Allowed origin
        event = {
            "routeKey": "OPTIONS /health",
            "requestContext": {"http": {"method": "OPTIONS"}},
            "headers": {"origin": "https://health.lexicone.com"},
        }
        response = handler(event, None)
        assert response["headers"]["Access-Control-Allow-Origin"] == "https://health.lexicone.com"

        # Disallowed origin gets wildcard
        event["headers"]["origin"] = "https://evil.com"
        response = handler(event, None)
        assert response["headers"]["Access-Control-Allow-Origin"] == "*"

    def test_unknown_path_returns_404(self) -> None:
        """Unknown paths should return 404."""
        from secdashboards.health.dashboard_handler import handler

        event = {
            "routeKey": "GET /unknown",
            "rawPath": "/unknown",
            "requestContext": {"http": {"method": "GET"}},
            "headers": {},
        }

        response = handler(event, None)

        assert response["statusCode"] == 404
        body = json.loads(response["body"])
        assert body["error"] == "Not found"

    @mock_aws
    def test_cache_bucket_operations(self) -> None:
        """Test S3 cache operations."""
        from secdashboards.health.dashboard_handler import (
            get_latest_snapshot,
            save_snapshot,
        )

        # Create mock S3 bucket
        s3 = boto3.client("s3", region_name="us-west-2")
        s3.create_bucket(
            Bucket="test-cache-bucket",
            CreateBucketConfiguration={"LocationConstraint": "us-west-2"},
        )

        # Test save_snapshot
        test_data = {"security_lake": {"sources": []}, "generated_at": "2025-01-17T10:00:00Z"}
        result = save_snapshot(test_data)
        assert result is True

        # Test get_latest_snapshot
        cached = get_latest_snapshot()
        assert cached is not None
        assert cached["generated_at"] == "2025-01-17T10:00:00Z"

    def test_get_cache_key_format(self) -> None:
        """Cache keys should follow the expected format."""
        from secdashboards.health.dashboard_handler import get_cache_key

        # Test with specific timestamp
        ts = datetime(2025, 1, 17, 14, 30, 0, tzinfo=UTC)
        key = get_cache_key(ts)
        assert key == "snapshots/2025/01/17/14.json"

        # Test with current time (should not fail)
        key_now = get_cache_key()
        assert key_now.startswith("snapshots/")
        assert key_now.endswith(".json")

    @mock_aws
    def test_scheduled_event_triggers_cache_collection(
        self, mock_scheduled_event: dict[str, Any]
    ) -> None:
        """Scheduled events should trigger cache collection."""
        # Create mock S3 bucket
        s3 = boto3.client("s3", region_name="us-west-2")
        s3.create_bucket(
            Bucket="test-cache-bucket",
            CreateBucketConfiguration={"LocationConstraint": "us-west-2"},
        )

        # Mock the expensive query functions
        with (
            patch("secdashboards.health.dashboard_handler.get_security_lake_health") as mock_sl,
            patch("secdashboards.health.dashboard_handler.get_cost_metrics") as mock_costs,
            patch("secdashboards.health.dashboard_handler.get_detection_status") as mock_detect,
        ):
            mock_sl.return_value = {"sources": [], "checked_at": "2025-01-17T10:00:00Z"}
            mock_costs.return_value = {"total": 5.00, "services": []}
            mock_detect.return_value = {"total_invocations": 100, "total_errors": 0}

            from secdashboards.health.dashboard_handler import handler

            response = handler(mock_scheduled_event, None)

            assert response["statusCode"] == 200
            body = json.loads(response["body"])
            assert "message" in body
            assert body["message"] == "Cache updated"

            # Verify the mocks were called
            mock_sl.assert_called_once()
            mock_costs.assert_called_once()
            mock_detect.assert_called_once()


class TestCacheBypassLogic:
    """Tests for cache bypass functionality."""

    @mock_aws
    def test_cache_false_bypasses_cache(self) -> None:
        """?cache=false should bypass the cache and query directly."""
        # Create mock S3 bucket with stale data
        s3 = boto3.client("s3", region_name="us-west-2")
        s3.create_bucket(
            Bucket="test-cache-bucket",
            CreateBucketConfiguration={"LocationConstraint": "us-west-2"},
        )

        # Put stale cached data
        stale_data = {"generated_at": "2024-01-01T00:00:00Z", "cached": True}
        s3.put_object(
            Bucket="test-cache-bucket",
            Key="latest.json",
            Body=json.dumps(stale_data),
        )

        # Mock the expensive query functions
        with (
            patch("secdashboards.health.dashboard_handler.get_security_lake_health") as mock_sl,
            patch("secdashboards.health.dashboard_handler.get_cost_metrics") as mock_costs,
            patch("secdashboards.health.dashboard_handler.get_detection_status") as mock_detect,
        ):
            mock_sl.return_value = {"sources": [], "checked_at": "2025-01-17T10:00:00Z"}
            mock_costs.return_value = {"total": 5.00, "services": []}
            mock_detect.return_value = {"total_invocations": 100, "total_errors": 0}

            from secdashboards.health.dashboard_handler import handler

            event = {
                "routeKey": "GET /health",
                "rawPath": "/health",
                "requestContext": {"http": {"method": "GET"}},
                "headers": {},
                "queryStringParameters": {"cache": "false"},
            }

            response = handler(event, None)

            assert response["statusCode"] == 200
            body = json.loads(response["body"])

            # Should have fresh data, not cached
            assert body.get("cached") is False

            # Verify the mocks were called (meaning we bypassed cache)
            mock_sl.assert_called_once()


class TestSecurityHeaders:
    """Tests for security headers in responses."""

    def test_security_headers_present(self) -> None:
        """All responses should include security headers."""
        from secdashboards.health.dashboard_handler import handler

        event = {
            "routeKey": "OPTIONS /health",
            "requestContext": {"http": {"method": "OPTIONS"}},
            "headers": {},
        }

        response = handler(event, None)
        headers = response["headers"]

        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert "Strict-Transport-Security" in headers


class TestPathParsing:
    """Tests for path parsing logic."""

    def test_route_key_parsing(self) -> None:
        """Path should be extracted from routeKey correctly."""
        from secdashboards.health.dashboard_handler import handler

        event = {
            "routeKey": "GET /health/sources",
            "rawPath": "/prod/health/sources",
            "requestContext": {"http": {"method": "GET"}, "stage": "prod"},
            "headers": {},
        }

        # Mock the query function
        with patch("secdashboards.health.dashboard_handler.get_security_lake_health") as mock:
            mock.return_value = {"sources": [], "checked_at": "now"}

            response = handler(event, None)

            assert response["statusCode"] == 200
            mock.assert_called_once()

    def test_stage_prefix_stripped(self) -> None:
        """Stage prefix should be stripped from rawPath."""
        from secdashboards.health.dashboard_handler import handler

        # Simulate fallback when routeKey doesn't have path
        event = {
            "routeKey": "",
            "rawPath": "/prod/health",
            "requestContext": {"http": {"method": "GET"}, "stage": "prod"},
            "headers": {},
            "queryStringParameters": {"cache": "false"},  # Bypass cache to hit endpoint
        }

        with (
            patch("secdashboards.health.dashboard_handler.get_security_lake_health") as mock_sl,
            patch("secdashboards.health.dashboard_handler.get_cost_metrics") as mock_costs,
            patch("secdashboards.health.dashboard_handler.get_detection_status") as mock_detect,
        ):
            mock_sl.return_value = {"sources": []}
            mock_costs.return_value = {"total": 0, "services": []}
            mock_detect.return_value = {"total_invocations": 0}

            response = handler(event, None)

            # Should return 200, not 404 (meaning path was parsed correctly)
            assert response["statusCode"] == 200
