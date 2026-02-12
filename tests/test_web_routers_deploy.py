"""Tests for deploy routes — Lambda build and operations."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from secdashboards.detections.rule import DetectionMetadata, Severity, SQLDetectionRule
from secdashboards.web.app import create_app
from secdashboards.web.config import WebConfig


@pytest.fixture
def app():
    config = WebConfig(duckdb_path=":memory:")
    return create_app(config)


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def app_with_rule(app):
    state = app.state.secdash
    metadata = DetectionMetadata(
        id="deploy-rule-1",
        name="Deploy Test Rule",
        severity=Severity.HIGH,
    )
    rule = SQLDetectionRule(
        metadata=metadata,
        query_template="SELECT 1",
        threshold=1,
    )
    state.runner.register_rule(rule)
    return app


@pytest.fixture
def client_with_rule(app_with_rule):
    return TestClient(app_with_rule)


class TestDeployRoutes:
    def test_index_returns_200(self, client) -> None:
        resp = client.get("/deploy/")
        assert resp.status_code == 200
        assert "Deployment" in resp.text

    def test_index_shows_rules(self, client_with_rule) -> None:
        resp = client_with_rule.get("/deploy/")
        assert resp.status_code == 200
        assert "Deploy Test Rule" in resp.text

    def test_index_shows_region(self, client) -> None:
        resp = client.get("/deploy/")
        assert resp.status_code == 200
        assert "us-west-2" in resp.text  # default region


class TestBuildLambda:
    @patch("secdashboards.deploy.lambda_builder.LambdaBuilder")
    def test_build_success(self, mock_builder_cls, client_with_rule) -> None:
        mock_builder = MagicMock()
        mock_builder.build_package.return_value = "/tmp/secdash-builds/deploy-rule-1.zip"
        mock_builder_cls.return_value = mock_builder

        resp = client_with_rule.post(
            "/deploy/build",
            data={
                "rule_id": "deploy-rule-1",
                "data_source": "security-lake",
                "lookback_minutes": "15",
            },
        )
        assert resp.status_code == 200
        assert "Deploy Test Rule" in resp.text or "deploy-rule-1.zip" in resp.text

    def test_build_rule_not_found(self, client) -> None:
        resp = client.post(
            "/deploy/build",
            data={
                "rule_id": "nonexistent",
                "data_source": "security-lake",
                "lookback_minutes": "15",
            },
        )
        assert resp.status_code == 200
        assert "not found" in resp.text

    @patch(
        "secdashboards.deploy.lambda_builder.LambdaBuilder",
        side_effect=Exception("Build failed: missing deps"),
    )
    def test_build_error(self, mock_cls, client_with_rule) -> None:
        resp = client_with_rule.post(
            "/deploy/build",
            data={
                "rule_id": "deploy-rule-1",
                "data_source": "security-lake",
                "lookback_minutes": "15",
            },
        )
        assert resp.status_code == 200
        assert "Build failed" in resp.text


class TestOperationStatus:
    def test_operation_not_found(self, client) -> None:
        resp = client.get("/deploy/operations/nonexistent")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "unknown"

    def test_operation_exists(self, app) -> None:
        app.state.secdash.operations["build-test"] = {
            "type": "build",
            "status": "complete",
            "package_path": "/tmp/test.zip",
        }
        client = TestClient(app)
        resp = client.get("/deploy/operations/build-test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "complete"
