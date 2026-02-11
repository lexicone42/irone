"""Tests for Lambda deployment workflow (LambdaBuilder, DualTargetLambdaBuilder, DetectionScheduler).

Covers:
- Handler code generation from detection rules
- Deployment package (zip) creation
- Lambda function deployment via boto3 (mocked)
- SAM template generation (single and dual-target)
- EventBridge schedule management (mocked)
- End-to-end build → deploy → schedule workflow
"""

import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from secdashboards.deploy.lambda_builder import (
    DualTargetLambdaBuilder,
    LambdaBuilder,
)
from secdashboards.deploy.scheduler import DetectionScheduler
from secdashboards.detections.rule import (
    DetectionMetadata,
    DualTargetDetectionRule,
    Severity,
    SQLDetectionRule,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sql_rule() -> SQLDetectionRule:
    """A sample SQL detection rule for testing."""
    metadata = DetectionMetadata(
        id="root-login",
        name="Root User Login",
        description="Detect root user console logins",
        severity=Severity.HIGH,
        schedule="rate(15 minutes)",
        enabled=True,
        tags=["iam", "root"],
        mitre_attack=["T1078"],
    )
    return SQLDetectionRule(
        metadata=metadata,
        query_template=(
            "SELECT * FROM security_lake "
            "WHERE actor_user = 'root' "
            "AND time_dt >= TIMESTAMP '{start_time}' "
            "AND time_dt < TIMESTAMP '{end_time}'"
        ),
        threshold=1,
    )


@pytest.fixture()
def dual_rule() -> DualTargetDetectionRule:
    """A sample dual-target detection rule for testing."""
    metadata = DetectionMetadata(
        id="lambda-errors",
        name="Lambda Function Errors",
        description="Detect Lambda function errors across log sources",
        severity=Severity.MEDIUM,
        schedule="rate(5 minutes)",
        enabled=True,
    )
    return DualTargetDetectionRule(
        metadata=metadata,
        queries={
            "cloudwatch": (
                "fields @timestamp, @message | filter @message like /ERROR/ | stats count(*)"
            ),
            "athena": (
                "SELECT time_dt, message FROM security_lake "
                "WHERE severity_id >= 4 "
                "AND time_dt >= TIMESTAMP '{start_time}' "
                "AND time_dt < TIMESTAMP '{end_time}'"
            ),
        },
        threshold=5,
    )


@pytest.fixture()
def builder(tmp_path: Path) -> LambdaBuilder:
    """LambdaBuilder with temp output directory."""
    return LambdaBuilder(tmp_path)


@pytest.fixture()
def dual_builder(tmp_path: Path) -> DualTargetLambdaBuilder:
    """DualTargetLambdaBuilder with temp output directory."""
    return DualTargetLambdaBuilder(tmp_path)


# ---------------------------------------------------------------------------
# LambdaBuilder — handler generation
# ---------------------------------------------------------------------------


class TestLambdaBuilderHandler:
    """Tests for handler code generation."""

    def test_build_handler_creates_file(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """build_handler() creates a .py file on disk."""
        handler_path = builder.build_handler(sql_rule, data_source="security_lake")
        assert handler_path.exists()
        assert handler_path.suffix == ".py"
        assert handler_path.name == "handler_root-login.py"

    def test_build_handler_embeds_rule_config(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """Generated handler contains the detection rule configuration."""
        handler_path = builder.build_handler(sql_rule, data_source="security_lake")
        code = handler_path.read_text()

        assert 'RULE_ID = "root-login"' in code
        assert 'RULE_NAME = "Root User Login"' in code
        assert 'SEVERITY = "high"' in code
        assert "THRESHOLD = 1" in code
        assert "LOOKBACK_MINUTES = 15" in code
        assert "actor_user = 'root'" in code

    def test_build_handler_custom_lookback(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """lookback_minutes parameter is embedded in the handler."""
        handler_path = builder.build_handler(
            sql_rule, data_source="security_lake", lookback_minutes=60
        )
        code = handler_path.read_text()
        assert "LOOKBACK_MINUTES = 60" in code

    def test_build_handler_is_valid_python(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """Generated handler is syntactically valid Python."""
        handler_path = builder.build_handler(sql_rule, data_source="security_lake")
        code = handler_path.read_text()
        compile(code, handler_path.name, "exec")  # Raises SyntaxError if invalid


# ---------------------------------------------------------------------------
# LambdaBuilder — package creation
# ---------------------------------------------------------------------------


class TestLambdaBuilderPackage:
    """Tests for deployment package (zip) creation."""

    def test_build_package_creates_zip(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """build_package() creates a valid zip file."""
        zip_path = builder.build_package(sql_rule, data_source="security_lake")
        assert zip_path.exists()
        assert zip_path.suffix == ".zip"
        assert zip_path.name == "detection_root-login.zip"

    def test_build_package_contains_handler(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """The zip contains handler.py at the root."""
        zip_path = builder.build_package(sql_rule, data_source="security_lake")
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            assert "handler.py" in names

    def test_build_package_handler_has_correct_content(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """handler.py in the zip contains the detection config."""
        zip_path = builder.build_package(sql_rule, data_source="security_lake")
        with zipfile.ZipFile(zip_path) as zf:
            handler_code = zf.read("handler.py").decode()
            assert 'RULE_ID = "root-login"' in handler_code
            assert "def handler(event, context):" in handler_code


# ---------------------------------------------------------------------------
# LambdaBuilder — deploy Lambda (mocked AWS)
# ---------------------------------------------------------------------------


class TestLambdaBuilderDeploy:
    """Tests for deploying Lambda functions (mocked boto3)."""

    def test_deploy_creates_new_function(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """deploy_lambda() creates a new function when none exists."""
        zip_path = builder.build_package(sql_rule, data_source="security_lake")

        mock_client = MagicMock()
        # Simulate ResourceNotFoundException on update attempt
        mock_client.update_function_code.side_effect = (
            mock_client.exceptions.ResourceNotFoundException
        ) = type("ResourceNotFoundException", (Exception,), {})
        mock_client.update_function_code.side_effect = (
            mock_client.exceptions.ResourceNotFoundException()
        )
        mock_client.create_function.return_value = {
            "FunctionArn": "arn:aws:lambda:us-west-2:123456789012:function:secdash-detection-root-login",
        }

        builder._lambda_client = mock_client

        result = builder.deploy_lambda(
            rule=sql_rule,
            package_path=zip_path,
            role_arn="arn:aws:iam::123456789012:role/test-role",
        )

        assert result["function_name"] == "secdash-detection-root-login"
        assert result["rule_id"] == "root-login"
        assert "lambda" in result["function_arn"]
        mock_client.create_function.assert_called_once()

    def test_deploy_updates_existing_function(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """deploy_lambda() updates an existing function."""
        zip_path = builder.build_package(sql_rule, data_source="security_lake")

        mock_client = MagicMock()
        mock_client.update_function_code.return_value = {
            "FunctionArn": "arn:aws:lambda:us-west-2:123456789012:function:secdash-detection-root-login",
        }

        builder._lambda_client = mock_client

        result = builder.deploy_lambda(
            rule=sql_rule,
            package_path=zip_path,
            role_arn="arn:aws:iam::123456789012:role/test-role",
        )

        assert result["function_name"] == "secdash-detection-root-login"
        mock_client.update_function_code.assert_called_once()
        mock_client.update_function_configuration.assert_called_once()
        mock_client.create_function.assert_not_called()

    def test_deploy_sets_environment_variables(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """deploy_lambda() passes environment variables to the function."""
        zip_path = builder.build_package(sql_rule, data_source="security_lake")

        mock_client = MagicMock()
        not_found = type("ResourceNotFoundException", (Exception,), {})
        mock_client.exceptions.ResourceNotFoundException = not_found
        mock_client.update_function_code.side_effect = not_found()
        mock_client.create_function.return_value = {
            "FunctionArn": "arn:aws:lambda:us-west-2:123456789012:function:test",
        }

        builder._lambda_client = mock_client

        builder.deploy_lambda(
            rule=sql_rule,
            package_path=zip_path,
            role_arn="arn:aws:iam::123456789012:role/test-role",
            environment={"ATHENA_DATABASE": "my_db", "SNS_TOPIC_ARN": "arn:aws:sns:topic"},
        )

        call_kwargs = mock_client.create_function.call_args[1]
        env_vars = call_kwargs["Environment"]["Variables"]
        assert env_vars["RULE_ID"] == "root-login"
        assert env_vars["RULE_NAME"] == "Root User Login"
        assert env_vars["ATHENA_DATABASE"] == "my_db"
        assert env_vars["SNS_TOPIC_ARN"] == "arn:aws:sns:topic"

    def test_deploy_rejects_invalid_memory(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """deploy_lambda() rejects memory outside 128-10240 range."""
        zip_path = builder.build_package(sql_rule, data_source="security_lake")
        with pytest.raises(ValueError, match="memory_mb"):
            builder.deploy_lambda(
                rule=sql_rule,
                package_path=zip_path,
                role_arn="arn:aws:iam::123456789012:role/test-role",
                memory_mb=64,
            )

    def test_deploy_rejects_invalid_timeout(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """deploy_lambda() rejects timeout outside 1-900 range."""
        zip_path = builder.build_package(sql_rule, data_source="security_lake")
        with pytest.raises(ValueError, match="timeout_seconds"):
            builder.deploy_lambda(
                rule=sql_rule,
                package_path=zip_path,
                role_arn="arn:aws:iam::123456789012:role/test-role",
                timeout_seconds=1000,
            )


# ---------------------------------------------------------------------------
# LambdaBuilder — SAM template generation
# ---------------------------------------------------------------------------


class TestSAMTemplateGeneration:
    """Tests for SAM/CloudFormation template generation."""

    def test_generate_sam_template_structure(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """SAM template has required top-level keys."""
        template = builder.generate_sam_template([sql_rule], data_source="security_lake")

        assert template["AWSTemplateFormatVersion"] == "2010-09-09"
        assert template["Transform"] == "AWS::Serverless-2016-10-31"
        assert "Parameters" in template
        assert "Resources" in template

    def test_generate_sam_template_has_function(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """SAM template contains a Lambda function resource for the rule."""
        template = builder.generate_sam_template([sql_rule], data_source="security_lake")

        # Rule id "root-login" → safe_name "Root-Login" → "RootLogin" after replace
        resources = template["Resources"]
        assert len(resources) == 1

        # Find the function resource
        func_key = list(resources.keys())[0]
        func = resources[func_key]
        assert func["Type"] == "AWS::Serverless::Function"
        assert func["Properties"]["Runtime"] == "python3.12"
        assert func["Properties"]["Handler"] == "handler.handler"

    def test_generate_sam_template_schedule(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """SAM template includes EventBridge schedule from rule metadata."""
        template = builder.generate_sam_template([sql_rule], data_source="security_lake")

        func = list(template["Resources"].values())[0]
        event = func["Properties"]["Events"]["ScheduleEvent"]
        assert event["Type"] == "Schedule"
        assert event["Properties"]["Schedule"] == "rate(15 minutes)"
        assert event["Properties"]["Enabled"] is True

    def test_generate_sam_template_tags(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """SAM template includes tags with rule metadata."""
        template = builder.generate_sam_template([sql_rule], data_source="security_lake")

        func = list(template["Resources"].values())[0]
        tags = func["Properties"]["Tags"]
        assert tags["Application"] == "secdashboards"
        assert tags["RuleId"] == "root-login"
        assert tags["Severity"] == "high"

    def test_generate_sam_template_multiple_rules(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """SAM template supports multiple rules in one template."""
        meta2 = DetectionMetadata(
            id="iam-key-creation",
            name="IAM Key Creation",
            severity=Severity.MEDIUM,
            schedule="rate(5 minutes)",
        )
        rule2 = SQLDetectionRule(
            metadata=meta2,
            query_template="SELECT * FROM events WHERE event_name = 'CreateAccessKey'",
            threshold=1,
        )

        template = builder.generate_sam_template([sql_rule, rule2], data_source="security_lake")

        assert len(template["Resources"]) == 2

    def test_write_sam_template(
        self, builder: LambdaBuilder, sql_rule: SQLDetectionRule, tmp_path: Path
    ) -> None:
        """write_sam_template() writes valid YAML to disk."""
        template = builder.generate_sam_template([sql_rule], data_source="security_lake")
        output_path = tmp_path / "template.yaml"

        builder.write_sam_template(template, output_path)

        assert output_path.exists()
        parsed = yaml.safe_load(output_path.read_text())
        assert parsed["AWSTemplateFormatVersion"] == "2010-09-09"
        assert "Resources" in parsed


# ---------------------------------------------------------------------------
# DualTargetLambdaBuilder
# ---------------------------------------------------------------------------


class TestDualTargetLambdaBuilder:
    """Tests for dual-target (CloudWatch + Athena) handler generation."""

    def test_build_dual_target_handler_creates_file(
        self, dual_builder: DualTargetLambdaBuilder
    ) -> None:
        """build_dual_target_handler() creates a valid handler file."""
        handler_path = dual_builder.build_dual_target_handler(
            rule_id="test-dual",
            rule_name="Test Dual Rule",
            severity="medium",
            cloudwatch_query="fields @timestamp | filter @message like /ERROR/",
            athena_query="SELECT * FROM events WHERE severity >= 4",
            log_groups=["/aws/lambda/my-function"],
            threshold=3,
            lookback_minutes=30,
        )

        assert handler_path.exists()
        code = handler_path.read_text()
        assert 'RULE_ID = "test-dual"' in code
        assert "THRESHOLD = 3" in code
        assert "LOOKBACK_MINUTES = 30" in code
        assert "CLOUDWATCH_QUERY" in code
        assert "ATHENA_QUERY" in code
        assert "LOG_GROUPS" in code

    def test_build_dual_target_handler_is_valid_python(
        self, dual_builder: DualTargetLambdaBuilder
    ) -> None:
        """Generated dual-target handler is syntactically valid Python."""
        handler_path = dual_builder.build_dual_target_handler(
            rule_id="test-dual",
            rule_name="Test",
            severity="low",
            cloudwatch_query="fields @timestamp",
            athena_query="SELECT 1",
            log_groups=["/aws/lambda/test"],
        )
        code = handler_path.read_text()
        compile(code, handler_path.name, "exec")

    def test_build_from_dual_rule(
        self, dual_builder: DualTargetLambdaBuilder, dual_rule: DualTargetDetectionRule
    ) -> None:
        """build_from_dual_rule() works with a DualTargetDetectionRule."""
        handler_path = dual_builder.build_from_dual_rule(
            dual_rule,
            log_groups=["/aws/lambda/test"],
            lookback_minutes=10,
        )

        assert handler_path.exists()
        code = handler_path.read_text()
        assert 'RULE_ID = "lambda-errors"' in code
        assert "THRESHOLD = 5" in code
        assert "LOOKBACK_MINUTES = 10" in code

    def test_build_from_dual_rule_rejects_wrong_type(
        self, dual_builder: DualTargetLambdaBuilder, sql_rule: SQLDetectionRule
    ) -> None:
        """build_from_dual_rule() raises TypeError for non-dual rule."""
        with pytest.raises(TypeError, match="Expected DualTargetDetectionRule"):
            dual_builder.build_from_dual_rule(sql_rule, log_groups=[])  # type: ignore[arg-type]

    def test_generate_dual_target_sam_template(
        self, dual_builder: DualTargetLambdaBuilder, dual_rule: DualTargetDetectionRule
    ) -> None:
        """Dual-target SAM template includes CloudWatch Logs policy."""
        template = dual_builder.generate_dual_target_sam_template(
            rules=[dual_rule],
            log_groups_map={"lambda-errors": ["/aws/lambda/test"]},
            sns_topic_arn="arn:aws:sns:us-west-2:123456789012:alerts",
        )

        assert template["AWSTemplateFormatVersion"] == "2010-09-09"
        func = list(template["Resources"].values())[0]
        policies = func["Properties"]["Policies"]
        assert "CloudWatchLogsReadOnlyAccess" in policies
        assert func["Properties"]["Tags"]["DualTarget"] == "true"


# ---------------------------------------------------------------------------
# DetectionScheduler (mocked EventBridge)
# ---------------------------------------------------------------------------


class TestDetectionScheduler:
    """Tests for EventBridge schedule management."""

    @pytest.fixture()
    def scheduler(self) -> DetectionScheduler:
        """Scheduler with mocked EventBridge client."""
        s = DetectionScheduler(region="us-west-2")
        s._events_client = MagicMock()
        return s

    def test_create_schedule(
        self, scheduler: DetectionScheduler, sql_rule: SQLDetectionRule
    ) -> None:
        """create_schedule() creates an EventBridge rule and adds target."""
        scheduler.events_client.put_rule.return_value = {
            "RuleArn": "arn:aws:events:us-west-2:123456789012:rule/secdash-schedule-root-login",
        }

        lambda_arn = "arn:aws:lambda:us-west-2:123456789012:function:secdash-detection-root-login"

        with patch("secdashboards.deploy.scheduler.boto3") as mock_boto:
            mock_lambda = MagicMock()
            mock_boto.client.return_value = mock_lambda

            result = scheduler.create_schedule(sql_rule, lambda_arn)

        assert result["rule_name"] == "secdash-schedule-root-login"
        assert result["schedule"] == "rate(15 minutes)"
        assert result["enabled"] is True

        # Verify EventBridge rule was created
        scheduler.events_client.put_rule.assert_called_once()
        call_kwargs = scheduler.events_client.put_rule.call_args[1]
        assert call_kwargs["Name"] == "secdash-schedule-root-login"
        assert call_kwargs["ScheduleExpression"] == "rate(15 minutes)"
        assert call_kwargs["State"] == "ENABLED"

        # Verify target was added
        scheduler.events_client.put_targets.assert_called_once()

    def test_create_schedule_disabled(
        self, scheduler: DetectionScheduler, sql_rule: SQLDetectionRule
    ) -> None:
        """create_schedule(enabled=False) creates a DISABLED rule."""
        scheduler.events_client.put_rule.return_value = {
            "RuleArn": "arn:aws:events:us-west-2:123456789012:rule/test",
        }

        lambda_arn = "arn:aws:lambda:us-west-2:123456789012:function:test"

        with patch("secdashboards.deploy.scheduler.boto3"):
            result = scheduler.create_schedule(sql_rule, lambda_arn, enabled=False)

        assert result["enabled"] is False
        call_kwargs = scheduler.events_client.put_rule.call_args[1]
        assert call_kwargs["State"] == "DISABLED"

    def test_delete_schedule(
        self, scheduler: DetectionScheduler, sql_rule: SQLDetectionRule
    ) -> None:
        """delete_schedule() removes targets and deletes the rule."""
        scheduler.delete_schedule(sql_rule)

        scheduler.events_client.remove_targets.assert_called_once_with(
            Rule="secdash-schedule-root-login",
            Ids=["detection-root-login"],
        )
        scheduler.events_client.delete_rule.assert_called_once_with(
            Name="secdash-schedule-root-login",
        )

    def test_delete_schedule_handles_not_found(
        self, scheduler: DetectionScheduler, sql_rule: SQLDetectionRule
    ) -> None:
        """delete_schedule() succeeds even when rule doesn't exist."""
        not_found = type("ResourceNotFoundException", (Exception,), {})
        scheduler.events_client.exceptions.ResourceNotFoundException = not_found
        scheduler.events_client.delete_rule.side_effect = not_found()

        # Should not raise
        scheduler.delete_schedule(sql_rule)

    def test_enable_schedule(
        self, scheduler: DetectionScheduler, sql_rule: SQLDetectionRule
    ) -> None:
        """enable_schedule() calls enable_rule with correct name."""
        scheduler.enable_schedule(sql_rule)
        scheduler.events_client.enable_rule.assert_called_once_with(
            Name="secdash-schedule-root-login",
        )

    def test_disable_schedule(
        self, scheduler: DetectionScheduler, sql_rule: SQLDetectionRule
    ) -> None:
        """disable_schedule() calls disable_rule with correct name."""
        scheduler.disable_schedule(sql_rule)
        scheduler.events_client.disable_rule.assert_called_once_with(
            Name="secdash-schedule-root-login",
        )

    def test_get_schedule_status(
        self, scheduler: DetectionScheduler, sql_rule: SQLDetectionRule
    ) -> None:
        """get_schedule_status() returns status dict."""
        scheduler.events_client.describe_rule.return_value = {
            "Name": "secdash-schedule-root-login",
            "Arn": "arn:aws:events:us-west-2:123456789012:rule/secdash-schedule-root-login",
            "ScheduleExpression": "rate(15 minutes)",
            "State": "ENABLED",
            "Description": "Schedule for detection: Root User Login",
        }

        status = scheduler.get_schedule_status(sql_rule)

        assert status is not None
        assert status["rule_name"] == "secdash-schedule-root-login"
        assert status["state"] == "ENABLED"
        assert status["schedule"] == "rate(15 minutes)"

    def test_get_schedule_status_not_found(
        self, scheduler: DetectionScheduler, sql_rule: SQLDetectionRule
    ) -> None:
        """get_schedule_status() returns None when rule doesn't exist."""
        not_found = type("ResourceNotFoundException", (Exception,), {})
        scheduler.events_client.exceptions.ResourceNotFoundException = not_found
        scheduler.events_client.describe_rule.side_effect = not_found()

        status = scheduler.get_schedule_status(sql_rule)
        assert status is None

    def test_list_schedules(self, scheduler: DetectionScheduler) -> None:
        """list_schedules() returns all schedules with the prefix."""
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Rules": [
                    {
                        "Name": "secdash-schedule-root-login",
                        "Arn": "arn:aws:events:us-west-2:123:rule/secdash-schedule-root-login",
                        "ScheduleExpression": "rate(15 minutes)",
                        "State": "ENABLED",
                        "Description": "Root login detection",
                    },
                    {
                        "Name": "secdash-schedule-iam-key",
                        "Arn": "arn:aws:events:us-west-2:123:rule/secdash-schedule-iam-key",
                        "ScheduleExpression": "rate(5 minutes)",
                        "State": "DISABLED",
                        "Description": "IAM key creation detection",
                    },
                ]
            }
        ]
        scheduler.events_client.get_paginator.return_value = mock_paginator

        schedules = scheduler.list_schedules()

        assert len(schedules) == 2
        assert schedules[0]["rule_name"] == "secdash-schedule-root-login"
        assert schedules[1]["state"] == "DISABLED"


# ---------------------------------------------------------------------------
# End-to-end workflow
# ---------------------------------------------------------------------------


class TestE2EDeploymentWorkflow:
    """End-to-end tests for the full build → deploy → schedule pipeline."""

    def test_build_deploy_schedule(self, tmp_path: Path, sql_rule: SQLDetectionRule) -> None:
        """Complete workflow: build package → deploy Lambda → create schedule."""
        # 1. Build
        builder = LambdaBuilder(tmp_path)
        zip_path = builder.build_package(sql_rule, data_source="security_lake")
        assert zip_path.exists()

        # 2. Deploy (mocked)
        mock_lambda_client = MagicMock()
        not_found = type("ResourceNotFoundException", (Exception,), {})
        mock_lambda_client.exceptions.ResourceNotFoundException = not_found
        mock_lambda_client.update_function_code.side_effect = not_found()
        mock_lambda_client.create_function.return_value = {
            "FunctionArn": "arn:aws:lambda:us-west-2:123456789012:function:secdash-detection-root-login",
        }
        builder._lambda_client = mock_lambda_client

        deploy_result = builder.deploy_lambda(
            rule=sql_rule,
            package_path=zip_path,
            role_arn="arn:aws:iam::123456789012:role/detection-role",
            environment={
                "ATHENA_DATABASE": "security_lake_db",
                "ATHENA_OUTPUT_LOCATION": "s3://athena-results/",
                "SNS_TOPIC_ARN": "arn:aws:sns:us-west-2:123456789012:alerts",
            },
        )

        assert deploy_result["function_name"] == "secdash-detection-root-login"
        lambda_arn = deploy_result["function_arn"]

        # 3. Schedule (mocked)
        scheduler = DetectionScheduler(region="us-west-2")
        scheduler._events_client = MagicMock()
        scheduler.events_client.put_rule.return_value = {
            "RuleArn": "arn:aws:events:us-west-2:123456789012:rule/secdash-schedule-root-login",
        }

        with patch("secdashboards.deploy.scheduler.boto3") as mock_boto:
            mock_boto.client.return_value = MagicMock()
            schedule_result = scheduler.create_schedule(sql_rule, lambda_arn)

        assert schedule_result["rule_name"] == "secdash-schedule-root-login"
        assert schedule_result["schedule"] == "rate(15 minutes)"
        assert schedule_result["enabled"] is True

    def test_multi_rule_sam_workflow(self, tmp_path: Path) -> None:
        """Build handlers for multiple rules and generate a single SAM template."""
        # Create multiple rules
        rules = []
        for rule_id, name, severity, schedule in [
            ("root-login", "Root Login", Severity.HIGH, "rate(15 minutes)"),
            ("iam-key", "IAM Key Creation", Severity.MEDIUM, "rate(5 minutes)"),
            ("s3-public", "S3 Public Access", Severity.CRITICAL, "rate(1 hour)"),
        ]:
            meta = DetectionMetadata(
                id=rule_id,
                name=name,
                severity=severity,
                schedule=schedule,
                enabled=True,
            )
            rules.append(
                SQLDetectionRule(
                    metadata=meta,
                    query_template=f"SELECT * FROM events WHERE event = '{rule_id}'",
                    threshold=1,
                )
            )

        builder = LambdaBuilder(tmp_path)

        # Build all handlers
        for rule in rules:
            handler_path = builder.build_handler(rule, data_source="security_lake")
            assert handler_path.exists()

        # Generate SAM template
        template = builder.generate_sam_template(
            rules,
            data_source="security_lake",
            sns_topic_arn="arn:aws:sns:us-west-2:123456789012:detection-alerts",
        )

        assert len(template["Resources"]) == 3
        assert template["Parameters"]["SnsTopicArn"]["Default"] == (
            "arn:aws:sns:us-west-2:123456789012:detection-alerts"
        )

        # Write and verify YAML
        output_path = tmp_path / "template.yaml"
        builder.write_sam_template(template, output_path)
        parsed = yaml.safe_load(output_path.read_text())
        assert len(parsed["Resources"]) == 3

    def test_dual_target_e2e_workflow(
        self, tmp_path: Path, dual_rule: DualTargetDetectionRule
    ) -> None:
        """Build dual-target handler, package, and generate SAM template."""
        builder = DualTargetLambdaBuilder(tmp_path)

        # Build handler from dual rule
        handler_path = builder.build_from_dual_rule(
            dual_rule,
            log_groups=["/aws/lambda/my-function"],
            lookback_minutes=10,
        )
        assert handler_path.exists()
        code = handler_path.read_text()
        assert "CLOUDWATCH_QUERY" in code
        assert "ATHENA_QUERY" in code

        # Generate dual-target SAM template
        template = builder.generate_dual_target_sam_template(
            rules=[dual_rule],
            log_groups_map={"lambda-errors": ["/aws/lambda/my-function"]},
            sns_topic_arn="arn:aws:sns:us-west-2:123456789012:alerts",
        )

        func = list(template["Resources"].values())[0]
        assert func["Properties"]["FunctionName"] == "secdash-dual-lambda-errors"
        assert "CloudWatchLogsReadOnlyAccess" in func["Properties"]["Policies"]
