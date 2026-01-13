"""CloudWatch Events / EventBridge scheduler for detection rules."""

import contextlib
from typing import Any

import boto3
import structlog

from secdashboards.detections.rule import DetectionRule

logger = structlog.get_logger()


class DetectionScheduler:
    """Manages EventBridge schedules for detection rules."""

    def __init__(self, region: str = "us-west-2") -> None:
        self.region = region
        self._events_client = None

    @property
    def events_client(self) -> Any:
        if not self._events_client:
            self._events_client = boto3.client("events", region_name=self.region)
        return self._events_client

    def create_schedule(
        self,
        rule: DetectionRule,
        lambda_arn: str,
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Create or update an EventBridge rule for a detection."""
        rule_name = f"secdash-schedule-{rule.id}"

        # Create the EventBridge rule
        response = self.events_client.put_rule(
            Name=rule_name,
            ScheduleExpression=rule.metadata.schedule,
            State="ENABLED" if enabled else "DISABLED",
            Description=f"Schedule for detection: {rule.name}",
            Tags=[
                {"Key": "Application", "Value": "secdashboards"},
                {"Key": "RuleId", "Value": rule.id},
            ],
        )

        rule_arn = response["RuleArn"]

        # Add Lambda as target
        self.events_client.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    "Id": f"detection-{rule.id}",
                    "Arn": lambda_arn,
                }
            ],
        )

        # Add Lambda permission for EventBridge to invoke
        lambda_client = boto3.client("lambda", region_name=self.region)
        with contextlib.suppress(lambda_client.exceptions.ResourceConflictException):
            lambda_client.add_permission(
                FunctionName=lambda_arn,
                StatementId=f"EventBridge-{rule.id}",
                Action="lambda:InvokeFunction",
                Principal="events.amazonaws.com",
                SourceArn=rule_arn,
            )

        logger.info(
            "Created schedule for detection",
            rule_id=rule.id,
            schedule=rule.metadata.schedule,
            rule_arn=rule_arn,
        )

        return {
            "rule_name": rule_name,
            "rule_arn": rule_arn,
            "schedule": rule.metadata.schedule,
            "enabled": enabled,
        }

    def delete_schedule(self, rule: DetectionRule) -> None:
        """Delete the EventBridge rule for a detection."""
        rule_name = f"secdash-schedule-{rule.id}"

        # Remove targets first
        with contextlib.suppress(Exception):
            self.events_client.remove_targets(
                Rule=rule_name,
                Ids=[f"detection-{rule.id}"],
            )

        # Delete rule
        try:
            self.events_client.delete_rule(Name=rule_name)
            logger.info("Deleted schedule for detection", rule_id=rule.id)
        except self.events_client.exceptions.ResourceNotFoundException:
            pass

    def enable_schedule(self, rule: DetectionRule) -> None:
        """Enable the schedule for a detection."""
        rule_name = f"secdash-schedule-{rule.id}"
        self.events_client.enable_rule(Name=rule_name)
        logger.info("Enabled schedule for detection", rule_id=rule.id)

    def disable_schedule(self, rule: DetectionRule) -> None:
        """Disable the schedule for a detection."""
        rule_name = f"secdash-schedule-{rule.id}"
        self.events_client.disable_rule(Name=rule_name)
        logger.info("Disabled schedule for detection", rule_id=rule.id)

    def get_schedule_status(self, rule: DetectionRule) -> dict[str, Any] | None:
        """Get the current status of a detection schedule."""
        rule_name = f"secdash-schedule-{rule.id}"

        try:
            response = self.events_client.describe_rule(Name=rule_name)
            return {
                "rule_name": response["Name"],
                "rule_arn": response["Arn"],
                "schedule": response.get("ScheduleExpression"),
                "state": response["State"],
                "description": response.get("Description"),
            }
        except self.events_client.exceptions.ResourceNotFoundException:
            return None

    def list_schedules(self, prefix: str = "secdash-schedule-") -> list[dict[str, Any]]:
        """List all detection schedules."""
        schedules = []
        paginator = self.events_client.get_paginator("list_rules")

        for page in paginator.paginate(NamePrefix=prefix):
            for rule in page["Rules"]:
                schedules.append({
                    "rule_name": rule["Name"],
                    "rule_arn": rule["Arn"],
                    "schedule": rule.get("ScheduleExpression"),
                    "state": rule["State"],
                    "description": rule.get("Description"),
                })

        return schedules
