"""ETL utilities for transforming application logs to OCSF format.

This module provides transformers to convert CloudWatch Logs, Cloudflare logs,
ALB logs, and EKS logs into OCSF-compliant format for ingestion into Security Lake.

The ETL pattern supports a hot/cold tier architecture:
- Hot tier (0-7 days): CloudWatch Logs Insights for real-time queries
- Cold tier (7+ days): Security Lake for long-term storage and analysis

Reference: https://schema.ocsf.io/
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import boto3
import structlog

if TYPE_CHECKING:
    import polars as pl

logger = structlog.get_logger()


class OCSFCategory(IntEnum):
    """OCSF event categories."""

    SYSTEM_ACTIVITY = 1
    FINDINGS = 2
    IAM = 3
    NETWORK_ACTIVITY = 4
    DISCOVERY = 5
    APPLICATION_ACTIVITY = 6


class OCSFClass(IntEnum):
    """OCSF event class IDs for application logs."""

    # Network Activity (4xxx)
    NETWORK_ACTIVITY = 4001
    HTTP_ACTIVITY = 4002
    DNS_ACTIVITY = 4003

    # Application Activity (6xxx)
    WEB_RESOURCE_ACCESS = 6001
    APPLICATION_LIFECYCLE = 6002
    API_ACTIVITY = 6003
    WEB_RESOURCE_ACTIVITY = 6004


class OCSFSeverity(IntEnum):
    """OCSF severity levels."""

    UNKNOWN = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class OCSFStatus(IntEnum):
    """OCSF activity status codes."""

    UNKNOWN = 0
    SUCCESS = 1
    FAILURE = 2


class OCSFTransformer(ABC):
    """Base class for OCSF log transformers."""

    @property
    @abstractmethod
    def class_uid(self) -> int:
        """OCSF class_uid for this transformer."""
        ...

    @property
    @abstractmethod
    def class_name(self) -> str:
        """OCSF class_name for this transformer."""
        ...

    @property
    def category_uid(self) -> int:
        """OCSF category_uid derived from class_uid."""
        return self.class_uid // 1000

    @abstractmethod
    def transform(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Transform records to OCSF format."""
        ...

    def _generate_uid(self, record: dict[str, Any]) -> str:
        """Generate a unique ID for a record."""
        # Use deterministic hash if we have enough unique fields
        content = json.dumps(record, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()[:32]

    def _base_event(
        self,
        time: datetime,
        severity: OCSFSeverity = OCSFSeverity.INFO,
        status: OCSFStatus = OCSFStatus.SUCCESS,
    ) -> dict[str, Any]:
        """Create base OCSF event structure."""
        time_ms = int(time.timestamp() * 1000)
        return {
            "class_uid": self.class_uid,
            "class_name": self.class_name,
            "category_uid": self.category_uid,
            "category_name": self._get_category_name(),
            "severity_id": int(severity),
            "severity": severity.name.lower(),
            "status_id": int(status),
            "status": "Success" if status == OCSFStatus.SUCCESS else "Failure",
            "time": time_ms,
            "time_dt": time.isoformat(),
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "secdashboards-etl",
                    "vendor_name": "secdashboards",
                    "version": "1.0.0",
                },
                "uid": str(uuid4()),
                "logged_time": int(datetime.now(UTC).timestamp() * 1000),
            },
        }

    def _get_category_name(self) -> str:
        """Get category name from category_uid."""
        names = {
            1: "System Activity",
            2: "Findings",
            3: "Identity & Access Management",
            4: "Network Activity",
            5: "Discovery",
            6: "Application Activity",
        }
        return names.get(self.category_uid, "Unknown")


class LambdaLogTransformer(OCSFTransformer):
    """Transform Lambda logs to OCSF Application Lifecycle events."""

    @property
    def class_uid(self) -> int:
        return OCSFClass.APPLICATION_LIFECYCLE

    @property
    def class_name(self) -> str:
        return "Application Lifecycle"

    def transform(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Transform Lambda log records to OCSF format."""
        ocsf_records = []

        for record in records:
            timestamp = self._parse_timestamp(record.get("@timestamp"))
            message = record.get("@message", "")
            log_stream = record.get("@logStream", "")

            # Determine severity based on log content
            severity = self._detect_severity(message)

            # Parse function name from log stream (format: YYYY/MM/DD/[$LATEST]function-name)
            function_name = self._extract_function_name(log_stream)

            event = self._base_event(timestamp, severity)
            event.update(
                {
                    "activity_id": 1,  # Launch
                    "activity_name": "Launch",
                    "app": {
                        "name": function_name,
                        "type": "AWS Lambda",
                        "type_id": 1,  # Web Application
                        "uid": log_stream,
                    },
                    "message": message[:1024],  # Truncate long messages
                    "raw_data": message,
                    "unmapped": {
                        "log_stream": log_stream,
                        "request_id": record.get("@requestId"),
                    },
                }
            )

            # Add duration info if this is a REPORT line
            if "REPORT RequestId" in message:
                metrics = self._parse_report_line(message)
                event["unmapped"].update(metrics)

            ocsf_records.append(event)

        return ocsf_records

    def _parse_timestamp(self, ts: str | None) -> datetime:
        """Parse CloudWatch timestamp."""
        if not ts:
            return datetime.now(UTC)
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return datetime.now(UTC)

    def _detect_severity(self, message: str) -> OCSFSeverity:
        """Detect severity from log message content."""
        msg_upper = message.upper()
        if any(kw in msg_upper for kw in ["CRITICAL", "FATAL"]):
            return OCSFSeverity.CRITICAL
        if any(kw in msg_upper for kw in ["ERROR", "EXCEPTION", "TRACEBACK"]):
            return OCSFSeverity.HIGH
        if "WARN" in msg_upper:
            return OCSFSeverity.MEDIUM
        if "DEBUG" in msg_upper:
            return OCSFSeverity.LOW
        return OCSFSeverity.INFO

    def _extract_function_name(self, log_stream: str) -> str:
        """Extract function name from log stream."""
        # Format: YYYY/MM/DD/[$LATEST]function-name
        parts = log_stream.split("/")
        if len(parts) >= 4:
            return parts[-1].removeprefix("[$LATEST]")
        return log_stream

    def _parse_report_line(self, message: str) -> dict[str, Any]:
        """Parse Lambda REPORT line for metrics."""
        metrics = {}
        # REPORT RequestId: xxx Duration: 123.45 ms ...
        import re

        patterns = {
            "duration_ms": r"Duration:\s+([\d.]+)\s+ms",
            "billed_duration_ms": r"Billed Duration:\s+(\d+)\s+ms",
            "memory_size_mb": r"Memory Size:\s+(\d+)\s+MB",
            "max_memory_used_mb": r"Max Memory Used:\s+(\d+)\s+MB",
            "init_duration_ms": r"Init Duration:\s+([\d.]+)\s+ms",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, message)
            if match:
                metrics[key] = float(match.group(1))
        return metrics


class ALBLogTransformer(OCSFTransformer):
    """Transform ALB access logs to OCSF HTTP Activity events."""

    @property
    def class_uid(self) -> int:
        return OCSFClass.HTTP_ACTIVITY

    @property
    def class_name(self) -> str:
        return "HTTP Activity"

    def transform(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Transform ALB access log records to OCSF format."""
        ocsf_records = []

        for record in records:
            timestamp = self._parse_timestamp(record.get("@timestamp"))

            # Determine severity from status code
            status_code = record.get("elb_status_code", 200)
            severity = self._status_to_severity(status_code)
            status = OCSFStatus.SUCCESS if status_code < 400 else OCSFStatus.FAILURE

            event = self._base_event(timestamp, severity, status)
            event.update(
                {
                    "activity_id": 1,  # Access
                    "activity_name": "Access",
                    "http_request": {
                        "url": {
                            "url_string": record.get("request", ""),
                        },
                        "http_method": self._extract_method(record.get("request", "")),
                        "user_agent": record.get("user_agent"),
                    },
                    "http_response": {
                        "code": status_code,
                    },
                    "src_endpoint": {
                        "ip": record.get("client_ip"),
                        "port": record.get("client_port"),
                    },
                    "dst_endpoint": {
                        "ip": record.get("target_ip"),
                        "port": record.get("target_port"),
                    },
                    "connection_info": {
                        "protocol_name": "HTTP",
                    },
                    "unmapped": {
                        "elb": record.get("elb"),
                        "target_status_code": record.get("target_status_code"),
                        "request_processing_time": record.get("request_processing_time"),
                        "target_processing_time": record.get("target_processing_time"),
                        "response_processing_time": record.get("response_processing_time"),
                        "received_bytes": record.get("received_bytes"),
                        "sent_bytes": record.get("sent_bytes"),
                    },
                }
            )

            ocsf_records.append(event)

        return ocsf_records

    def _parse_timestamp(self, ts: str | None) -> datetime:
        """Parse ALB timestamp."""
        if not ts:
            return datetime.now(UTC)
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return datetime.now(UTC)

    def _status_to_severity(self, code: int) -> OCSFSeverity:
        """Map HTTP status code to severity."""
        if code >= 500:
            return OCSFSeverity.HIGH
        if code >= 400:
            return OCSFSeverity.MEDIUM
        if code >= 300:
            return OCSFSeverity.LOW
        return OCSFSeverity.INFO

    def _extract_method(self, request: str) -> str:
        """Extract HTTP method from request string."""
        # Format: "METHOD URL HTTP/1.1"
        parts = request.split()
        return parts[0] if parts else "UNKNOWN"


class CloudflareLogTransformer(OCSFTransformer):
    """Transform Cloudflare logs to OCSF HTTP Activity events."""

    @property
    def class_uid(self) -> int:
        return OCSFClass.HTTP_ACTIVITY

    @property
    def class_name(self) -> str:
        return "HTTP Activity"

    def transform(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Transform Cloudflare log records to OCSF format."""
        ocsf_records = []

        for record in records:
            timestamp = self._parse_timestamp(record.get("@timestamp"))

            # Determine severity from response status and WAF action
            status_code = record.get("EdgeResponseStatus", 200)
            waf_action = record.get("WAFAction", "")
            severity = self._determine_severity(status_code, waf_action)
            status = OCSFStatus.SUCCESS if status_code < 400 else OCSFStatus.FAILURE

            event = self._base_event(timestamp, severity, status)

            # Build URL from components
            host = record.get("ClientRequestHost", "")
            uri = record.get("ClientRequestURI", "")
            url = f"https://{host}{uri}" if host else uri

            event.update(
                {
                    "activity_id": 1,  # Access
                    "activity_name": "Access",
                    "http_request": {
                        "url": {
                            "hostname": host,
                            "path": uri,
                            "url_string": url,
                        },
                        "http_method": record.get("ClientRequestMethod"),
                    },
                    "http_response": {
                        "code": status_code,
                    },
                    "src_endpoint": {
                        "ip": record.get("ClientIP"),
                    },
                    "dst_endpoint": {
                        "ip": record.get("EdgeServerIP"),
                    },
                    "connection_info": {
                        "protocol_name": "HTTPS",
                    },
                    # Cloudflare-specific security fields
                    "security_controls": self._extract_security_info(record),
                    "unmapped": {
                        "ray_id": record.get("RayID"),
                        "cache_status": record.get("CacheCacheStatus"),
                        "origin_response_status": record.get("OriginResponseStatus"),
                        "security_level": record.get("SecurityLevel"),
                        "country": record.get("ClientCountry"),
                    },
                }
            )

            ocsf_records.append(event)

        return ocsf_records

    def _parse_timestamp(self, ts: str | None) -> datetime:
        """Parse Cloudflare timestamp."""
        if not ts:
            return datetime.now(UTC)
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return datetime.now(UTC)

    def _determine_severity(self, status_code: int, waf_action: str) -> OCSFSeverity:
        """Determine severity from status code and WAF action."""
        # WAF blocks are always high severity
        if waf_action in ["block", "drop"]:
            return OCSFSeverity.HIGH
        if waf_action in ["challenge", "managed_challenge"]:
            return OCSFSeverity.MEDIUM

        # Fall back to status code
        if status_code >= 500:
            return OCSFSeverity.HIGH
        if status_code >= 400:
            return OCSFSeverity.MEDIUM
        return OCSFSeverity.INFO

    def _extract_security_info(self, record: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract Cloudflare security control info."""
        controls = []
        waf_action = record.get("WAFAction")
        if waf_action:
            controls.append(
                {
                    "type": "WAF",
                    "type_id": 1,
                    "state": waf_action,
                    "state_id": 1 if waf_action == "block" else 0,
                    "uid": record.get("WAFRuleID"),
                }
            )
        return controls


class EKSLogTransformer(OCSFTransformer):
    """Transform EKS container logs to OCSF Application Lifecycle events."""

    @property
    def class_uid(self) -> int:
        return OCSFClass.APPLICATION_LIFECYCLE

    @property
    def class_name(self) -> str:
        return "Application Lifecycle"

    def transform(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Transform EKS container log records to OCSF format."""
        ocsf_records = []

        for record in records:
            timestamp = self._parse_timestamp(record.get("@timestamp"))
            message = record.get("@message", "")

            # Determine severity
            severity = self._detect_severity(message)

            # Extract Kubernetes metadata
            k8s = self._extract_k8s_metadata(record)

            event = self._base_event(timestamp, severity)
            event.update(
                {
                    "activity_id": 1,  # Launch
                    "activity_name": "Log",
                    "app": {
                        "name": k8s.get("container_name", "unknown"),
                        "type": "Container",
                        "type_id": 2,
                        "uid": k8s.get("pod_name", ""),
                    },
                    "message": message[:1024],
                    "raw_data": message,
                    "resources": [
                        {
                            "type": "kubernetes.pod",
                            "name": k8s.get("pod_name"),
                            "namespace": k8s.get("namespace"),
                            "details": json.dumps(k8s),
                        }
                    ],
                    "unmapped": k8s,
                }
            )

            ocsf_records.append(event)

        return ocsf_records

    def _parse_timestamp(self, ts: str | None) -> datetime:
        """Parse EKS timestamp."""
        if not ts:
            return datetime.now(UTC)
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return datetime.now(UTC)

    def _detect_severity(self, message: str) -> OCSFSeverity:
        """Detect severity from log message."""
        msg_upper = message.upper()
        if any(kw in msg_upper for kw in ["PANIC", "FATAL", "CRITICAL"]):
            return OCSFSeverity.CRITICAL
        if any(kw in msg_upper for kw in ["ERROR", "EXCEPTION", "OOMKILLED"]):
            return OCSFSeverity.HIGH
        if "WARN" in msg_upper:
            return OCSFSeverity.MEDIUM
        if "DEBUG" in msg_upper:
            return OCSFSeverity.LOW
        return OCSFSeverity.INFO

    def _extract_k8s_metadata(self, record: dict[str, Any]) -> dict[str, Any]:
        """Extract Kubernetes metadata from record."""
        # Handle both dot notation and nested dict
        k8s = record.get("kubernetes", {})
        if isinstance(k8s, dict):
            return {
                "pod_name": k8s.get("pod_name", record.get("kubernetes.pod_name")),
                "namespace": k8s.get("namespace_name", record.get("kubernetes.namespace_name")),
                "container_name": k8s.get(
                    "container_name", record.get("kubernetes.container_name")
                ),
                "host": k8s.get("host", record.get("kubernetes.host")),
                "labels": k8s.get("labels", {}),
            }
        return {
            "pod_name": record.get("kubernetes.pod_name"),
            "namespace": record.get("kubernetes.namespace_name"),
            "container_name": record.get("kubernetes.container_name"),
            "host": record.get("kubernetes.host"),
        }


class LogETLPipeline:
    """Pipeline for transforming and exporting logs to OCSF format.

    Example usage:
        pipeline = LogETLPipeline()
        pipeline.register_transformer("lambda", LambdaLogTransformer())

        # Transform logs
        ocsf_records = pipeline.transform("lambda", raw_records)

        # Export to parquet for S3 upload
        pipeline.export_parquet(ocsf_records, "output/lambda_logs.parquet")
    """

    def __init__(self) -> None:
        self._transformers: dict[str, OCSFTransformer] = {}
        self._register_default_transformers()

    def _register_default_transformers(self) -> None:
        """Register built-in transformers."""
        self._transformers["lambda"] = LambdaLogTransformer()
        self._transformers["alb"] = ALBLogTransformer()
        self._transformers["cloudflare"] = CloudflareLogTransformer()
        self._transformers["eks"] = EKSLogTransformer()

    def register_transformer(self, name: str, transformer: OCSFTransformer) -> None:
        """Register a custom transformer."""
        self._transformers[name] = transformer

    def list_transformers(self) -> list[str]:
        """List registered transformer names."""
        return list(self._transformers.keys())

    def transform(
        self,
        source_type: str,
        records: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Transform records using the appropriate transformer."""
        transformer = self._transformers.get(source_type)
        if not transformer:
            raise ValueError(f"No transformer registered for source type: {source_type}")

        return transformer.transform(records)

    def transform_dataframe(
        self,
        source_type: str,
        df: pl.DataFrame,
    ) -> pl.DataFrame:
        """Transform a Polars DataFrame to OCSF format."""
        import polars as pl

        records = df.to_dicts()
        ocsf_records = self.transform(source_type, records)
        return pl.DataFrame(ocsf_records)

    def export_parquet(
        self,
        records: list[dict[str, Any]],
        output_path: str,
        partition_by: list[str] | None = None,
    ) -> None:
        """Export OCSF records to Parquet format for S3 upload.

        Args:
            records: OCSF-formatted records
            output_path: Output file path
            partition_by: Optional columns to partition by (e.g., ['class_uid', 'time_dt'])
        """
        import polars as pl

        df = pl.DataFrame(records)

        if partition_by:
            # Write partitioned dataset
            output_dir = str(Path(output_path).parent)
            df.write_parquet(
                output_dir,
                partition_by=partition_by,
            )
        else:
            df.write_parquet(output_path)

        logger.info(
            "exported_ocsf_parquet",
            output_path=output_path,
            record_count=len(records),
        )

    def export_json_lines(
        self,
        records: list[dict[str, Any]],
        output_path: str,
    ) -> None:
        """Export OCSF records to JSON Lines format."""
        with Path(output_path).open("w") as f:
            for record in records:
                f.write(json.dumps(record, default=str) + "\n")

        logger.info(
            "exported_ocsf_jsonl",
            output_path=output_path,
            record_count=len(records),
        )


class CloudWatchLogExporter:
    """Export CloudWatch Logs to S3 using the Export Task API.

    This is the most cost-effective method for batch log exports, avoiding
    Firehose costs. Ideal for rolling logs from CloudWatch to Security Lake
    after a retention period (e.g., 7 days).

    Cost comparison:
    - Firehose: $0.029/GB ingested
    - Export Task: ~$0.03/GB (one-time) + S3 storage

    Example usage:
        exporter = CloudWatchLogExporter(
            destination_bucket="my-security-lake-bucket",
            destination_prefix="custom-logs/cloudwatch/",
            region="us-west-2"
        )

        # Export logs from the last 7 days
        task_id = exporter.export_log_group(
            log_group="/aws/lambda/my-function",
            days_ago=7
        )

        # Wait for completion
        exporter.wait_for_export(task_id)
    """

    def __init__(
        self,
        destination_bucket: str,
        destination_prefix: str = "cloudwatch-exports/",
        region: str = "us-west-2",
    ) -> None:
        self._client = boto3.client("logs", region_name=region)
        self._s3_client = boto3.client("s3", region_name=region)
        self._bucket = destination_bucket
        self._prefix = destination_prefix
        self._region = region

    def export_log_group(
        self,
        log_group: str,
        start: datetime | None = None,
        end: datetime | None = None,
        days_ago: int = 7,
        destination_prefix: str | None = None,
    ) -> str:
        """Create an export task for a log group.

        Args:
            log_group: CloudWatch log group name
            start: Export start time (default: days_ago)
            end: Export end time (default: now)
            days_ago: Days of logs to export (if start not specified)
            destination_prefix: Override default S3 prefix

        Returns:
            Export task ID for tracking
        """

        end = end or datetime.now(UTC)
        start = start or (end - timedelta(days=days_ago))

        # Build S3 prefix with date partitioning
        prefix = destination_prefix or self._prefix
        date_partition = start.strftime("%Y/%m/%d")
        full_prefix = f"{prefix}{log_group.lstrip('/')}/{date_partition}"

        try:
            response = self._client.create_export_task(
                logGroupName=log_group,
                fromTime=int(start.timestamp() * 1000),
                to=int(end.timestamp() * 1000),
                destination=self._bucket,
                destinationPrefix=full_prefix,
            )

            task_id = response["taskId"]
            logger.info(
                "export_task_created",
                task_id=task_id,
                log_group=log_group,
                start=start.isoformat(),
                end=end.isoformat(),
                destination=f"s3://{self._bucket}/{full_prefix}",
            )
            return task_id

        except self._client.exceptions.LimitExceededException:
            # Only one export task can run per account at a time
            logger.warning("export_task_limit_exceeded", log_group=log_group)
            raise
        except self._client.exceptions.ResourceNotFoundException:
            logger.error("log_group_not_found", log_group=log_group)
            raise

    def get_export_status(self, task_id: str) -> dict[str, Any]:
        """Get the status of an export task."""
        response = self._client.describe_export_tasks(taskId=task_id)
        tasks = response.get("exportTasks", [])
        if tasks:
            return tasks[0]
        return {"status": {"code": "UNKNOWN"}}

    def wait_for_export(
        self,
        task_id: str,
        timeout: int = 3600,
        poll_interval: int = 30,
    ) -> bool:
        """Wait for an export task to complete.

        Args:
            task_id: Export task ID
            timeout: Maximum wait time in seconds
            poll_interval: Seconds between status checks

        Returns:
            True if export completed successfully
        """
        import time as time_module

        start_time = time_module.time()

        while time_module.time() - start_time < timeout:
            status = self.get_export_status(task_id)
            code = status.get("status", {}).get("code", "UNKNOWN")

            if code == "COMPLETED":
                logger.info("export_task_completed", task_id=task_id)
                return True
            elif code in ("CANCELLED", "FAILED"):
                logger.error(
                    "export_task_failed",
                    task_id=task_id,
                    status=status,
                )
                return False

            logger.debug(
                "export_task_pending",
                task_id=task_id,
                status=code,
            )
            time_module.sleep(poll_interval)

        logger.warning("export_task_timeout", task_id=task_id)
        return False

    def export_multiple_log_groups(
        self,
        log_groups: list[str],
        days_ago: int = 7,
    ) -> list[str]:
        """Export multiple log groups sequentially.

        Note: AWS limits concurrent export tasks to 1 per account,
        so exports are run sequentially.

        Args:
            log_groups: List of log group names
            days_ago: Days of logs to export

        Returns:
            List of task IDs
        """
        task_ids = []

        for log_group in log_groups:
            try:
                task_id = self.export_log_group(log_group, days_ago=days_ago)
                task_ids.append(task_id)

                # Wait for completion before starting next
                self.wait_for_export(task_id)

            except Exception as e:
                logger.error(
                    "export_failed",
                    log_group=log_group,
                    error=str(e),
                )
                continue

        return task_ids

    def setup_bucket_policy(self) -> str:
        """Generate the required bucket policy for CloudWatch Logs exports.

        Returns the policy JSON that must be applied to the destination bucket.
        """
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowCloudWatchLogsExport",
                    "Effect": "Allow",
                    "Principal": {"Service": "logs.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{self._bucket}",
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceAccount": ["ACCOUNT_ID"]  # Replace with actual account ID
                        }
                    },
                },
                {
                    "Sid": "AllowCloudWatchLogsWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "logs.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{self._bucket}/{self._prefix}*",
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-acl": "bucket-owner-full-control",
                            "aws:SourceAccount": ["ACCOUNT_ID"],  # Replace with actual account ID
                        }
                    },
                },
            ],
        }
        return json.dumps(policy, indent=2)
