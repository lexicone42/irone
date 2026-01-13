"""AWS Security Lake connector with OCSF schema support."""

import time
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from typing import Any

import polars as pl
import structlog

from secdashboards.catalog.models import DataSource
from secdashboards.connectors.athena import AthenaConnector
from secdashboards.connectors.base import HealthCheckResult
from secdashboards.connectors.sql_utils import (
    SQLSanitizationError,
    quote_table,
    sanitize_int,
    sanitize_string,
    validate_ipv4,
)

logger = structlog.get_logger()


class OCSFEventClass(IntEnum):
    """OCSF event class IDs commonly found in Security Lake."""

    # System Activity (1xxx)
    FILE_ACTIVITY = 1001
    KERNEL_EXTENSION = 1002
    KERNEL_ACTIVITY = 1003
    MEMORY_ACTIVITY = 1004
    MODULE_ACTIVITY = 1005
    SCHEDULED_JOB_ACTIVITY = 1006
    PROCESS_ACTIVITY = 1007

    # Findings (2xxx)
    SECURITY_FINDING = 2001
    VULNERABILITY_FINDING = 2002
    COMPLIANCE_FINDING = 2003
    DETECTION_FINDING = 2004
    INCIDENT_FINDING = 2005

    # Identity & Access Management (3xxx)
    ACCOUNT_CHANGE = 3001
    AUTHENTICATION = 3002
    AUTHORIZE_SESSION = 3003
    ENTITY_MANAGEMENT = 3004
    USER_ACCESS_MANAGEMENT = 3005
    GROUP_MANAGEMENT = 3006

    # Network Activity (4xxx)
    NETWORK_ACTIVITY = 4001
    HTTP_ACTIVITY = 4002
    DNS_ACTIVITY = 4003
    DHCP_ACTIVITY = 4004
    RDP_ACTIVITY = 4005
    SMB_ACTIVITY = 4006
    SSH_ACTIVITY = 4007
    FTP_ACTIVITY = 4008
    EMAIL_ACTIVITY = 4009
    NETWORK_FILE_ACTIVITY = 4010
    EMAIL_FILE_ACTIVITY = 4011
    EMAIL_URL_ACTIVITY = 4012
    NTP_ACTIVITY = 4013
    TUNNEL_ACTIVITY = 4014

    # Application Activity (6xxx)
    WEB_RESOURCE_ACCESS_ACTIVITY = 6001
    APPLICATION_LIFECYCLE = 6002
    API_ACTIVITY = 6003
    WEB_RESOURCE_ACTIVITY = 6004
    DATASTORE_ACTIVITY = 6005
    FILE_HOSTING_ACTIVITY = 6006
    SCAN_ACTIVITY = 6007


class SecurityLakeConnector(AthenaConnector):
    """Connector for AWS Security Lake with OCSF schema awareness."""

    # OCSF time fields - time_dt is a proper timestamp, time is epoch ms
    TIME_FIELD = "time_dt"
    TIME_EPOCH_FIELD = "time"

    # Security Lake standard tables
    CLOUDTRAIL_MGMT = "cloud_trail_mgmt"
    CLOUDTRAIL_DATA = "cloud_trail_data"
    VPC_FLOW = "vpc_flow"
    ROUTE53 = "route53"
    SECURITY_HUB = "sh_findings"
    LAMBDA_LOGS = "lambda"

    def __init__(self, source: DataSource) -> None:
        super().__init__(source)

    @staticmethod
    def _format_timestamp(dt: datetime) -> str:
        """Format datetime for Athena TIMESTAMP literal.

        Athena expects format: YYYY-MM-DD HH:MM:SS.ffffff (no T, no timezone)
        """
        # Remove timezone info and format without T separator
        dt_naive = dt.replace(tzinfo=None) if dt.tzinfo else dt
        return dt_naive.strftime("%Y-%m-%d %H:%M:%S.%f")

    def query_by_event_class(
        self,
        event_class: OCSFEventClass | str,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 1000,
        additional_filters: str | None = None,
    ) -> pl.DataFrame:
        """Query events by OCSF event class ID.

        SECURITY NOTE: The additional_filters parameter accepts raw SQL.
        Callers MUST sanitize any user input before passing it here.
        Use the helper methods (query_authentication_events, etc.) which
        handle sanitization automatically.
        """
        end = end or datetime.now(UTC)
        start = start or (end - timedelta(hours=1))

        # Use proper identifier quoting for table names
        table = quote_table(
            self.source.database or "default",
            self.source.table or "unknown",
        )

        # Safely convert event_class to integer
        class_uid = sanitize_int(int(event_class))

        # Sanitize limit to prevent injection
        safe_limit = sanitize_int(limit)
        if safe_limit > 10000:
            safe_limit = 10000  # Cap at reasonable limit

        sql = f"""
        SELECT *
        FROM {table}
        WHERE class_uid = {class_uid}
          AND time_dt >= TIMESTAMP '{self._format_timestamp(start)}'
          AND time_dt < TIMESTAMP '{self._format_timestamp(end)}'
        """

        if additional_filters:
            # Log warning if filters look suspicious
            if any(kw in additional_filters.upper() for kw in ["DROP", "DELETE", "INSERT", "UPDATE", "TRUNCATE"]):
                logger.warning(
                    "suspicious_sql_filter_detected",
                    filter=additional_filters[:100],
                )
            sql += f" AND ({additional_filters})"

        sql += f" LIMIT {safe_limit}"

        return self.query(sql)

    def query_authentication_events(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        status: str | None = None,
        limit: int = 1000,
    ) -> pl.DataFrame:
        """Query authentication events."""
        filters = None
        if status:
            # Sanitize status to prevent SQL injection
            safe_status = sanitize_string(status)
            filters = f"status = '{safe_status}'"

        return self.query_by_event_class(
            OCSFEventClass.AUTHENTICATION,
            start=start,
            end=end,
            limit=limit,
            additional_filters=filters,
        )

    def query_api_activity(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        service: str | None = None,
        operation: str | None = None,
        limit: int = 1000,
    ) -> pl.DataFrame:
        """Query API activity events (CloudTrail)."""
        filters = []
        if service:
            # Sanitize service name to prevent SQL injection
            safe_service = sanitize_string(service)
            filters.append(f""""api"."service"."name" = '{safe_service}'""")
        if operation:
            # Sanitize operation name to prevent SQL injection
            safe_operation = sanitize_string(operation)
            filters.append(f""""api"."operation" = '{safe_operation}'""")

        additional = " AND ".join(filters) if filters else None

        return self.query_by_event_class(
            OCSFEventClass.API_ACTIVITY,
            start=start,
            end=end,
            limit=limit,
            additional_filters=additional,
        )

    def query_network_activity(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        dst_port: int | None = None,
        limit: int = 1000,
    ) -> pl.DataFrame:
        """Query network activity events."""
        filters = []
        if src_ip:
            try:
                # Validate IP address format to prevent injection
                safe_ip = validate_ipv4(src_ip)
                filters.append(f""""src_endpoint"."ip" = '{safe_ip}'""")
            except SQLSanitizationError:
                logger.warning("invalid_source_ip_format", ip=src_ip)
                return pl.DataFrame()
        if dst_ip:
            try:
                # Validate IP address format to prevent injection
                safe_ip = validate_ipv4(dst_ip)
                filters.append(f""""dst_endpoint"."ip" = '{safe_ip}'""")
            except SQLSanitizationError:
                logger.warning("invalid_dest_ip_format", ip=dst_ip)
                return pl.DataFrame()
        if dst_port is not None:
            # Validate port is an integer to prevent injection
            safe_port = sanitize_int(dst_port)
            if 0 <= safe_port <= 65535:
                filters.append(f""""dst_endpoint"."port" = {safe_port}""")
            else:
                logger.warning("invalid_port_range", port=dst_port)
                return pl.DataFrame()

        additional = " AND ".join(filters) if filters else None

        return self.query_by_event_class(
            OCSFEventClass.NETWORK_ACTIVITY,
            start=start,
            end=end,
            limit=limit,
            additional_filters=additional,
        )

    def query_security_findings(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        severity: str | None = None,
        limit: int = 1000,
    ) -> pl.DataFrame:
        """Query security findings."""
        filters = None
        if severity:
            # Sanitize severity to prevent SQL injection
            safe_severity = sanitize_string(severity)
            filters = f"severity = '{safe_severity}'"

        return self.query_by_event_class(
            OCSFEventClass.SECURITY_FINDING,
            start=start,
            end=end,
            limit=limit,
            additional_filters=filters,
        )

    def get_event_summary(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> pl.DataFrame:
        """Get a summary of events by class."""
        end = end or datetime.now(UTC)
        start = start or (end - timedelta(hours=24))

        # Use proper identifier quoting for table names
        table = quote_table(
            self.source.database or "default",
            self.source.table or "unknown",
        )

        sql = f"""
        SELECT
            class_uid,
            class_name,
            COUNT(*) as event_count,
            MIN(time_dt) as earliest,
            MAX(time_dt) as latest
        FROM {table}
        WHERE time_dt >= TIMESTAMP '{self._format_timestamp(start)}'
          AND time_dt < TIMESTAMP '{self._format_timestamp(end)}'
        GROUP BY class_uid, class_name
        ORDER BY event_count DESC
        """

        return self.query(sql)

    def check_health(self) -> HealthCheckResult:
        """Check Security Lake data source health."""
        start_time = time.time()

        try:
            # Use proper identifier quoting for table names
            table = quote_table(
                self.source.database or "default",
                self.source.table or "unknown",
            )
            sql = f"""
            SELECT
                COUNT(*) as cnt,
                MAX(time_dt) as latest_time,
                COUNT(DISTINCT class_uid) as class_count
            FROM {table}
            WHERE time_dt >= CURRENT_TIMESTAMP - INTERVAL '1' HOUR
            """

            df = self.query(sql)
            latency = time.time() - start_time

            record_count = int(df["cnt"][0]) if len(df) > 0 else 0
            class_count = int(df["class_count"][0]) if len(df) > 0 else 0
            last_time_raw = df["latest_time"][0] if len(df) > 0 else None

            last_time = None
            if isinstance(last_time_raw, str):
                last_time = datetime.fromisoformat(last_time_raw.replace("Z", "+00:00"))
            elif isinstance(last_time_raw, datetime):
                last_time = last_time_raw

            # Determine health
            healthy = record_count > 0
            if last_time:
                delta = datetime.now(UTC) - last_time.replace(tzinfo=None)
                age_minutes = delta.total_seconds() / 60
                healthy = age_minutes <= self.source.expected_freshness_minutes

            return HealthCheckResult(
                source_name=self.source.name,
                healthy=healthy,
                last_data_time=last_time,
                record_count=record_count,
                latency_seconds=latency,
                details={"event_class_count": class_count},
            )

        except Exception as e:
            return HealthCheckResult(
                source_name=self.source.name,
                healthy=False,
                latency_seconds=time.time() - start_time,
                error=str(e),
            )

    def list_available_tables(self) -> list[dict[str, Any]]:
        """List all Security Lake tables in the database."""
        return self.list_tables()
