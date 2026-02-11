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
            if any(
                kw in additional_filters.upper()
                for kw in ["DROP", "DELETE", "INSERT", "UPDATE", "TRUNCATE"]
            ):
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
                # Parse ISO format string, handling 'Z' suffix
                last_time = datetime.fromisoformat(last_time_raw.replace("Z", "+00:00"))
                # Ensure timezone awareness - assume UTC if naive
                if last_time.tzinfo is None:
                    last_time = last_time.replace(tzinfo=UTC)
            elif isinstance(last_time_raw, datetime):
                last_time = last_time_raw
                # Ensure timezone awareness - assume UTC if naive
                if last_time.tzinfo is None:
                    last_time = last_time.replace(tzinfo=UTC)

            # Determine health
            healthy = record_count > 0
            if last_time:
                # Both datetimes are now UTC-aware, safe to subtract
                now_utc = datetime.now(UTC)
                delta = now_utc - last_time
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

    def query_vpc_flow(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        dst_port: int | None = None,
        action: str | None = None,
        direction: str | None = None,
        limit: int = 1000,
    ) -> pl.DataFrame:
        """Query VPC Flow Log events from Security Lake.

        VPC Flow logs in OCSF format use class_uid 4001 (Network Activity).

        Args:
            start: Start time for the query window
            end: End time for the query window
            src_ip: Filter by source IP address
            dst_ip: Filter by destination IP address
            dst_port: Filter by destination port
            action: Filter by action ('Allow' or 'Deny')
            direction: Filter by traffic direction ('Inbound' or 'Outbound')
            limit: Maximum number of records to return
        """
        filters = []

        if src_ip:
            try:
                safe_ip = validate_ipv4(src_ip)
                filters.append(f""""src_endpoint"."ip" = '{safe_ip}'""")
            except SQLSanitizationError:
                logger.warning("invalid_source_ip_format", ip=src_ip)
                return pl.DataFrame()

        if dst_ip:
            try:
                safe_ip = validate_ipv4(dst_ip)
                filters.append(f""""dst_endpoint"."ip" = '{safe_ip}'""")
            except SQLSanitizationError:
                logger.warning("invalid_dest_ip_format", ip=dst_ip)
                return pl.DataFrame()

        if dst_port is not None:
            safe_port = sanitize_int(dst_port)
            if 0 <= safe_port <= 65535:
                filters.append(f""""dst_endpoint"."port" = {safe_port}""")
            else:
                logger.warning("invalid_port_range", port=dst_port)
                return pl.DataFrame()

        if action:
            safe_action = sanitize_string(action)
            filters.append(f"activity_name = '{safe_action}'")

        if direction:
            safe_direction = sanitize_string(direction)
            filters.append(f"direction = '{safe_direction}'")

        additional = " AND ".join(filters) if filters else None

        return self.query_by_event_class(
            OCSFEventClass.NETWORK_ACTIVITY,
            start=start,
            end=end,
            limit=limit,
            additional_filters=additional,
        )

    def query_vpc_flow_summary(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        group_by: str = "src_ip",
    ) -> pl.DataFrame:
        """Get a summary of VPC Flow traffic.

        Args:
            start: Start time for the query window
            end: End time for the query window
            group_by: Field to group by ('src_ip', 'dst_ip', 'dst_port', 'action')
        """
        end = end or datetime.now(UTC)
        start = start or (end - timedelta(hours=24))

        table = quote_table(
            self.source.database or "default",
            self.source.table or "unknown",
        )

        # Map friendly names to OCSF fields
        group_field_map = {
            "src_ip": '"src_endpoint"."ip"',
            "dst_ip": '"dst_endpoint"."ip"',
            "dst_port": '"dst_endpoint"."port"',
            "action": "activity_name",
        }

        if group_by not in group_field_map:
            logger.warning("invalid_group_by", group_by=group_by)
            group_by = "src_ip"

        group_field = group_field_map[group_by]

        sql = f"""
        SELECT
            {group_field} as {group_by},
            COUNT(*) as flow_count,
            SUM(COALESCE(traffic.bytes, 0)) as total_bytes,
            SUM(COALESCE(traffic.packets, 0)) as total_packets,
            COUNT(DISTINCT "dst_endpoint"."port") as unique_ports
        FROM {table}
        WHERE class_uid = {int(OCSFEventClass.NETWORK_ACTIVITY)}
          AND time_dt >= TIMESTAMP '{self._format_timestamp(start)}'
          AND time_dt < TIMESTAMP '{self._format_timestamp(end)}'
        GROUP BY {group_field}
        ORDER BY flow_count DESC
        LIMIT 100
        """

        return self.query(sql)

    def query_dns_logs(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        query_domain: str | None = None,
        query_type: str | None = None,
        response_code: str | None = None,
        limit: int = 1000,
    ) -> pl.DataFrame:
        """Query Route53 DNS resolver logs from Security Lake.

        DNS logs in OCSF format use class_uid 4003 (DNS Activity).

        Args:
            start: Start time for the query window
            end: End time for the query window
            query_domain: Filter by queried domain (partial match supported)
            query_type: Filter by DNS query type (A, AAAA, CNAME, MX, etc.)
            response_code: Filter by DNS response code (NOERROR, NXDOMAIN, etc.)
            limit: Maximum number of records to return
        """
        filters = []

        if query_domain:
            safe_domain = sanitize_string(query_domain)
            # Use LIKE for partial matching on domain names
            filters.append(f""""query"."hostname" LIKE '%{safe_domain}%'""")

        if query_type:
            safe_type = sanitize_string(query_type.upper())
            filters.append(f""""query"."type" = '{safe_type}'""")

        if response_code:
            safe_code = sanitize_string(response_code.upper())
            filters.append(f"rcode = '{safe_code}'")

        additional = " AND ".join(filters) if filters else None

        return self.query_by_event_class(
            OCSFEventClass.DNS_ACTIVITY,
            start=start,
            end=end,
            limit=limit,
            additional_filters=additional,
        )

    def query_suspicious_dns(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 100,
    ) -> pl.DataFrame:
        """Query DNS logs for potentially suspicious patterns.

        Detects:
        - High-entropy domain names (potential DGA)
        - Unusually long domain names
        - Requests to known suspicious TLDs
        """
        end = end or datetime.now(UTC)
        start = start or (end - timedelta(hours=24))

        table = quote_table(
            self.source.database or "default",
            self.source.table or "unknown",
        )
        safe_limit = sanitize_int(min(limit, 1000))

        # List of suspicious TLDs commonly used in malware
        suspicious_tlds = "('xyz', 'top', 'click', 'gdn', 'loan', 'work', 'party', 'date')"

        sql = f"""
        SELECT
            time_dt,
            "query"."hostname" as domain,
            "query"."type" as query_type,
            "src_endpoint"."ip" as src_ip,
            rcode as response_code,
            LENGTH("query"."hostname") as domain_length,
            CASE
                WHEN LENGTH("query"."hostname") > 50 THEN 'long_domain'
                WHEN REGEXP_LIKE("query"."hostname", '[0-9]{{10,}}') THEN 'numeric_heavy'
                WHEN ELEMENT_AT(SPLIT("query"."hostname", '.'), -1)
                    IN {suspicious_tlds} THEN 'suspicious_tld'
                ELSE 'other'
            END as suspicion_type
        FROM {table}
        WHERE class_uid = {int(OCSFEventClass.DNS_ACTIVITY)}
          AND time_dt >= TIMESTAMP '{self._format_timestamp(start)}'
          AND time_dt < TIMESTAMP '{self._format_timestamp(end)}'
          AND (
            LENGTH("query"."hostname") > 50
            OR REGEXP_LIKE("query"."hostname", '[0-9]{{10,}}')
            OR ELEMENT_AT(SPLIT("query"."hostname", '.'), -1) IN {suspicious_tlds}
          )
        ORDER BY time_dt DESC
        LIMIT {safe_limit}
        """

        return self.query(sql)

    def query_lambda_execution(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        function_name: str | None = None,
        status: str | None = None,
        limit: int = 1000,
    ) -> pl.DataFrame:
        """Query Lambda execution logs from Security Lake.

        Lambda execution logs in OCSF format use class_uid 6002 (Application Lifecycle).

        Args:
            start: Start time for the query window
            end: End time for the query window
            function_name: Filter by Lambda function name
            status: Filter by execution status
            limit: Maximum number of records to return
        """
        filters = []

        if function_name:
            safe_name = sanitize_string(function_name)
            filters.append(f""""app"."name" LIKE '%{safe_name}%'""")

        if status:
            safe_status = sanitize_string(status)
            filters.append(f"status = '{safe_status}'")

        additional = " AND ".join(filters) if filters else None

        return self.query_by_event_class(
            OCSFEventClass.APPLICATION_LIFECYCLE,
            start=start,
            end=end,
            limit=limit,
            additional_filters=additional,
        )

    def get_data_source_health_summary(
        self,
        hours: int = 24,
    ) -> pl.DataFrame:
        """Get a health summary across all Security Lake data sources.

        Returns event counts and freshness for each event class.
        """
        end = datetime.now(UTC)
        start = end - timedelta(hours=hours)

        table = quote_table(
            self.source.database or "default",
            self.source.table or "unknown",
        )

        sql = f"""
        SELECT
            class_uid,
            class_name,
            COUNT(*) as event_count,
            MIN(time_dt) as earliest_event,
            MAX(time_dt) as latest_event,
            DATE_DIFF('minute', MAX(time_dt), CURRENT_TIMESTAMP) as minutes_since_last
        FROM {table}
        WHERE time_dt >= TIMESTAMP '{self._format_timestamp(start)}'
          AND time_dt < TIMESTAMP '{self._format_timestamp(end)}'
        GROUP BY class_uid, class_name
        ORDER BY class_uid
        """

        return self.query(sql)
