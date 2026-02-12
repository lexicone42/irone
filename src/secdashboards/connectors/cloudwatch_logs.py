"""CloudWatch Logs Insights connector for application log queries.

This connector provides a flexible interface for querying various application logs
via CloudWatch Logs Insights, supporting Lambda, EKS, ALB, and custom log sources.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import boto3
import structlog

if TYPE_CHECKING:
    import polars as pl
from botocore.exceptions import ClientError

from secdashboards.catalog.models import DataSource
from secdashboards.connectors.base import DataConnector, HealthCheckResult

logger = structlog.get_logger()


class LogSourceType(StrEnum):
    """Common CloudWatch log source types."""

    LAMBDA = "lambda"
    EKS = "eks"
    ALB = "alb"
    API_GATEWAY = "api_gateway"
    CLOUDFLARE = "cloudflare"
    CUSTOM = "custom"


# Log group patterns for common sources
LOG_GROUP_PATTERNS: dict[LogSourceType, str] = {
    LogSourceType.LAMBDA: "/aws/lambda/*",
    LogSourceType.EKS: "/aws/eks/*",
    LogSourceType.ALB: "/aws/alb/*",
    LogSourceType.API_GATEWAY: "/aws/apigateway/*",
    LogSourceType.CLOUDFLARE: "/cloudflare/*",  # Common convention for Cloudflare logs
}


class CloudWatchLogsConnector(DataConnector):
    """Connector for querying CloudWatch Logs via Logs Insights.

    This connector uses CloudWatch Logs Insights API for efficient querying
    of application logs without moving data to another service.

    Supports:
    - Lambda function logs
    - EKS container logs
    - ALB access logs
    - API Gateway access logs
    - Cloudflare logs (streamed via Kinesis/S3)
    - Custom application logs

    Example usage:
        source = DataSource(
            name="lambda-logs",
            type=DataSourceType.CLOUDWATCH_LOGS,
            region="us-west-2",
            connector_config={
                "log_groups": ["/aws/lambda/my-function"],
                "source_type": "lambda"
            }
        )
        connector = CloudWatchLogsConnector(source)
        df = connector.query_insights("fields @timestamp, @message | limit 100")
    """

    # Default query timeout in seconds
    DEFAULT_TIMEOUT = 120

    # Maximum concurrent queries
    MAX_CONCURRENT_QUERIES = 5

    # Cost limit: CloudWatch Logs Insights charges $0.005 per GB scanned
    DEFAULT_SCAN_LIMIT_GB = 10.0

    def __init__(self, source: DataSource) -> None:
        super().__init__(source)
        self._client = boto3.client("logs", region_name=source.region)
        self._log_groups: list[str] = source.connector_config.get("log_groups", [])
        self._source_type = LogSourceType(source.connector_config.get("source_type", "custom"))

    @property
    def log_groups(self) -> list[str]:
        """Get configured log groups."""
        return self._log_groups

    @property
    def source_type(self) -> LogSourceType:
        """Get the source type for this connector."""
        return self._source_type

    def discover_log_groups(
        self,
        pattern: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Discover available log groups matching a pattern.

        Args:
            pattern: Glob pattern to filter log groups (e.g., "/aws/lambda/*")
            limit: Maximum number of log groups to return

        Returns:
            List of log group info dicts with name, arn, storedBytes, retentionDays
        """
        # Use pattern from source type if not specified
        if pattern is None and self._source_type != LogSourceType.CUSTOM:
            pattern = LOG_GROUP_PATTERNS.get(self._source_type)

        paginator = self._client.get_paginator("describe_log_groups")
        log_groups = []

        try:
            # CloudWatch doesn't support wildcards directly, filter client-side
            for page in paginator.paginate(limit=limit):
                for lg in page.get("logGroups", []):
                    name = lg.get("logGroupName", "")
                    if pattern is None or self._match_pattern(name, pattern):
                        log_groups.append(
                            {
                                "name": name,
                                "arn": lg.get("arn"),
                                "stored_bytes": lg.get("storedBytes", 0),
                                "retention_days": lg.get("retentionInDays"),
                                "creation_time": lg.get("creationTime"),
                            }
                        )
                        if len(log_groups) >= limit:
                            return log_groups
        except ClientError as e:
            logger.error("log_group_discovery_failed", error=str(e))
            raise

        return log_groups

    @staticmethod
    def _match_pattern(name: str, pattern: str) -> bool:
        """Simple glob pattern matching for log group names."""
        import fnmatch

        return fnmatch.fnmatch(name, pattern)

    def query(self, sql: str) -> pl.DataFrame:
        """Execute a CloudWatch Logs Insights query.

        Note: This method accepts Logs Insights query syntax, not SQL.
        For backward compatibility with the DataConnector interface.
        """
        return self.query_insights(sql)

    def query_insights(
        self,
        query: str,
        start: datetime | None = None,
        end: datetime | None = None,
        log_groups: list[str] | None = None,
        timeout: int | None = None,
    ) -> pl.DataFrame:
        """Execute a CloudWatch Logs Insights query.

        Args:
            query: Logs Insights query string
            start: Start time for the query window (default: 1 hour ago)
            end: End time for the query window (default: now)
            log_groups: Override configured log groups
            timeout: Query timeout in seconds

        Returns:
            Query results as a Polars DataFrame
        """
        import polars as pl

        end = end or datetime.now(UTC)
        start = start or (end - timedelta(hours=1))
        groups = log_groups or self._log_groups
        timeout = timeout or self.DEFAULT_TIMEOUT

        if not groups:
            logger.warning("no_log_groups_configured")
            return pl.DataFrame()

        try:
            # Start the query
            response = self._client.start_query(
                logGroupNames=groups,
                startTime=int(start.timestamp() * 1000),
                endTime=int(end.timestamp() * 1000),
                queryString=query,
            )
            query_id = response["queryId"]

            logger.debug(
                "insights_query_started",
                query_id=query_id,
                log_groups=groups,
                query=query[:100],
            )

            # Poll for results
            return self._wait_for_query(query_id, timeout)

        except ClientError as e:
            logger.error("insights_query_failed", error=str(e), query=query[:100])
            raise

    def _wait_for_query(
        self,
        query_id: str,
        timeout: int,
    ) -> pl.DataFrame:
        """Wait for a Logs Insights query to complete."""
        import polars as pl

        start_time = time.time()

        while time.time() - start_time < timeout:
            response = self._client.get_query_results(queryId=query_id)
            status = response.get("status")

            if status == "Complete":
                return self._parse_results(response.get("results", []))
            elif status in ("Failed", "Cancelled", "Timeout"):
                logger.error("query_failed", query_id=query_id, status=status)
                return pl.DataFrame()

            # Exponential backoff
            elapsed = time.time() - start_time
            sleep_time = min(2.0, 0.5 * (1.5 ** (elapsed / 10)))
            time.sleep(sleep_time)

        # Query timed out
        logger.warning("query_timeout", query_id=query_id, timeout=timeout)
        with contextlib.suppress(ClientError):
            self._client.stop_query(queryId=query_id)

        return pl.DataFrame()

    def _parse_results(self, results: list[list[dict[str, str]]]) -> pl.DataFrame:
        """Parse Logs Insights results into a Polars DataFrame."""
        import polars as pl

        if not results:
            return pl.DataFrame()

        # Convert results to row dictionaries
        rows = []
        for result_row in results:
            row = {}
            for field in result_row:
                # Skip the @ptr field (internal pointer)
                if field.get("field") != "@ptr":
                    row[field.get("field", "unknown")] = field.get("value")
            rows.append(row)

        return pl.DataFrame(rows)

    def get_schema(self) -> dict[str, str]:
        """Get schema information for the log groups.

        CloudWatch Logs Insights extracts fields dynamically, so we return
        common fields for the configured source type.
        """
        common_fields = {
            "@timestamp": "timestamp",
            "@message": "string",
            "@logStream": "string",
            "@log": "string",
        }

        if self._source_type == LogSourceType.LAMBDA:
            common_fields.update(
                {
                    "@requestId": "string",
                    "@duration": "float",
                    "@billedDuration": "int",
                    "@memorySize": "int",
                    "@maxMemoryUsed": "int",
                    "level": "string",
                }
            )
        elif self._source_type == LogSourceType.EKS:
            common_fields.update(
                {
                    "kubernetes.pod_name": "string",
                    "kubernetes.namespace_name": "string",
                    "kubernetes.container_name": "string",
                    "kubernetes.host": "string",
                    "stream": "string",
                }
            )
        elif self._source_type == LogSourceType.ALB:
            common_fields.update(
                {
                    "type": "string",
                    "timestamp": "timestamp",
                    "elb": "string",
                    "client_ip": "string",
                    "client_port": "int",
                    "target_ip": "string",
                    "target_port": "int",
                    "request_processing_time": "float",
                    "target_processing_time": "float",
                    "response_processing_time": "float",
                    "elb_status_code": "int",
                    "target_status_code": "int",
                    "received_bytes": "int",
                    "sent_bytes": "int",
                    "request": "string",
                    "user_agent": "string",
                }
            )
        elif self._source_type == LogSourceType.CLOUDFLARE:
            common_fields.update(
                {
                    "ClientIP": "string",
                    "ClientRequestHost": "string",
                    "ClientRequestMethod": "string",
                    "ClientRequestURI": "string",
                    "EdgeResponseStatus": "int",
                    "EdgeServerIP": "string",
                    "RayID": "string",
                    "SecurityLevel": "string",
                    "WAFAction": "string",
                    "WAFRuleID": "string",
                    "OriginResponseStatus": "int",
                    "CacheCacheStatus": "string",
                }
            )

        return common_fields

    def check_health(self) -> HealthCheckResult:
        """Check CloudWatch Logs health for configured log groups."""
        start_time = time.time()

        if not self._log_groups:
            return HealthCheckResult(
                source_name=self.source.name,
                healthy=False,
                latency_seconds=time.time() - start_time,
                error="No log groups configured",
            )

        try:
            # Check for recent log events
            end = datetime.now(UTC)
            start = end - timedelta(hours=1)

            query = """
            fields @timestamp, @message
            | stats count(*) as event_count, max(@timestamp) as latest_time
            """

            df = self.query_insights(query, start=start, end=end, timeout=30)
            latency = time.time() - start_time

            if len(df) == 0:
                return HealthCheckResult(
                    source_name=self.source.name,
                    healthy=False,
                    latency_seconds=latency,
                    error="No data in the last hour",
                    details={"log_groups": self._log_groups},
                )

            record_count = int(df["event_count"][0]) if "event_count" in df.columns else 0
            latest_time_raw = df["latest_time"][0] if "latest_time" in df.columns else None

            last_time = None
            if latest_time_raw:
                try:
                    # Parse ISO format from Logs Insights
                    last_time = datetime.fromisoformat(str(latest_time_raw).replace("Z", "+00:00"))
                    if last_time.tzinfo is None:
                        last_time = last_time.replace(tzinfo=UTC)
                except (ValueError, TypeError):
                    pass

            healthy = record_count > 0
            if last_time:
                age_minutes = (datetime.now(UTC) - last_time).total_seconds() / 60
                healthy = age_minutes <= self.source.expected_freshness_minutes

            return HealthCheckResult(
                source_name=self.source.name,
                healthy=healthy,
                last_data_time=last_time,
                record_count=record_count,
                latency_seconds=latency,
                details={
                    "log_groups": self._log_groups,
                    "source_type": self._source_type,
                },
            )

        except Exception as e:
            return HealthCheckResult(
                source_name=self.source.name,
                healthy=False,
                latency_seconds=time.time() - start_time,
                error=str(e),
            )

    # -------------------------------------------------------------------------
    # Convenience methods for common log queries
    # -------------------------------------------------------------------------

    def query_lambda_errors(
        self,
        function_name: str | None = None,
        hours: int = 24,
        limit: int = 100,
    ) -> pl.DataFrame:
        """Query Lambda function errors and exceptions.

        Args:
            function_name: Specific function name (filters log stream)
            hours: Hours of history to query
            limit: Maximum number of records
        """
        query = f"""
        fields @timestamp, @message, @logStream, @requestId
        | filter @message like /ERROR|Exception|Traceback|Task timed out/
        | sort @timestamp desc
        | limit {limit}
        """

        if function_name:
            query = f"""
            filter @logStream like /{function_name}/
            | {query}
            """

        end = datetime.now(UTC)
        start = end - timedelta(hours=hours)
        return self.query_insights(query, start=start, end=end)

    def query_lambda_cold_starts(
        self,
        hours: int = 24,
        limit: int = 100,
    ) -> pl.DataFrame:
        """Query Lambda cold start events."""
        query = f"""
        fields @timestamp, @logStream
        | filter @message like /INIT_START/
        | stats count(*) as cold_starts by @logStream
        | sort cold_starts desc
        | limit {limit}
        """

        end = datetime.now(UTC)
        start = end - timedelta(hours=hours)
        return self.query_insights(query, start=start, end=end)

    def query_lambda_performance(
        self,
        hours: int = 24,
    ) -> pl.DataFrame:
        """Query Lambda performance metrics from logs."""
        query = """
        filter @type = "REPORT"
        | stats
            count(*) as invocations,
            avg(@duration) as avg_duration,
            max(@duration) as max_duration,
            avg(@maxMemoryUsed / @memorySize * 100) as avg_memory_pct,
            sum(@billedDuration) / 1000 as total_billed_seconds
        by bin(1h) as time_bucket
        | sort time_bucket desc
        """

        end = datetime.now(UTC)
        start = end - timedelta(hours=hours)
        return self.query_insights(query, start=start, end=end)

    def query_eks_pod_errors(
        self,
        namespace: str | None = None,
        hours: int = 24,
        limit: int = 100,
    ) -> pl.DataFrame:
        """Query EKS pod errors and crash loops."""
        query = f"""
        fields @timestamp, @message, kubernetes.pod_name, kubernetes.namespace_name
        | filter @message like /error|Error|ERROR|panic|PANIC|OOMKilled|CrashLoopBackOff/
        | sort @timestamp desc
        | limit {limit}
        """

        if namespace:
            query = f"""
            filter kubernetes.namespace_name = "{namespace}"
            | {query}
            """

        end = datetime.now(UTC)
        start = end - timedelta(hours=hours)
        return self.query_insights(query, start=start, end=end)

    def query_eks_pod_restarts(
        self,
        hours: int = 24,
    ) -> pl.DataFrame:
        """Query EKS pod restart patterns."""
        query = """
        fields kubernetes.pod_name, kubernetes.namespace_name
        | filter @message like /Started container|Back-off restarting/
        | stats count(*) as start_count by kubernetes.pod_name, kubernetes.namespace_name
        | filter start_count > 3
        | sort start_count desc
        """

        end = datetime.now(UTC)
        start = end - timedelta(hours=hours)
        return self.query_insights(query, start=start, end=end)

    def query_alb_access_logs(
        self,
        hours: int = 24,
        status_code: int | None = None,
        client_ip: str | None = None,
        limit: int = 1000,
    ) -> pl.DataFrame:
        """Query ALB access logs."""
        filters = []
        if status_code:
            filters.append(f"elb_status_code = {status_code}")
        if client_ip:
            filters.append(f'client_ip = "{client_ip}"')

        filter_clause = " and ".join(filters) if filters else "1=1"

        query = f"""
        fields @timestamp, client_ip, elb_status_code, target_status_code,
               request_processing_time, target_processing_time, request, user_agent
        | filter {filter_clause}
        | sort @timestamp desc
        | limit {limit}
        """

        end = datetime.now(UTC)
        start = end - timedelta(hours=hours)
        return self.query_insights(query, start=start, end=end)

    def query_alb_error_summary(
        self,
        hours: int = 24,
    ) -> pl.DataFrame:
        """Query ALB error rate summary."""
        query = """
        stats
            count(*) as total_requests,
            sum(elb_status_code >= 400 and elb_status_code < 500) as client_errors,
            sum(elb_status_code >= 500) as server_errors,
            avg(target_processing_time) as avg_latency,
            max(target_processing_time) as max_latency
        by bin(1h) as time_bucket
        | sort time_bucket desc
        """

        end = datetime.now(UTC)
        start = end - timedelta(hours=hours)
        return self.query_insights(query, start=start, end=end)

    def query_cloudflare_waf_events(
        self,
        hours: int = 24,
        action: str | None = None,
        limit: int = 100,
    ) -> pl.DataFrame:
        """Query Cloudflare WAF events from streamed logs."""
        filters = []
        if action:
            filters.append(f'WAFAction = "{action}"')

        filter_clause = " and ".join(filters) if filters else "WAFAction != ''"

        query = f"""
        fields @timestamp, ClientIP, ClientRequestHost, ClientRequestURI,
               WAFAction, WAFRuleID, EdgeResponseStatus, RayID
        | filter {filter_clause}
        | sort @timestamp desc
        | limit {limit}
        """

        end = datetime.now(UTC)
        start = end - timedelta(hours=hours)
        return self.query_insights(query, start=start, end=end)

    def query_cloudflare_security_summary(
        self,
        hours: int = 24,
    ) -> pl.DataFrame:
        """Query Cloudflare security event summary."""
        query = """
        stats
            count(*) as total_requests,
            sum(WAFAction = "block") as waf_blocks,
            sum(WAFAction = "challenge") as waf_challenges,
            sum(EdgeResponseStatus >= 400 and EdgeResponseStatus < 500) as client_errors,
            sum(EdgeResponseStatus >= 500) as origin_errors
        by bin(1h) as time_bucket
        | sort time_bucket desc
        """

        end = datetime.now(UTC)
        start = end - timedelta(hours=hours)
        return self.query_insights(query, start=start, end=end)

    def query_cloudflare_top_threats(
        self,
        hours: int = 24,
        limit: int = 20,
    ) -> pl.DataFrame:
        """Query top threat sources from Cloudflare logs."""
        query = f"""
        filter WAFAction in ["block", "challenge", "managed_challenge"]
        | stats count(*) as threat_count by ClientIP, WAFAction
        | sort threat_count desc
        | limit {limit}
        """

        end = datetime.now(UTC)
        start = end - timedelta(hours=hours)
        return self.query_insights(query, start=start, end=end)

    def query_api_gateway_errors(
        self,
        hours: int = 24,
        limit: int = 100,
    ) -> pl.DataFrame:
        """Query API Gateway access log errors."""
        query = f"""
        fields @timestamp, @message
        | filter status >= 400
        | sort @timestamp desc
        | limit {limit}
        """

        end = datetime.now(UTC)
        start = end - timedelta(hours=hours)
        return self.query_insights(query, start=start, end=end)

    def query_custom_pattern(
        self,
        pattern: str,
        hours: int = 24,
        limit: int = 100,
    ) -> pl.DataFrame:
        """Query logs matching a custom pattern.

        Args:
            pattern: Regex pattern to match in log messages
            hours: Hours of history to query
            limit: Maximum number of records
        """
        # Escape the pattern for Logs Insights
        safe_pattern = pattern.replace('"', '\\"')

        query = f"""
        fields @timestamp, @message, @logStream
        | filter @message like /{safe_pattern}/
        | sort @timestamp desc
        | limit {limit}
        """

        end = datetime.now(UTC)
        start = end - timedelta(hours=hours)
        return self.query_insights(query, start=start, end=end)

    async def query_multiple_async(
        self,
        queries: list[tuple[str, list[str]]],
        start: datetime | None = None,
        end: datetime | None = None,
        timeout: int | None = None,
    ) -> list[pl.DataFrame]:
        """Execute multiple queries concurrently.

        Args:
            queries: List of (query_string, log_groups) tuples
            start: Start time for all queries
            end: End time for all queries
            timeout: Query timeout in seconds

        Returns:
            List of DataFrames in the same order as input queries
        """
        end = end or datetime.now(UTC)
        start = start or (end - timedelta(hours=1))
        timeout = timeout or self.DEFAULT_TIMEOUT

        async def run_query(query: str, groups: list[str]) -> pl.DataFrame:
            # Run in thread pool since boto3 is synchronous
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, lambda: self.query_insights(query, start, end, groups, timeout)
            )

        # Limit concurrent queries
        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_QUERIES)

        async def bounded_query(query: str, groups: list[str]) -> pl.DataFrame:
            async with semaphore:
                return await run_query(query, groups)

        tasks = [bounded_query(q, g) for q, g in queries]
        return await asyncio.gather(*tasks)
