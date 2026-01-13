"""Athena connector for querying data via AWS Athena."""

import io
import time
from datetime import UTC, datetime
from typing import Any

import boto3
import polars as pl

from secdashboards.catalog.models import DataSource
from secdashboards.connectors.base import DataConnector, HealthCheckResult
from secdashboards.connectors.sql_utils import (
    quote_identifier,
    quote_table,
    sanitize_string,
)


class AthenaConnector(DataConnector):
    """Connector for AWS Athena queries."""

    def __init__(self, source: DataSource) -> None:
        super().__init__(source)
        self._athena = boto3.client("athena", region_name=source.region)
        self._s3 = boto3.client("s3", region_name=source.region)

        # Output location for query results
        self._output_location = source.connector_config.get(
            "output_location", f"s3://aws-athena-query-results-{source.region}/"
        )
        self._workgroup = source.connector_config.get("workgroup", "primary")

    def query(self, sql: str) -> pl.DataFrame:
        """Execute a SQL query and return results as a Polars DataFrame."""
        # Start query execution
        response = self._athena.start_query_execution(
            QueryString=sql,
            QueryExecutionContext={"Database": self.source.database or "default"},
            ResultConfiguration={"OutputLocation": self._output_location},
            WorkGroup=self._workgroup,
        )

        query_execution_id = response["QueryExecutionId"]

        # Wait for query to complete
        self._wait_for_query(query_execution_id)

        # Get results location and read with Polars
        result_response = self._athena.get_query_execution(QueryExecutionId=query_execution_id)
        result_location = result_response["QueryExecution"]["ResultConfiguration"][
            "OutputLocation"
        ]

        return self._read_results(result_location)

    def _wait_for_query(self, query_execution_id: str, max_wait_seconds: int = 300) -> None:
        """Wait for an Athena query to complete."""
        start_time = time.time()

        while True:
            response = self._athena.get_query_execution(QueryExecutionId=query_execution_id)
            state = response["QueryExecution"]["Status"]["State"]

            if state == "SUCCEEDED":
                return
            elif state in ("FAILED", "CANCELLED"):
                reason = response["QueryExecution"]["Status"].get(
                    "StateChangeReason", "Unknown error"
                )
                raise RuntimeError(f"Query {state}: {reason}")

            if time.time() - start_time > max_wait_seconds:
                raise TimeoutError(f"Query did not complete within {max_wait_seconds} seconds")

            time.sleep(1)

    def _read_results(self, s3_location: str) -> pl.DataFrame:
        """Read query results from S3."""
        # Parse S3 location
        # Format: s3://bucket/key
        parts = s3_location.replace("s3://", "").split("/", 1)
        bucket = parts[0]
        key = parts[1] if len(parts) > 1 else ""

        # Download and read CSV
        response = self._s3.get_object(Bucket=bucket, Key=key)
        csv_content = response["Body"].read()

        return pl.read_csv(io.BytesIO(csv_content))

    def get_schema(self) -> dict[str, str]:
        """Get the schema of the table."""
        if not self.source.table:
            return {}

        # Sanitize database and table names to prevent SQL injection
        safe_database = sanitize_string(self.source.database or "default")
        safe_table = sanitize_string(self.source.table)

        sql = f"""
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_schema = '{safe_database}'
          AND table_name = '{safe_table}'
        """

        df = self.query(sql)
        columns = df["column_name"].to_list()
        types = df["data_type"].to_list()
        return dict(zip(columns, types, strict=True))

    def check_health(self) -> HealthCheckResult:
        """Check if the data source is healthy."""
        start_time = time.time()

        try:
            # Use custom health check query or default
            if self.source.health_check_query:
                sql = self.source.health_check_query
            else:
                # Use proper identifier quoting for table names
                table = quote_table(
                    self.source.database or "default",
                    self.source.table or "unknown",
                )
                sql = f"""
                SELECT COUNT(*) as cnt, MAX(time) as latest_time
                FROM {table}
                WHERE time >= CURRENT_TIMESTAMP - INTERVAL '1' HOUR
                """

            df = self.query(sql)
            latency = time.time() - start_time

            record_count = int(df["cnt"][0]) if len(df) > 0 else 0
            last_time = None
            if len(df) > 0 and "latest_time" in df.columns:
                last_time = df["latest_time"][0]

            # Parse last_time if it's a string
            if isinstance(last_time, str):
                last_time = datetime.fromisoformat(last_time.replace("Z", "+00:00"))

            # Determine health based on freshness
            healthy = True
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
            )

        except Exception as e:
            return HealthCheckResult(
                source_name=self.source.name,
                healthy=False,
                latency_seconds=time.time() - start_time,
                error=str(e),
            )

    def list_tables(self) -> list[dict[str, Any]]:
        """List all tables in the database."""
        # Sanitize database name to prevent SQL injection
        safe_database = sanitize_string(self.source.database or "default")

        sql = f"""
        SELECT table_name, table_type
        FROM information_schema.tables
        WHERE table_schema = '{safe_database}'
        """
        df = self.query(sql)
        return df.to_dicts()
