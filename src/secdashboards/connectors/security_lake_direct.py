"""Direct Security Lake connector — DuckDB with Iceberg/Glue catalog.

Bypasses Athena entirely by using DuckDB's Iceberg extension to read
Security Lake tables directly from S3 via the Glue Data Catalog.

Expected latency: <1s per query (vs 5-30s through Athena).

Requirements:
    - DuckDB >= 1.1.0 (Iceberg extension with Glue endpoint support)
    - IAM permissions: glue:GetTable, glue:GetTables, glue:GetDatabase,
      s3:GetObject, s3:ListBucket on the Security Lake bucket
    - Lake Formation grants (same as Athena)
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime
from typing import Any

import duckdb
import structlog

from secdashboards.catalog.models import DataSource
from secdashboards.connectors.base import DataConnector, HealthCheckResult
from secdashboards.connectors.result import QueryResult
from secdashboards.connectors.sql_utils import quote_table

logger = structlog.get_logger()


def _result_to_query_result(result: Any) -> QueryResult:
    """Convert a DuckDB result to a QueryResult using fetchall + description."""
    if result.description is None:
        return QueryResult.empty()
    columns = [desc[0] for desc in result.description]
    rows = [dict(zip(columns, row, strict=True)) for row in result.fetchall()]
    return QueryResult(columns=columns, rows=rows)


class _SharedConnection:
    """Module-level shared DuckDB connection for Iceberg/Glue access.

    All SecurityLakeDirectConnector instances sharing the same
    (account_id, region, catalog_alias) key reuse a single DuckDB
    connection.  This avoids loading the iceberg extension 5× when the
    monitoring router checks all Security Lake sources in parallel.

    Thread safety: a threading.Lock serializes all ``execute()`` calls.
    DuckDB is single-writer, so this is the correct approach.
    """

    _instances: dict[tuple[str, str, str], _SharedConnection] = {}
    _class_lock = threading.Lock()

    def __init__(self, account_id: str, region: str, catalog_alias: str) -> None:
        self._account_id = account_id
        self._region = region
        self._catalog_alias = catalog_alias
        self._conn: duckdb.DuckDBPyConnection | None = None
        self._attached = False
        self._lock = threading.Lock()

    @classmethod
    def get(cls, account_id: str, region: str, catalog_alias: str) -> _SharedConnection:
        """Get or create a shared connection for the given key."""
        key = (account_id, region, catalog_alias)
        with cls._class_lock:
            if key not in cls._instances:
                cls._instances[key] = cls(account_id, region, catalog_alias)
            return cls._instances[key]

    @classmethod
    def _reset(cls) -> None:
        """Reset all shared connections (for testing only)."""
        with cls._class_lock:
            for inst in cls._instances.values():
                inst.close()
            cls._instances.clear()

    def ensure_ready(self) -> duckdb.DuckDBPyConnection:
        """Ensure the connection is initialized with extensions and catalog."""
        with self._lock:
            if self._conn is not None and self._attached:
                return self._conn

            if self._conn is None:
                self._conn = duckdb.connect(":memory:")

            # Lambda has no writable HOME — point DuckDB to /tmp for extension cache
            self._conn.execute("SET home_directory = '/tmp';")

            # Install all extensions first (avro is a transitive dep of iceberg —
            # must be installed explicitly before LOAD iceberg, otherwise iceberg's
            # init tries to auto-install it and fails to find home_directory on Lambda)
            for ext in ("httpfs", "aws", "avro", "iceberg"):
                self._conn.execute(f"INSTALL {ext};")
            for ext in ("httpfs", "aws", "avro", "iceberg"):
                self._conn.execute(f"LOAD {ext};")

            # Configure AWS region
            self._conn.execute(f"SET s3_region = '{self._region}';")

            # Attach Glue catalog
            self._conn.execute(
                f"ATTACH '{self._account_id}' AS {self._catalog_alias} "
                f"(TYPE iceberg, ENDPOINT_TYPE 'glue');"
            )
            self._attached = True

            logger.info(
                "glue_catalog_attached",
                account_id=self._account_id,
                region=self._region,
                alias=self._catalog_alias,
            )
            return self._conn

    def execute(self, sql: str) -> Any:
        """Execute SQL with the lock held."""
        conn = self.ensure_ready()
        with self._lock:
            return conn.execute(sql)

    def close(self) -> None:
        """Close the underlying connection."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
                self._attached = False


class SecurityLakeDirectConnector(DataConnector):
    """Direct Iceberg connector for Security Lake via DuckDB + Glue catalog.

    Instead of routing queries through Athena (queue → compile → execute →
    S3 result write → poll), this connector:

    1. Installs DuckDB's iceberg, httpfs, and aws extensions
    2. ATTACHes the Glue catalog as an Iceberg database
    3. Queries Security Lake Parquet files directly from S3

    All connector instances sharing the same account/region/alias use a
    single shared DuckDB connection to avoid duplicate extension loading
    and excessive memory usage on Lambda (512MB–1024MB).

    The ``account_id`` is required for Glue catalog attachment and can be
    supplied via ``source.connector_config["account_id"]``.

    The attached catalog name defaults to ``"sl"`` and qualifies tables as
    ``sl.<database>.<table>``.
    """

    # OCSF time field used by Security Lake
    TIME_FIELD = "time_dt"

    def __init__(self, source: DataSource) -> None:
        super().__init__(source)
        self._account_id: str = source.connector_config.get("account_id", "")
        self._region: str = source.region or "us-west-2"
        self._catalog_alias: str = source.connector_config.get("catalog_alias", "sl")

    def _get_shared(self) -> _SharedConnection:
        """Get the shared connection, validating account_id first."""
        if not self._account_id:
            raise ValueError(
                "account_id is required for Glue catalog attachment. "
                "Set SECDASH_ACCOUNT_ID or pass account_id in connector_config."
            )
        return _SharedConnection.get(self._account_id, self._region, self._catalog_alias)

    def _qualified_table(self) -> str:
        """Build the fully qualified table name: sl.database.table.

        Uses the DuckDB identifier quoting from sql_utils for the database
        and table components, but prefixes with the catalog alias.
        """
        db = self.source.database or "default"
        table = self.source.table or "unknown"
        # quote_table returns "db"."table" — prepend catalog alias
        return f"{self._catalog_alias}.{quote_table(db, table)}"

    def query(self, sql: str) -> QueryResult:
        """Execute a SQL query against the attached Iceberg catalog."""
        shared = self._get_shared()
        result = shared.execute(sql)
        return _result_to_query_result(result)

    def get_schema(self) -> dict[str, str]:
        """Get the schema of the Security Lake table.

        Uses DuckDB's DESCRIBE to introspect the Iceberg table structure.
        """
        table_ref = self._qualified_table()
        try:
            shared = self._get_shared()
            result = shared.execute(f"DESCRIBE {table_ref}")
            qr = _result_to_query_result(result)
            if qr.is_empty():
                return {}
            return dict(
                zip(
                    qr["column_name"].to_list(),
                    qr["column_type"].to_list(),
                    strict=True,
                )
            )
        except Exception as e:
            logger.warning("describe_failed", table=table_ref, error=str(e))
            return {}

    def check_health(self) -> HealthCheckResult:
        """Check Security Lake data freshness via direct Iceberg read.

        Runs the same COUNT/MAX query as SecurityLakeConnector but against
        the DuckDB-attached Iceberg table — expected <1s vs 5-30s via Athena.
        """
        start_time = time.time()

        try:
            table = self._qualified_table()
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

            last_time = self._parse_timestamp(last_time_raw)

            # Determine health based on freshness
            healthy = record_count > 0
            if last_time:
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
                details={
                    "event_class_count": class_count,
                    "connector": "direct_iceberg",
                },
            )

        except Exception as e:
            return HealthCheckResult(
                source_name=self.source.name,
                healthy=False,
                latency_seconds=time.time() - start_time,
                error=str(e),
                details={"connector": "direct_iceberg"},
            )

    @staticmethod
    def _parse_timestamp(raw: Any) -> datetime | None:
        """Parse a timestamp value from DuckDB query results."""
        if raw is None:
            return None
        if isinstance(raw, datetime):
            if raw.tzinfo is None:
                return raw.replace(tzinfo=UTC)
            return raw
        if isinstance(raw, str):
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=UTC)
            return parsed
        return None

    def close(self) -> None:
        """Close the shared connection (affects all instances with same key)."""
        if self._account_id:
            shared = _SharedConnection.get(self._account_id, self._region, self._catalog_alias)
            shared.close()
