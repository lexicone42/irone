"""DuckDB connector for local and Lambda SQL queries."""

from __future__ import annotations

import time
from typing import Any

import duckdb

from secdashboards.catalog.models import DataSource
from secdashboards.connectors.base import DataConnector, HealthCheckResult
from secdashboards.connectors.result import QueryResult


def _quote_ident(name: str) -> str:
    """Quote a SQL identifier by escaping embedded double-quotes."""
    return '"' + name.replace('"', '""') + '"'


def _result_to_query_result(result: Any) -> QueryResult:
    """Convert a DuckDB result to a QueryResult using fetchall + description."""
    columns = [desc[0] for desc in result.description]
    rows = [dict(zip(columns, row, strict=True)) for row in result.fetchall()]
    return QueryResult(columns=columns, rows=rows)


class DuckDBConnector(DataConnector):
    """Connector for DuckDB — local/in-memory SQL engine.

    Reads ``db_path`` from ``source.connector_config`` (defaults to ``:memory:``).
    Supports loading DataFrames, Parquet files (including S3 via httpfs),
    and standard SQL queries.
    """

    def __init__(self, source: DataSource) -> None:
        super().__init__(source)
        db_path = source.connector_config.get("db_path", ":memory:")
        self._conn = duckdb.connect(db_path)

    def query(self, sql: str) -> QueryResult:
        """Execute a SQL query and return results as a QueryResult."""
        result = self._conn.execute(sql)
        return _result_to_query_result(result)

    def get_schema(self) -> dict[str, str]:
        """Get the schema of tables in the database.

        Returns a mapping of ``table.column`` to data type for all tables,
        or ``column`` to type when ``source.table`` is set.
        """
        if self.source.database and self.source.table:
            sql = """
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_schema = ?
              AND table_name = ?
            """
            result = self._conn.execute(sql, [self.source.database, self.source.table])
        elif self.source.table:
            sql = """
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = ?
            """
            result = self._conn.execute(sql, [self.source.table])
        else:
            sql = """
            SELECT table_name || '.' || column_name AS column_name, data_type
            FROM information_schema.columns
            """
            result = self._conn.execute(sql)

        df = _result_to_query_result(result)
        if df.is_empty():
            return {}
        columns = df["column_name"].to_list()
        types = df["data_type"].to_list()
        return dict(zip(columns, types, strict=True))

    def check_health(self) -> HealthCheckResult:
        """Check if the DuckDB connection is healthy."""
        start_time = time.time()
        try:
            tables_df = self.query(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema NOT IN ('information_schema', 'pg_catalog')"
            )
            table_count = len(tables_df)

            total_rows = 0
            for table_name in tables_df["table_name"].to_list():
                count_df = self.query(f"SELECT COUNT(*) AS cnt FROM {_quote_ident(table_name)}")
                total_rows += int(count_df["cnt"][0])

            latency = time.time() - start_time
            return HealthCheckResult(
                source_name=self.source.name,
                healthy=True,
                record_count=total_rows,
                latency_seconds=latency,
                details={"table_count": table_count},
            )
        except Exception as e:
            return HealthCheckResult(
                source_name=self.source.name,
                healthy=False,
                latency_seconds=time.time() - start_time,
                error=str(e),
            )

    def import_parquet(self, path: str, table_name: str) -> int:
        """Load a Parquet file (local or S3) into a DuckDB table.

        For S3 paths, installs and loads the ``httpfs`` and ``aws`` extensions
        automatically. Returns the number of rows loaded.
        """
        if path.startswith("s3://"):
            self._conn.execute("INSTALL httpfs; LOAD httpfs;")
            self._conn.execute("INSTALL aws; LOAD aws;")

        quoted = _quote_ident(table_name)
        self._conn.execute(
            f"CREATE OR REPLACE TABLE {quoted} AS SELECT * FROM read_parquet(?)",
            [path],
        )
        count_df = self.query(f"SELECT COUNT(*) AS cnt FROM {quoted}")
        return int(count_df["cnt"][0])

    def load_dataframe(self, df: Any, table_name: str) -> None:
        """Register a DataFrame as a DuckDB table.

        Accepts polars or pandas DataFrames — DuckDB scans them via Arrow.
        """
        # DuckDB can scan Polars/Pandas DataFrames directly via Arrow
        self._conn.execute(
            f"CREATE OR REPLACE TABLE {_quote_ident(table_name)} AS SELECT * FROM df"
        )

    def list_tables(self) -> list[str]:
        """List all user tables in the database."""
        df = self.query(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema NOT IN ('information_schema', 'pg_catalog')"
        )
        return df["table_name"].to_list()

    def close(self) -> None:
        """Close the DuckDB connection."""
        self._conn.close()

    @property
    def connection(self) -> duckdb.DuckDBPyConnection:
        """Access the underlying DuckDB connection (for advanced use)."""
        return self._conn
