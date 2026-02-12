"""DuckDB connector for local and Lambda SQL queries."""

from __future__ import annotations

import time

import duckdb
import polars as pl

from secdashboards.catalog.models import DataSource
from secdashboards.connectors.base import DataConnector, HealthCheckResult


def _quote_ident(name: str) -> str:
    """Quote a SQL identifier by escaping embedded double-quotes."""
    return '"' + name.replace('"', '""') + '"'


class DuckDBConnector(DataConnector):
    """Connector for DuckDB — local/in-memory SQL engine.

    Reads ``db_path`` from ``source.connector_config`` (defaults to ``:memory:``).
    Supports loading Polars DataFrames, Parquet files (including S3 via httpfs),
    and standard SQL queries with native Polars/Arrow return.
    """

    def __init__(self, source: DataSource) -> None:
        super().__init__(source)
        db_path = source.connector_config.get("db_path", ":memory:")
        self._conn = duckdb.connect(db_path)

    def query(self, sql: str) -> pl.DataFrame:
        """Execute a SQL query and return results as a Polars DataFrame."""
        result = self._conn.execute(sql)
        return result.pl()

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
            df = self._conn.execute(sql, [self.source.database, self.source.table]).pl()
        elif self.source.table:
            sql = """
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = ?
            """
            df = self._conn.execute(sql, [self.source.table]).pl()
        else:
            sql = """
            SELECT table_name || '.' || column_name AS column_name, data_type
            FROM information_schema.columns
            """
            df = self._conn.execute(sql).pl()

        if df.is_empty():
            return {}
        columns = df["column_name"].to_list()
        types = df["data_type"].to_list()
        return dict(zip(columns, types, strict=True))

    def check_health(self) -> HealthCheckResult:
        """Check if the DuckDB connection is healthy."""
        start_time = time.time()
        try:
            tables_df = self._conn.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema NOT IN ('information_schema', 'pg_catalog')"
            ).pl()
            table_count = len(tables_df)

            total_rows = 0
            for table_name in tables_df["table_name"].to_list():
                count_df = self._conn.execute(
                    f"SELECT COUNT(*) AS cnt FROM {_quote_ident(table_name)}"
                ).pl()
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
        count_df = self._conn.execute(f"SELECT COUNT(*) AS cnt FROM {quoted}").pl()
        return int(count_df["cnt"][0])

    def load_dataframe(self, df: pl.DataFrame, table_name: str) -> None:
        """Register a Polars DataFrame as a DuckDB table."""
        # DuckDB can scan Polars DataFrames directly via Arrow
        self._conn.execute(
            f"CREATE OR REPLACE TABLE {_quote_ident(table_name)} AS SELECT * FROM df"
        )

    def list_tables(self) -> list[str]:
        """List all user tables in the database."""
        df = self._conn.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema NOT IN ('information_schema', 'pg_catalog')"
        ).pl()
        return df["table_name"].to_list()

    def close(self) -> None:
        """Close the DuckDB connection."""
        self._conn.close()

    @property
    def connection(self) -> duckdb.DuckDBPyConnection:
        """Access the underlying DuckDB connection (for advanced use)."""
        return self._conn
