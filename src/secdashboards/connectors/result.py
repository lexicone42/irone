"""Lightweight query result container — zero external dependencies.

QueryResult wraps ``list[dict]`` and exposes the subset of the polars
DataFrame API that the serverless tier actually uses (``len``,
``to_dicts``, ``head``, ``columns``, column access with chaining).
Heavy analytics libraries (polars, pyarrow, plotly …) are only needed
by the *investigation* optional‑extras group.
"""

from typing import Any


class ColumnAccessor:
    """Proxy returned by ``QueryResult["col"]``.

    Supports the same chaining patterns as a polars Series:
    ``qr["col"].drop_nulls().unique().to_list()``
    """

    __slots__ = ("_values",)

    def __init__(self, values: list[Any]) -> None:
        self._values = values

    # -- scalar / slice access ------------------------------------------------

    def __getitem__(self, index: int | slice) -> Any:
        return self._values[index]

    def __len__(self) -> int:
        return len(self._values)

    def __iter__(self):
        return iter(self._values)

    def __repr__(self) -> str:
        return f"ColumnAccessor({self._values!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ColumnAccessor):
            return self._values == other._values
        return NotImplemented

    # -- polars-compatible chain methods --------------------------------------

    def to_list(self) -> list[Any]:
        """Return the column values as a plain list."""
        return list(self._values)

    def drop_nulls(self) -> "ColumnAccessor":
        """Return a new accessor with ``None`` values removed."""
        return ColumnAccessor([v for v in self._values if v is not None])

    def unique(self) -> "ColumnAccessor":
        """Return a new accessor with duplicate values removed (order-preserving)."""
        seen: set[Any] = set()
        result: list[Any] = []
        for v in self._values:
            # unhashable values (dicts, lists) fall back to linear search
            try:
                if v not in seen:
                    seen.add(v)
                    result.append(v)
            except TypeError:
                if v not in result:
                    result.append(v)
        return ColumnAccessor(result)


class QueryResult:
    """Lightweight ``list[dict]`` wrapper with a polars-compatible read API.

    Parameters
    ----------
    columns:
        Ordered column names.  When *rows* is non-empty the caller
        **must** supply this — it defines both ordering and the
        universe of valid column names.
    rows:
        Row data as ``list[dict]``.  Keys that are not in *columns*
        are silently ignored; missing keys default to ``None``.
    """

    __slots__ = ("_columns", "_rows")

    def __init__(self, columns: list[str], rows: list[dict[str, Any]] | None = None) -> None:
        self._columns = list(columns)
        self._rows: list[dict[str, Any]] = rows if rows is not None else []

    # -- constructors ---------------------------------------------------------

    @classmethod
    def empty(cls) -> "QueryResult":
        """Return an empty result (no columns, no rows)."""
        return cls(columns=[], rows=[])

    @classmethod
    def from_dicts(cls, rows: list[dict[str, Any]]) -> "QueryResult":
        """Build a QueryResult from a list of dicts, inferring columns from keys."""
        if not rows:
            return cls.empty()
        # preserve insertion order from the first row, then add any extra keys
        seen: set[str] = set()
        columns: list[str] = []
        for row in rows:
            for k in row:
                if k not in seen:
                    seen.add(k)
                    columns.append(k)
        return cls(columns=columns, rows=rows)

    @classmethod
    def from_polars(cls, df: Any) -> "QueryResult":
        """Convert a polars DataFrame to a QueryResult."""
        return cls(columns=list(df.columns), rows=df.to_dicts())

    @classmethod
    def concat(cls, results: "list[QueryResult]") -> "QueryResult":
        """Concatenate multiple QueryResults (diagonal / outer join).

        All columns from all results are preserved.  Missing values
        become ``None`` — matching polars ``concat(how="diagonal")``.
        """
        if not results:
            return cls.empty()
        if len(results) == 1:
            return results[0]

        # build unified column list preserving order of first appearance
        seen: set[str] = set()
        all_columns: list[str] = []
        for qr in results:
            for c in qr._columns:
                if c not in seen:
                    seen.add(c)
                    all_columns.append(c)

        all_rows: list[dict[str, Any]] = []
        for qr in results:
            all_rows.extend(qr._rows)

        return cls(columns=all_columns, rows=all_rows)

    # -- read API (polars-compatible) -----------------------------------------

    @property
    def columns(self) -> list[str]:
        """Ordered column names."""
        return list(self._columns)

    def to_dicts(self) -> list[dict[str, Any]]:
        """Return rows as ``list[dict]``, each dict keyed by column name.

        Only keys present in ``self.columns`` are included, and missing
        keys default to ``None`` — so every dict has exactly the same
        keys in the same order.
        """
        cols = self._columns
        return [{c: row.get(c) for c in cols} for row in self._rows]

    def head(self, n: int = 5) -> "QueryResult":
        """Return a new QueryResult with at most *n* rows."""
        return QueryResult(columns=list(self._columns), rows=self._rows[:n])

    def is_empty(self) -> bool:
        """Return ``True`` when there are zero rows."""
        return len(self._rows) == 0

    def to_polars(self) -> Any:
        """Convert to a polars DataFrame (lazy import — investigation only)."""
        import polars as pl

        return pl.DataFrame(self.to_dicts())

    # -- column access --------------------------------------------------------

    def __getitem__(self, column: str) -> ColumnAccessor:
        if column not in self._columns:
            msg = f"column {column!r} not found; available: {self._columns}"
            raise KeyError(msg)
        return ColumnAccessor([row.get(column) for row in self._rows])

    def __contains__(self, column: str) -> bool:
        return column in self._columns

    # -- sizing ---------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._rows)

    # -- repr -----------------------------------------------------------------

    def __repr__(self) -> str:
        return f"QueryResult(columns={self._columns!r}, rows={len(self._rows)})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, QueryResult):
            return self._columns == other._columns and self._rows == other._rows
        return NotImplemented

    def __bool__(self) -> bool:
        """Truthy when non-empty — consistent with polars behaviour."""
        return len(self._rows) > 0
