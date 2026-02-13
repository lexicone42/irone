"""Tests for QueryResult — lightweight list[dict] wrapper."""

import pytest

from secdashboards.connectors.result import ColumnAccessor, QueryResult

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_COLUMNS = ["name", "age", "city"]
SAMPLE_ROWS = [
    {"name": "Alice", "age": 30, "city": "NYC"},
    {"name": "Bob", "age": 25, "city": "LA"},
    {"name": "Charlie", "age": 35, "city": "NYC"},
]


@pytest.fixture
def sample() -> QueryResult:
    return QueryResult(columns=SAMPLE_COLUMNS, rows=list(SAMPLE_ROWS))


@pytest.fixture
def empty_qr() -> QueryResult:
    return QueryResult.empty()


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_basic(self, sample: QueryResult):
        assert sample.columns == ["name", "age", "city"]
        assert len(sample) == 3

    def test_empty_constructor(self):
        qr = QueryResult(columns=["a", "b"], rows=[])
        assert qr.columns == ["a", "b"]
        assert len(qr) == 0

    def test_no_rows_arg(self):
        qr = QueryResult(columns=["x"])
        assert len(qr) == 0
        assert qr.columns == ["x"]

    def test_empty_class_method(self, empty_qr: QueryResult):
        assert empty_qr.columns == []
        assert len(empty_qr) == 0
        assert empty_qr.is_empty()

    def test_from_dicts(self):
        rows = [{"a": 1, "b": 2}, {"a": 3, "b": 4}]
        qr = QueryResult.from_dicts(rows)
        assert qr.columns == ["a", "b"]
        assert len(qr) == 2

    def test_from_dicts_empty(self):
        qr = QueryResult.from_dicts([])
        assert qr.columns == []
        assert len(qr) == 0

    def test_from_dicts_heterogeneous_keys(self):
        rows = [{"a": 1}, {"b": 2}, {"a": 3, "c": 4}]
        qr = QueryResult.from_dicts(rows)
        assert qr.columns == ["a", "b", "c"]
        # to_dicts normalizes — every row has all columns
        dicts = qr.to_dicts()
        assert dicts[0] == {"a": 1, "b": None, "c": None}
        assert dicts[1] == {"a": None, "b": 2, "c": None}
        assert dicts[2] == {"a": 3, "b": None, "c": 4}


# ---------------------------------------------------------------------------
# Read API
# ---------------------------------------------------------------------------


class TestReadAPI:
    def test_columns_returns_copy(self, sample: QueryResult):
        cols = sample.columns
        cols.append("extra")
        assert "extra" not in sample.columns

    def test_to_dicts(self, sample: QueryResult):
        dicts = sample.to_dicts()
        assert dicts == SAMPLE_ROWS
        # returns a new list — not the internal storage
        dicts.clear()
        assert len(sample.to_dicts()) == 3

    def test_to_dicts_normalizes_missing_keys(self):
        qr = QueryResult(columns=["a", "b"], rows=[{"a": 1}])
        assert qr.to_dicts() == [{"a": 1, "b": None}]

    def test_to_dicts_strips_extra_keys(self):
        qr = QueryResult(columns=["a"], rows=[{"a": 1, "extra": 99}])
        assert qr.to_dicts() == [{"a": 1}]

    def test_head_default(self, sample: QueryResult):
        h = sample.head()
        assert len(h) == 3  # only 3 rows, default n=5

    def test_head_n(self, sample: QueryResult):
        h = sample.head(2)
        assert len(h) == 2
        assert h.to_dicts() == SAMPLE_ROWS[:2]

    def test_head_n_larger_than_rows(self, sample: QueryResult):
        h = sample.head(100)
        assert len(h) == 3

    def test_head_preserves_columns(self, sample: QueryResult):
        h = sample.head(1)
        assert h.columns == sample.columns

    def test_is_empty_true(self, empty_qr: QueryResult):
        assert empty_qr.is_empty() is True

    def test_is_empty_false(self, sample: QueryResult):
        assert sample.is_empty() is False

    def test_len(self, sample: QueryResult):
        assert len(sample) == 3

    def test_len_empty(self, empty_qr: QueryResult):
        assert len(empty_qr) == 0


# ---------------------------------------------------------------------------
# Column access
# ---------------------------------------------------------------------------


class TestColumnAccess:
    def test_getitem(self, sample: QueryResult):
        col = sample["name"]
        assert isinstance(col, ColumnAccessor)
        assert col.to_list() == ["Alice", "Bob", "Charlie"]

    def test_getitem_missing_column(self, sample: QueryResult):
        with pytest.raises(KeyError, match="nonexistent"):
            sample["nonexistent"]

    def test_contains(self, sample: QueryResult):
        assert "name" in sample
        assert "missing" not in sample


# ---------------------------------------------------------------------------
# ColumnAccessor
# ---------------------------------------------------------------------------


class TestColumnAccessor:
    def test_to_list(self):
        ca = ColumnAccessor([1, 2, 3])
        assert ca.to_list() == [1, 2, 3]

    def test_to_list_returns_copy(self):
        ca = ColumnAccessor([1, 2, 3])
        lst = ca.to_list()
        lst.append(4)
        assert ca.to_list() == [1, 2, 3]

    def test_index_access(self):
        ca = ColumnAccessor(["a", "b", "c"])
        assert ca[0] == "a"
        assert ca[2] == "c"
        assert ca[-1] == "c"

    def test_index_out_of_range(self):
        ca = ColumnAccessor([1])
        with pytest.raises(IndexError):
            ca[5]

    def test_slice_access(self):
        ca = ColumnAccessor([1, 2, 3, 4, 5])
        assert ca[1:3] == [2, 3]

    def test_len(self):
        assert len(ColumnAccessor([1, 2, 3])) == 3
        assert len(ColumnAccessor([])) == 0

    def test_iter(self):
        ca = ColumnAccessor([10, 20, 30])
        assert list(ca) == [10, 20, 30]

    def test_drop_nulls(self):
        ca = ColumnAccessor([1, None, 3, None, 5])
        cleaned = ca.drop_nulls()
        assert cleaned.to_list() == [1, 3, 5]

    def test_drop_nulls_no_nulls(self):
        ca = ColumnAccessor([1, 2, 3])
        assert ca.drop_nulls().to_list() == [1, 2, 3]

    def test_drop_nulls_all_nulls(self):
        ca = ColumnAccessor([None, None])
        assert ca.drop_nulls().to_list() == []

    def test_unique(self):
        ca = ColumnAccessor([1, 2, 2, 3, 1])
        assert ca.unique().to_list() == [1, 2, 3]

    def test_unique_preserves_order(self):
        ca = ColumnAccessor(["c", "a", "b", "a", "c"])
        assert ca.unique().to_list() == ["c", "a", "b"]

    def test_unique_with_none(self):
        ca = ColumnAccessor([1, None, 2, None, 1])
        assert ca.unique().to_list() == [1, None, 2]

    def test_unique_unhashable(self):
        ca = ColumnAccessor([{"a": 1}, {"b": 2}, {"a": 1}])
        result = ca.unique().to_list()
        assert result == [{"a": 1}, {"b": 2}]

    def test_chaining_drop_nulls_unique_to_list(self):
        """The canonical polars chain: df[col].drop_nulls().unique().to_list()"""
        ca = ColumnAccessor(["NYC", None, "LA", "NYC", None, "LA", "SF"])
        result = ca.drop_nulls().unique().to_list()
        assert result == ["NYC", "LA", "SF"]

    def test_equality(self):
        assert ColumnAccessor([1, 2]) == ColumnAccessor([1, 2])
        assert ColumnAccessor([1, 2]) != ColumnAccessor([1, 3])

    def test_repr(self):
        ca = ColumnAccessor([1, 2])
        assert "ColumnAccessor" in repr(ca)


# ---------------------------------------------------------------------------
# concat
# ---------------------------------------------------------------------------


class TestConcat:
    def test_concat_same_columns(self):
        a = QueryResult(["x", "y"], [{"x": 1, "y": 2}])
        b = QueryResult(["x", "y"], [{"x": 3, "y": 4}])
        merged = QueryResult.concat([a, b])
        assert merged.columns == ["x", "y"]
        assert len(merged) == 2
        assert merged.to_dicts() == [{"x": 1, "y": 2}, {"x": 3, "y": 4}]

    def test_concat_diagonal(self):
        """Different columns → outer join, missing → None (like polars diagonal)."""
        a = QueryResult(["x"], [{"x": 1}])
        b = QueryResult(["y"], [{"y": 2}])
        merged = QueryResult.concat([a, b])
        assert merged.columns == ["x", "y"]
        dicts = merged.to_dicts()
        assert dicts[0] == {"x": 1, "y": None}
        assert dicts[1] == {"x": None, "y": 2}

    def test_concat_overlapping_columns(self):
        a = QueryResult(["x", "y"], [{"x": 1, "y": 2}])
        b = QueryResult(["y", "z"], [{"y": 3, "z": 4}])
        merged = QueryResult.concat([a, b])
        assert merged.columns == ["x", "y", "z"]
        dicts = merged.to_dicts()
        assert dicts[0] == {"x": 1, "y": 2, "z": None}
        assert dicts[1] == {"x": None, "y": 3, "z": 4}

    def test_concat_empty_list(self):
        merged = QueryResult.concat([])
        assert merged.is_empty()
        assert merged.columns == []

    def test_concat_single(self, sample: QueryResult):
        merged = QueryResult.concat([sample])
        assert merged is sample  # returns the same object

    def test_concat_with_empty_result(self):
        a = QueryResult(["x"], [{"x": 1}])
        b = QueryResult.empty()
        merged = QueryResult.concat([a, b])
        assert merged.columns == ["x"]
        assert len(merged) == 1


# ---------------------------------------------------------------------------
# from_polars / to_polars
# ---------------------------------------------------------------------------


class TestPolarsInterop:
    def test_from_polars(self):
        pl = pytest.importorskip("polars")
        df = pl.DataFrame({"a": [1, 2], "b": ["x", "y"]})
        qr = QueryResult.from_polars(df)
        assert qr.columns == ["a", "b"]
        assert len(qr) == 2
        assert qr["a"].to_list() == [1, 2]

    def test_to_polars(self):
        pl = pytest.importorskip("polars")
        qr = QueryResult(["a", "b"], [{"a": 1, "b": "x"}, {"a": 2, "b": "y"}])
        df = qr.to_polars()
        assert isinstance(df, pl.DataFrame)
        assert df.columns == ["a", "b"]
        assert len(df) == 2

    def test_roundtrip(self):
        pl = pytest.importorskip("polars")
        original = pl.DataFrame({"id": [1, 2, 3], "val": ["a", "b", "c"]})
        roundtripped = QueryResult.from_polars(original).to_polars()
        assert roundtripped.to_dicts() == original.to_dicts()


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_repr(self, sample: QueryResult):
        r = repr(sample)
        assert "QueryResult" in r
        assert "rows=3" in r

    def test_equality(self):
        a = QueryResult(["x"], [{"x": 1}])
        b = QueryResult(["x"], [{"x": 1}])
        assert a == b

    def test_inequality_different_rows(self):
        a = QueryResult(["x"], [{"x": 1}])
        b = QueryResult(["x"], [{"x": 2}])
        assert a != b

    def test_inequality_different_columns(self):
        a = QueryResult(["x"], [{"x": 1}])
        b = QueryResult(["y"], [{"y": 1}])
        assert a != b

    def test_bool_truthy(self, sample: QueryResult):
        assert bool(sample) is True

    def test_bool_falsy(self, empty_qr: QueryResult):
        assert bool(empty_qr) is False

    def test_column_with_none_values(self):
        qr = QueryResult(["x"], [{"x": None}, {"x": 1}, {"x": None}])
        assert qr["x"].to_list() == [None, 1, None]
        assert qr["x"].drop_nulls().to_list() == [1]

    def test_head_then_column_access(self, sample: QueryResult):
        """Chain head() then column access — common in rule.evaluate()."""
        result = sample.head(2)["name"].to_list()
        assert result == ["Alice", "Bob"]

    def test_to_dicts_then_slice(self, sample: QueryResult):
        """Pattern: df.to_dicts()[:10] (enrichment.py)."""
        sliced = sample.to_dicts()[:2]
        assert len(sliced) == 2

    def test_column_scalar_access(self):
        """Pattern: int(df["cnt"][0]) (athena.py)."""
        qr = QueryResult(["cnt"], [{"cnt": "42"}])
        assert int(qr["cnt"][0]) == 42

    def test_large_result(self):
        """Sanity check with larger dataset."""
        rows = [{"id": i, "val": f"row_{i}"} for i in range(10000)]
        qr = QueryResult(["id", "val"], rows)
        assert len(qr) == 10000
        assert qr.head(5)["id"].to_list() == [0, 1, 2, 3, 4]
        assert qr["id"][-1] == 9999
