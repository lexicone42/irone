use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A single column's values extracted from a [`QueryResult`].
///
/// Supports chaining: `qr.column("ip")?.drop_nulls().unique().to_vec()`
#[derive(Debug, Clone, PartialEq)]
pub struct ColumnAccessor {
    values: Vec<Value>,
}

impl ColumnAccessor {
    #[must_use]
    pub fn new(values: Vec<Value>) -> Self {
        Self { values }
    }

    /// Return the values as a plain `Vec<Value>`.
    #[must_use]
    pub fn to_vec(&self) -> Vec<Value> {
        self.values.clone()
    }

    /// Number of values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether there are no values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Return a new accessor with null values removed.
    #[must_use]
    pub fn drop_nulls(&self) -> Self {
        Self {
            values: self
                .values
                .iter()
                .filter(|v| !v.is_null())
                .cloned()
                .collect(),
        }
    }

    /// Return a new accessor with duplicate values removed (order-preserving).
    #[must_use]
    pub fn unique(&self) -> Self {
        let mut seen = HashSet::new();
        let mut result = Vec::new();
        for v in &self.values {
            // Use the JSON string repr as the hash key for consistency
            let key = v.to_string();
            if seen.insert(key) {
                result.push(v.clone());
            }
        }
        Self { values: result }
    }

    /// Get a value by index.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&Value> {
        self.values.get(index)
    }

    /// Iterate over the values.
    pub fn iter(&self) -> impl Iterator<Item = &Value> {
        self.values.iter()
    }
}

impl IntoIterator for ColumnAccessor {
    type Item = Value;
    type IntoIter = std::vec::IntoIter<Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}

/// Lightweight row-oriented query result container.
///
/// Wraps `Vec<serde_json::Map>` with ordered column metadata.
/// This is the Rust equivalent of the Python `QueryResult(list[dict])`.
///
/// All connector and consumer APIs use this type — no heavy analytics
/// dependencies needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    columns: Vec<String>,
    rows: Vec<serde_json::Map<String, Value>>,
}

impl QueryResult {
    /// Create a new `QueryResult` with explicit columns and rows.
    pub fn new(columns: Vec<String>, rows: Vec<serde_json::Map<String, Value>>) -> Self {
        Self { columns, rows }
    }

    /// Return an empty result (no columns, no rows).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            columns: Vec::new(),
            rows: Vec::new(),
        }
    }

    /// Build a `QueryResult` from a list of JSON maps, inferring columns
    /// from all keys (order-preserving, first-appearance).
    pub fn from_maps(rows: Vec<serde_json::Map<String, Value>>) -> Self {
        if rows.is_empty() {
            return Self::empty();
        }
        let mut seen = HashSet::new();
        let mut columns = Vec::new();
        for row in &rows {
            for key in row.keys() {
                if seen.insert(key.clone()) {
                    columns.push(key.clone());
                }
            }
        }
        Self { columns, rows }
    }

    /// Build a `QueryResult` from a `Vec<HashMap<String, Value>>`.
    pub fn from_hash_maps(rows: Vec<std::collections::HashMap<String, Value>>) -> Self {
        let maps: Vec<serde_json::Map<String, Value>> = rows
            .into_iter()
            .map(|hm| hm.into_iter().collect())
            .collect();
        Self::from_maps(maps)
    }

    /// Concatenate multiple `QueryResult`s (diagonal / outer join).
    ///
    /// All columns from all results are preserved. Missing values
    /// become `null` — matching polars `concat(how="diagonal")`.
    pub fn concat(results: Vec<Self>) -> Self {
        if results.is_empty() {
            return Self::empty();
        }
        if results.len() == 1 {
            return results.into_iter().next().unwrap();
        }

        let mut seen = HashSet::new();
        let mut all_columns = Vec::new();
        for qr in &results {
            for c in &qr.columns {
                if seen.insert(c.clone()) {
                    all_columns.push(c.clone());
                }
            }
        }

        let mut all_rows = Vec::new();
        for qr in results {
            all_rows.extend(qr.rows);
        }

        Self {
            columns: all_columns,
            rows: all_rows,
        }
    }

    /// Ordered column names.
    #[must_use]
    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    /// Return rows as `Vec<Map>`, each map keyed by column name.
    ///
    /// Only keys present in `self.columns` are included, and missing
    /// keys default to `null`.
    #[must_use]
    pub fn to_maps(&self) -> Vec<serde_json::Map<String, Value>> {
        self.rows
            .iter()
            .map(|row| {
                let mut m = serde_json::Map::new();
                for c in &self.columns {
                    m.insert(c.clone(), row.get(c).cloned().unwrap_or(Value::Null));
                }
                m
            })
            .collect()
    }

    /// Return the first `n` rows as a new `QueryResult`.
    #[must_use]
    pub fn head(&self, n: usize) -> Self {
        Self {
            columns: self.columns.clone(),
            rows: self.rows.iter().take(n).cloned().collect(),
        }
    }

    /// Whether there are zero rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Number of rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Access a single column by name.
    ///
    /// # Errors
    /// Returns `Err` if the column does not exist.
    pub fn column(&self, name: &str) -> Result<ColumnAccessor, QueryResultError> {
        if !self.columns.contains(&name.to_string()) {
            return Err(QueryResultError::ColumnNotFound {
                column: name.to_string(),
                available: self.columns.clone(),
            });
        }
        let values = self
            .rows
            .iter()
            .map(|row| row.get(name).cloned().unwrap_or(Value::Null))
            .collect();
        Ok(ColumnAccessor::new(values))
    }

    /// Check if a column name exists.
    #[must_use]
    pub fn contains_column(&self, name: &str) -> bool {
        self.columns.iter().any(|c| c == name)
    }

    /// Access the raw rows.
    #[must_use]
    pub fn rows(&self) -> &[serde_json::Map<String, Value>] {
        &self.rows
    }
}

impl PartialEq for QueryResult {
    fn eq(&self, other: &Self) -> bool {
        self.columns == other.columns && self.rows == other.rows
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QueryResultError {
    #[error("column {column:?} not found; available: {available:?}")]
    ColumnNotFound {
        column: String,
        available: Vec<String>,
    },
}

/// Helper: create a `serde_json::Map` from key-value pairs.
#[macro_export]
macro_rules! json_row {
    ($($key:expr => $val:expr),* $(,)?) => {{
        let mut map = serde_json::Map::new();
        $(map.insert($key.to_string(), serde_json::json!($val));)*
        map
    }};
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn sample_rows() -> Vec<serde_json::Map<String, Value>> {
        vec![
            json_row!("name" => "alice", "age" => 30),
            json_row!("name" => "bob", "age" => 25),
            json_row!("name" => "charlie", "age" => 35),
        ]
    }

    #[test]
    fn empty_result() {
        let qr = QueryResult::empty();
        assert!(qr.is_empty());
        assert_eq!(qr.len(), 0);
        assert!(qr.columns().is_empty());
    }

    #[test]
    fn from_maps_infers_columns() {
        let qr = QueryResult::from_maps(sample_rows());
        assert_eq!(qr.len(), 3);
        assert!(qr.columns().contains(&"name".to_string()));
        assert!(qr.columns().contains(&"age".to_string()));
    }

    #[test]
    fn from_maps_empty_input() {
        let qr = QueryResult::from_maps(vec![]);
        assert!(qr.is_empty());
        assert!(qr.columns().is_empty());
    }

    #[test]
    fn column_access() {
        let qr = QueryResult::from_maps(sample_rows());
        let names = qr.column("name").unwrap();
        assert_eq!(names.len(), 3);
        assert_eq!(names.get(0), Some(&json!("alice")));
    }

    #[test]
    fn column_not_found() {
        let qr = QueryResult::from_maps(sample_rows());
        let err = qr.column("missing").unwrap_err();
        assert!(matches!(err, QueryResultError::ColumnNotFound { .. }));
    }

    #[test]
    fn contains_column() {
        let qr = QueryResult::from_maps(sample_rows());
        assert!(qr.contains_column("name"));
        assert!(!qr.contains_column("missing"));
    }

    #[test]
    fn head() {
        let qr = QueryResult::from_maps(sample_rows());
        let head = qr.head(2);
        assert_eq!(head.len(), 2);
        assert_eq!(head.columns(), qr.columns());
    }

    #[test]
    fn head_exceeding_len() {
        let qr = QueryResult::from_maps(sample_rows());
        let head = qr.head(100);
        assert_eq!(head.len(), 3);
    }

    #[test]
    fn to_maps_normalizes_columns() {
        let rows = vec![json_row!("a" => 1), json_row!("a" => 2, "b" => 3)];
        let qr = QueryResult::from_maps(rows);
        let maps = qr.to_maps();
        // Second row should have "a" and "b", first row should have "b" as null
        assert_eq!(maps[0].get("b"), Some(&Value::Null));
        assert_eq!(maps[1].get("b"), Some(&json!(3)));
    }

    #[test]
    fn concat_empty() {
        let qr = QueryResult::concat(vec![]);
        assert!(qr.is_empty());
    }

    #[test]
    fn concat_single() {
        let qr = QueryResult::from_maps(sample_rows());
        let concat = QueryResult::concat(vec![qr.clone()]);
        assert_eq!(concat, qr);
    }

    #[test]
    fn concat_multiple() {
        let qr1 = QueryResult::new(vec!["a".into()], vec![json_row!("a" => 1)]);
        let qr2 = QueryResult::new(
            vec!["a".into(), "b".into()],
            vec![json_row!("a" => 2, "b" => 3)],
        );
        let concat = QueryResult::concat(vec![qr1, qr2]);
        assert_eq!(concat.len(), 2);
        assert_eq!(concat.columns().len(), 2);
        assert!(concat.contains_column("a"));
        assert!(concat.contains_column("b"));
    }

    #[test]
    fn equality() {
        let qr1 = QueryResult::from_maps(sample_rows());
        let qr2 = QueryResult::from_maps(sample_rows());
        assert_eq!(qr1, qr2);
    }

    #[test]
    fn column_accessor_drop_nulls() {
        let acc = ColumnAccessor::new(vec![json!(1), Value::Null, json!(3)]);
        let filtered = acc.drop_nulls();
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered.to_vec(), vec![json!(1), json!(3)]);
    }

    #[test]
    fn column_accessor_unique() {
        let acc = ColumnAccessor::new(vec![json!("a"), json!("b"), json!("a"), json!("c")]);
        let unique = acc.unique();
        assert_eq!(unique.len(), 3);
        assert_eq!(unique.to_vec(), vec![json!("a"), json!("b"), json!("c")]);
    }

    #[test]
    fn column_accessor_chaining() {
        let acc = ColumnAccessor::new(vec![
            json!("x"),
            Value::Null,
            json!("x"),
            json!("y"),
            Value::Null,
        ]);
        let result = acc.drop_nulls().unique().to_vec();
        assert_eq!(result, vec![json!("x"), json!("y")]);
    }

    #[test]
    fn column_accessor_into_iter() {
        let acc = ColumnAccessor::new(vec![json!(1), json!(2)]);
        let collected: Vec<Value> = acc.into_iter().collect();
        assert_eq!(collected, vec![json!(1), json!(2)]);
    }

    #[test]
    fn json_row_macro() {
        let row = json_row!("x" => 1, "y" => "hello");
        assert_eq!(row.get("x"), Some(&json!(1)));
        assert_eq!(row.get("y"), Some(&json!("hello")));
    }

    #[test]
    fn from_hash_maps() {
        let mut hm = std::collections::HashMap::new();
        hm.insert("key".to_string(), json!("val"));
        let qr = QueryResult::from_hash_maps(vec![hm]);
        assert_eq!(qr.len(), 1);
        assert!(qr.contains_column("key"));
    }

    #[test]
    fn serde_roundtrip() {
        let qr = QueryResult::from_maps(sample_rows());
        let json_str = serde_json::to_string(&qr).unwrap();
        let deserialized: QueryResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(qr, deserialized);
    }
}
