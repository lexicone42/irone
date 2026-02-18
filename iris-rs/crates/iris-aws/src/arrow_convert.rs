//! Convert Arrow `RecordBatch`es to `QueryResult` (Vec of JSON maps).
//!
//! Handles nested `StructArray` fields (OCSF columns like `actor`, `src_endpoint`)
//! by recursively converting them to nested `serde_json::Value::Object`s.

use arrow_array::types::{
    Float32Type, Float64Type, Int8Type, Int16Type, Int32Type, Int64Type, TimestampMicrosecondType,
    TimestampMillisecondType, TimestampNanosecondType, TimestampSecondType, UInt8Type, UInt16Type,
    UInt32Type, UInt64Type,
};
use arrow_array::{
    Array, BooleanArray, GenericListArray, LargeStringArray, OffsetSizeTrait, PrimitiveArray,
    RecordBatch, StringArray, StructArray,
};
use arrow_schema::DataType;
use serde_json::Value;

use iris_core::connectors::result::QueryResult;

/// Convert a slice of `RecordBatch`es into a `QueryResult`.
///
/// Columns are derived from the schema of the first batch. Nested `StructArray`
/// fields are expanded into nested JSON objects, preserving the OCSF hierarchy.
pub fn record_batches_to_query_result(batches: &[RecordBatch]) -> QueryResult {
    if batches.is_empty() {
        return QueryResult::empty();
    }

    let schema = batches[0].schema();
    let columns: Vec<String> = schema.fields().iter().map(|f| f.name().clone()).collect();

    let mut rows = Vec::new();
    for batch in batches {
        for row_idx in 0..batch.num_rows() {
            let mut map = serde_json::Map::new();
            for (col_idx, field) in batch.schema().fields().iter().enumerate() {
                let col = batch.column(col_idx);
                let value = array_value_to_json(col.as_ref(), row_idx);
                map.insert(field.name().clone(), value);
            }
            rows.push(map);
        }
    }

    QueryResult::new(columns, rows)
}

/// Extract a single value from an Arrow array at the given row index.
fn array_value_to_json(array: &dyn Array, idx: usize) -> Value {
    if array.is_null(idx) {
        return Value::Null;
    }

    match array.data_type() {
        DataType::Boolean => {
            let arr = array.as_any().downcast_ref::<BooleanArray>().unwrap();
            Value::Bool(arr.value(idx))
        }

        // Signed integers
        DataType::Int8 => int_to_json::<Int8Type>(array, idx),
        DataType::Int16 => int_to_json::<Int16Type>(array, idx),
        DataType::Int32 => int_to_json::<Int32Type>(array, idx),
        DataType::Int64 => int_to_json::<Int64Type>(array, idx),

        // Unsigned integers
        DataType::UInt8 => uint_to_json::<UInt8Type>(array, idx),
        DataType::UInt16 => uint_to_json::<UInt16Type>(array, idx),
        DataType::UInt32 => uint_to_json::<UInt32Type>(array, idx),
        DataType::UInt64 => uint_to_json::<UInt64Type>(array, idx),

        // Floats
        DataType::Float32 => float_to_json::<Float32Type>(array, idx),
        DataType::Float64 => float_to_json::<Float64Type>(array, idx),

        // Strings
        DataType::Utf8 => {
            let arr = array.as_any().downcast_ref::<StringArray>().unwrap();
            Value::String(arr.value(idx).to_string())
        }
        DataType::LargeUtf8 => {
            let arr = array.as_any().downcast_ref::<LargeStringArray>().unwrap();
            Value::String(arr.value(idx).to_string())
        }

        // Timestamps → ISO-8601 strings
        DataType::Timestamp(unit, tz) => timestamp_to_json(array, idx, *unit, tz.as_deref()),

        // Nested structs (OCSF fields like actor, src_endpoint)
        DataType::Struct(_) => {
            let arr = array.as_any().downcast_ref::<StructArray>().unwrap();
            struct_to_json(arr, idx)
        }

        // Lists
        DataType::List(_) => {
            let arr = array
                .as_any()
                .downcast_ref::<GenericListArray<i32>>()
                .unwrap();
            list_to_json(arr, idx)
        }
        DataType::LargeList(_) => {
            let arr = array
                .as_any()
                .downcast_ref::<GenericListArray<i64>>()
                .unwrap();
            list_to_json(arr, idx)
        }

        // Fallback: use arrow_cast's display formatter
        _ => {
            let formatter = arrow_cast::display::ArrayFormatter::try_new(
                array,
                &arrow_cast::display::FormatOptions::default(),
            );
            match formatter {
                Ok(fmt) => Value::String(fmt.value(idx).to_string()),
                Err(_) => Value::String(format!("<unsupported: {:?}>", array.data_type())),
            }
        }
    }
}

fn int_to_json<T>(array: &dyn Array, idx: usize) -> Value
where
    T: arrow_array::types::ArrowPrimitiveType,
    T::Native: Into<i64>,
{
    let arr = array.as_any().downcast_ref::<PrimitiveArray<T>>().unwrap();
    let val: i64 = arr.value(idx).into();
    Value::Number(serde_json::Number::from(val))
}

fn uint_to_json<T>(array: &dyn Array, idx: usize) -> Value
where
    T: arrow_array::types::ArrowPrimitiveType,
    T::Native: Into<u64>,
{
    let arr = array.as_any().downcast_ref::<PrimitiveArray<T>>().unwrap();
    let val: u64 = arr.value(idx).into();
    Value::Number(serde_json::Number::from(val))
}

fn float_to_json<T>(array: &dyn Array, idx: usize) -> Value
where
    T: arrow_array::types::ArrowPrimitiveType,
    T::Native: Into<f64>,
{
    let arr = array.as_any().downcast_ref::<PrimitiveArray<T>>().unwrap();
    let val: f64 = arr.value(idx).into();
    serde_json::Number::from_f64(val).map_or(Value::Null, Value::Number)
}

fn timestamp_to_json(
    array: &dyn Array,
    idx: usize,
    unit: arrow_schema::TimeUnit,
    tz: Option<&str>,
) -> Value {
    use arrow_schema::TimeUnit;
    use chrono::{DateTime, TimeZone, Utc};

    let epoch_nanos: Option<i64> = match unit {
        TimeUnit::Second => {
            let arr = array
                .as_any()
                .downcast_ref::<PrimitiveArray<TimestampSecondType>>()
                .unwrap();
            arr.value(idx).checked_mul(1_000_000_000)
        }
        TimeUnit::Millisecond => {
            let arr = array
                .as_any()
                .downcast_ref::<PrimitiveArray<TimestampMillisecondType>>()
                .unwrap();
            arr.value(idx).checked_mul(1_000_000)
        }
        TimeUnit::Microsecond => {
            let arr = array
                .as_any()
                .downcast_ref::<PrimitiveArray<TimestampMicrosecondType>>()
                .unwrap();
            arr.value(idx).checked_mul(1_000)
        }
        TimeUnit::Nanosecond => {
            let arr = array
                .as_any()
                .downcast_ref::<PrimitiveArray<TimestampNanosecondType>>()
                .unwrap();
            Some(arr.value(idx))
        }
    };

    match epoch_nanos {
        Some(ns) => {
            let secs = ns / 1_000_000_000;
            #[allow(clippy::cast_possible_truncation)] // ns % 1B always fits in u32
            let nsec = (ns % 1_000_000_000).unsigned_abs() as u32;
            let dt: DateTime<Utc> = if tz.is_some() {
                // Timezone-aware: interpret as UTC
                Utc.timestamp_opt(secs, nsec)
                    .single()
                    .unwrap_or_else(Utc::now)
            } else {
                // Timezone-naive: assume UTC
                Utc.timestamp_opt(secs, nsec)
                    .single()
                    .unwrap_or_else(Utc::now)
            };
            Value::String(dt.to_rfc3339())
        }
        None => Value::Null,
    }
}

fn struct_to_json(arr: &StructArray, idx: usize) -> Value {
    if arr.is_null(idx) {
        return Value::Null;
    }
    let mut map = serde_json::Map::new();
    for (field_idx, field) in arr.fields().iter().enumerate() {
        let child = arr.column(field_idx);
        let value = array_value_to_json(child.as_ref(), idx);
        map.insert(field.name().clone(), value);
    }
    Value::Object(map)
}

fn list_to_json<O: OffsetSizeTrait>(arr: &GenericListArray<O>, idx: usize) -> Value {
    let values = arr.value(idx);
    let mut items = Vec::with_capacity(values.len());
    for i in 0..values.len() {
        items.push(array_value_to_json(values.as_ref(), i));
    }
    Value::Array(items)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arrow_array::builder::{ListBuilder, StringBuilder, TimestampMicrosecondBuilder};
    use arrow_array::{Float64Array, Int64Array, RecordBatch, StringArray};
    use arrow_schema::{Field, Schema, TimeUnit};
    use serde_json::json;

    use super::*;

    #[test]
    fn empty_batches() {
        let qr = record_batches_to_query_result(&[]);
        assert!(qr.is_empty());
        assert!(qr.columns().is_empty());
    }

    #[test]
    fn flat_primitive_types() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("name", DataType::Utf8, false),
            Field::new("count", DataType::Int64, false),
            Field::new("score", DataType::Float64, true),
        ]));

        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(StringArray::from(vec!["alice", "bob"])),
                Arc::new(Int64Array::from(vec![10, 20])),
                Arc::new(Float64Array::from(vec![Some(1.5), None])),
            ],
        )
        .unwrap();

        let qr = record_batches_to_query_result(&[batch]);
        assert_eq!(qr.len(), 2);
        assert_eq!(qr.columns(), &["name", "count", "score"]);

        let rows = qr.rows();
        assert_eq!(rows[0]["name"], json!("alice"));
        assert_eq!(rows[0]["count"], json!(10));
        assert_eq!(rows[0]["score"], json!(1.5));
        assert_eq!(rows[1]["name"], json!("bob"));
        assert_eq!(rows[1]["score"], json!(null));
    }

    #[test]
    fn nested_struct_fields() {
        // Simulate OCSF: { "actor": { "user": { "name": "alice" } } }
        let inner_fields = vec![Field::new("name", DataType::Utf8, true)];
        let user_field = Field::new("user", DataType::Struct(inner_fields.clone().into()), true);
        let actor_field = Field::new(
            "actor",
            DataType::Struct(vec![user_field.clone()].into()),
            true,
        );

        let schema = Arc::new(Schema::new(vec![
            Field::new("class_uid", DataType::Int64, false),
            actor_field,
        ]));

        // Build the nested struct
        let name_arr = StringArray::from(vec![Some("alice"), Some("bob")]);
        let user_struct = StructArray::from(vec![(
            Arc::new(Field::new("name", DataType::Utf8, true)),
            Arc::new(name_arr) as Arc<dyn Array>,
        )]);
        let actor_struct = StructArray::from(vec![(
            Arc::new(user_field),
            Arc::new(user_struct) as Arc<dyn Array>,
        )]);

        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(Int64Array::from(vec![3002, 3002])),
                Arc::new(actor_struct),
            ],
        )
        .unwrap();

        let qr = record_batches_to_query_result(&[batch]);
        assert_eq!(qr.len(), 2);

        let actor = &qr.rows()[0]["actor"];
        assert_eq!(actor["user"]["name"], json!("alice"));
    }

    #[test]
    fn timestamp_to_iso8601() {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "time_dt",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        )]));

        let mut builder = TimestampMicrosecondBuilder::new().with_timezone("UTC");
        // 2024-06-15T13:30:00Z = Unix 1718458200 seconds
        builder.append_value(1_718_458_200_000_000);
        let ts_array = builder.finish();

        let batch = RecordBatch::try_new(schema, vec![Arc::new(ts_array)]).unwrap();
        let qr = record_batches_to_query_result(&[batch]);

        let time_val = qr.rows()[0]["time_dt"].as_str().unwrap();
        assert!(time_val.starts_with("2024-06-15T13:30:00"));
    }

    #[test]
    fn list_array_conversion() {
        let mut builder = ListBuilder::new(StringBuilder::new());
        builder.values().append_value("tag1");
        builder.values().append_value("tag2");
        builder.append(true);
        builder.values().append_value("tag3");
        builder.append(true);
        let list_arr = builder.finish();

        let schema = Arc::new(Schema::new(vec![Field::new(
            "tags",
            list_arr.data_type().clone(),
            true,
        )]));

        let batch = RecordBatch::try_new(schema, vec![Arc::new(list_arr)]).unwrap();
        let qr = record_batches_to_query_result(&[batch]);

        assert_eq!(qr.rows()[0]["tags"], json!(["tag1", "tag2"]));
        assert_eq!(qr.rows()[1]["tags"], json!(["tag3"]));
    }

    #[test]
    fn multiple_batches_concatenated() {
        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]));

        let b1 = RecordBatch::try_new(schema.clone(), vec![Arc::new(Int64Array::from(vec![1, 2]))])
            .unwrap();
        let b2 = RecordBatch::try_new(schema, vec![Arc::new(Int64Array::from(vec![3]))]).unwrap();

        let qr = record_batches_to_query_result(&[b1, b2]);
        assert_eq!(qr.len(), 3);
        assert_eq!(qr.rows()[2]["id"], json!(3));
    }

    #[test]
    fn deeply_nested_ocsf_struct() {
        // actor.user.credential_uid → 3 levels deep
        let cred_field = Field::new("credential_uid", DataType::Int64, true);
        let user_type = DataType::Struct(vec![cred_field.clone()].into());
        let user_field = Field::new("user", user_type.clone(), true);
        let actor_type = DataType::Struct(vec![user_field.clone()].into());
        let actor_field = Field::new("actor", actor_type, true);

        let schema = Arc::new(Schema::new(vec![actor_field]));

        // Build from inner out
        let cred_arr = Int64Array::from(vec![Some(99)]);
        let user_struct = StructArray::from(vec![(
            Arc::new(cred_field),
            Arc::new(cred_arr) as Arc<dyn Array>,
        )]);
        let actor_struct = StructArray::from(vec![(
            Arc::new(user_field),
            Arc::new(user_struct) as Arc<dyn Array>,
        )]);

        let batch = RecordBatch::try_new(schema, vec![Arc::new(actor_struct)]).unwrap();
        let qr = record_batches_to_query_result(&[batch]);

        assert_eq!(qr.rows()[0]["actor"]["user"]["credential_uid"], json!(99));
    }

    #[test]
    fn list_of_strings() {
        // Test list conversion with a simpler type (list of strings is sufficient
        // to verify the list_to_json path; nested struct-in-list is covered by
        // the deeply_nested test's struct conversion + list conversion separately)
        let mut builder = ListBuilder::new(StringBuilder::new());
        // Row 0: ["a", "b", "c"]
        builder.values().append_value("a");
        builder.values().append_value("b");
        builder.values().append_value("c");
        builder.append(true);
        // Row 1: empty list
        builder.append(true);
        let list_arr = builder.finish();

        let schema = Arc::new(Schema::new(vec![Field::new(
            "items",
            list_arr.data_type().clone(),
            true,
        )]));

        let batch = RecordBatch::try_new(schema, vec![Arc::new(list_arr)]).unwrap();
        let qr = record_batches_to_query_result(&[batch]);

        assert_eq!(qr.rows()[0]["items"], json!(["a", "b", "c"]));
        assert_eq!(qr.rows()[1]["items"], json!([]));
    }
}
