//! Table-in-out functions (`attributes`, `streams`): relation in, fanned table
//! out. Used instead of correlated table functions, which DuckDB rejects for
//! per-row column arguments.

mod attributes;
mod streams;

use std::collections::HashMap;

use arrow_schema::{DataType, Field, Schema};
use vgi::Worker;
use vgi_rpc::{Result, RpcError};

/// Register every table-in-out function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_table_in_out(attributes::Attributes);
    worker.register_table_in_out(streams::Streams);
}

/// A field carrying a `comment` (surfaced via `duckdb_columns().comment`).
pub(crate) fn commented(name: &str, dt: DataType, nullable: bool, comment: &str) -> Field {
    Field::new(name, dt, nullable).with_metadata(HashMap::from([(
        "comment".to_string(),
        comment.to_string(),
    )]))
}

/// Locate the `blob` BLOB column of an input relation (case-insensitive; falls
/// back to the first binary column).
pub(crate) fn find_blob_col(schema: &Schema) -> Result<usize> {
    if let Some(i) = schema
        .fields()
        .iter()
        .position(|f| f.name().eq_ignore_ascii_case("blob"))
    {
        return Ok(i);
    }
    schema
        .fields()
        .iter()
        .position(|f| matches!(f.data_type(), DataType::Binary | DataType::LargeBinary))
        .ok_or_else(|| {
            RpcError::value_error("input relation must carry a `blob` BLOB column of $MFT bytes")
        })
}

/// Locate the `entry` UBIGINT column of an input relation (case-insensitive;
/// falls back to the first integer column).
pub(crate) fn find_entry_col(schema: &Schema) -> Result<usize> {
    if let Some(i) = schema
        .fields()
        .iter()
        .position(|f| f.name().eq_ignore_ascii_case("entry"))
    {
        return Ok(i);
    }
    schema
        .fields()
        .iter()
        .position(|f| {
            matches!(
                f.data_type(),
                DataType::UInt64
                    | DataType::UInt32
                    | DataType::UInt16
                    | DataType::UInt8
                    | DataType::Int64
                    | DataType::Int32
                    | DataType::Int16
                    | DataType::Int8
            )
        })
        .ok_or_else(|| RpcError::value_error("input relation must carry an `entry` UBIGINT column"))
}
