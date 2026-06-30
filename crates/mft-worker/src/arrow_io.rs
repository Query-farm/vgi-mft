//! Small Arrow helpers shared across the scalar / table functions: reading BLOB
//! and unsigned-integer input cells, and building the microsecond `TIMESTAMP`
//! arrays the timeline schema uses.

use arrow_array::cast::AsArray;
use arrow_array::types::{
    Int16Type, Int32Type, Int64Type, Int8Type, UInt16Type, UInt32Type, UInt64Type, UInt8Type,
};
use arrow_array::{Array, ArrayRef};
use arrow_schema::DataType;
use vgi_rpc::{Result, RpcError};

/// Borrow the bytes of a BLOB cell at `row`, or `None` if null. Errors if the
/// column is not a binary type.
pub fn blob_val(col: &ArrayRef, row: usize) -> Result<Option<&[u8]>> {
    if col.is_null(row) {
        return Ok(None);
    }
    Ok(Some(match col.data_type() {
        DataType::Binary => col.as_binary::<i32>().value(row),
        DataType::LargeBinary => col.as_binary::<i64>().value(row),
        other => {
            return Err(RpcError::value_error(format!(
                "expected a BLOB (binary) argument, got {other:?}"
            )))
        }
    }))
}

/// Read element `row` of an integer column as `u64`, or `None` if null. Accepts
/// any of DuckDB's integer widths (a bare literal like `mft_record(b, 5)` is
/// typed as a signed integer; a negative value clamps to 0).
pub fn u64_val(col: &ArrayRef, row: usize) -> Result<Option<u64>> {
    if col.is_null(row) {
        return Ok(None);
    }
    let v = match col.data_type() {
        DataType::UInt64 => col.as_primitive::<UInt64Type>().value(row),
        DataType::UInt32 => col.as_primitive::<UInt32Type>().value(row) as u64,
        DataType::UInt16 => col.as_primitive::<UInt16Type>().value(row) as u64,
        DataType::UInt8 => col.as_primitive::<UInt8Type>().value(row) as u64,
        DataType::Int64 => col.as_primitive::<Int64Type>().value(row).max(0) as u64,
        DataType::Int32 => col.as_primitive::<Int32Type>().value(row).max(0) as u64,
        DataType::Int16 => col.as_primitive::<Int16Type>().value(row).max(0) as u64,
        DataType::Int8 => col.as_primitive::<Int8Type>().value(row).max(0) as u64,
        other => {
            return Err(RpcError::value_error(format!(
                "expected an integer (UBIGINT) argument, got {other:?}"
            )))
        }
    };
    Ok(Some(v))
}

/// A timestamp cell read back as `Option<i64>` **microseconds**, scaling from
/// whatever unit the column carries (used by the `timestomp` scalar, whose input
/// is a STRUCT of timestamps).
pub fn ts_micros(col: &ArrayRef, row: usize) -> Option<i64> {
    use arrow_array::types::{
        TimestampMicrosecondType, TimestampMillisecondType, TimestampNanosecondType,
        TimestampSecondType,
    };
    use arrow_schema::TimeUnit;
    if col.is_null(row) {
        return None;
    }
    match col.data_type() {
        DataType::Timestamp(TimeUnit::Second, _) => {
            Some(col.as_primitive::<TimestampSecondType>().value(row) * 1_000_000)
        }
        DataType::Timestamp(TimeUnit::Millisecond, _) => {
            Some(col.as_primitive::<TimestampMillisecondType>().value(row) * 1_000)
        }
        DataType::Timestamp(TimeUnit::Microsecond, _) => {
            Some(col.as_primitive::<TimestampMicrosecondType>().value(row))
        }
        DataType::Timestamp(TimeUnit::Nanosecond, _) => {
            Some(col.as_primitive::<TimestampNanosecondType>().value(row) / 1_000)
        }
        _ => None,
    }
}
