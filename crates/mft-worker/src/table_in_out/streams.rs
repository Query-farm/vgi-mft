//! `streams((FROM rel)) -> TABLE(entry, name, logical_size, physical_size,
//! resident, data)` — fan every `$DATA` stream (primary + each ADS) of each
//! `(blob, entry)` row of the input relation into one output row.
//!
//! Table-in-out (relation in/out), like [`super::attributes`]: pass a relation
//! with a `blob` BLOB column and an `entry` UBIGINT column.

use std::sync::Arc;

use arrow_array::builder::{BinaryBuilder, BooleanBuilder, StringBuilder, UInt64Builder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Schema, SchemaRef};
use vgi::table_in_out::TableInOutFunction;
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams};
use vgi_rpc::{Result, RpcError};

use crate::table_in_out::{commented, find_blob_col, find_entry_col};

pub struct Streams;

fn output_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        commented(
            "entry",
            DataType::UInt64,
            false,
            "MFT record number this $DATA stream belongs to.",
        ),
        commented(
            "name",
            DataType::Utf8,
            true,
            "Stream name: NULL for the primary unnamed $DATA, set for an ADS.",
        ),
        commented(
            "logical_size",
            DataType::UInt64,
            true,
            "The stream's logical (data) size in bytes.",
        ),
        commented(
            "physical_size",
            DataType::UInt64,
            true,
            "The stream's allocated/on-disk size in bytes.",
        ),
        commented(
            "resident",
            DataType::Boolean,
            true,
            "Whether the stream's bytes are stored inside the record (resident).",
        ),
        commented(
            "data",
            DataType::Binary,
            true,
            "The resident stream bytes when resident; NULL when non-resident.",
        ),
    ]))
}

impl TableInOutFunction for Streams {
    fn name(&self) -> &str {
        "streams"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Attributes & Streams",
            "MFT $DATA Streams (LATERAL)",
            "Fan every $DATA stream of each ($MFT blob, entry) row of the input relation into one \
             output row: the unnamed primary stream (name NULL) plus each alternate data stream \
             (ADS, name set). Columns: entry, name, logical_size, physical_size, resident, and \
             data (the resident bytes when the stream is resident, else NULL). ADS are a classic \
             malware hiding spot. Pass a relation with a `blob` column of $MFT bytes and an \
             `entry` column of record indexes (DuckDB table functions cannot take correlated \
             column args).",
            "Fan every $DATA stream (the unnamed primary stream plus each alternate data stream) of \
             each `(blob, entry)` input row into one output row — columns `entry`, `name` (NULL for \
             the primary stream, set for an ADS), `logical_size`, `physical_size`, `resident`, and \
             `data` (the resident bytes when the stream is resident, else NULL). Alternate data \
             streams are a classic malware hiding spot. Pass a relation carrying a `blob` column of \
             $MFT bytes and an `entry` column of record numbers.",
            "streams, $DATA, alternate data stream, ADS, resident, malware hiding, mft, ntfs, \
             lateral",
        );
        tags.push((
            "vgi.result_columns_schema".into(),
            crate::meta::result_columns_schema_json(&output_schema()),
        ));
        tags.push((
            "vgi.example_queries".into(),
            r#"[
  {"description": "List the $DATA streams (primary + each ADS) of one sample $MFT record.",
   "sql": "SELECT entry, name, logical_size, resident FROM mft.main.streams((FROM (SELECT content AS blob, 22::UBIGINT AS entry FROM read_blob('data/sample.mft'))))"}
]"#
                .into(),
        ));
        // A guaranteed-runnable, verified example over the committed sample $MFT
        // (run from the repo root, where data/ lives). Entry 22 has a primary
        // $DATA stream plus one alternate data stream named 'hidden'.
        tags.push((
            "vgi.executable_examples".into(),
            r#"[
  {"description": "List the $DATA streams of one sample $MFT record, surfacing the hidden ADS by name.",
   "sql": "SELECT name, logical_size, resident FROM mft.main.streams((FROM (SELECT content AS blob, 22::UBIGINT AS entry FROM read_blob('data/sample.mft')))) ORDER BY name NULLS FIRST"}
]"#
            .into(),
        ));
        FunctionMetadata {
            description: "Fan each MFT record's $DATA streams into rows (relation in/out)".into(),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::column(
            "relation",
            0,
            "table",
            "A relation carrying a `blob` column of $MFT bytes and an `entry` column of record \
             indexes to expand.",
        )]
    }

    fn on_bind(&self, params: &BindParams) -> Result<BindResponse> {
        let input = params
            .input_schema
            .clone()
            .ok_or_else(|| RpcError::value_error("streams: requires an input relation"))?;
        find_blob_col(&input)?;
        find_entry_col(&input)?;
        Ok(BindResponse {
            output_schema: output_schema(),
            opaque_data: Vec::new(),
        })
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<Vec<RecordBatch>> {
        let bi = find_blob_col(&batch.schema())?;
        let ei = find_entry_col(&batch.schema())?;
        let blob = batch.column(bi);
        let entry = batch.column(ei);

        let mut entry_b = UInt64Builder::new();
        let mut name = StringBuilder::new();
        let mut logical = UInt64Builder::new();
        let mut physical = UInt64Builder::new();
        let mut resident = BooleanBuilder::new();
        let mut data = BinaryBuilder::new();

        for i in 0..batch.num_rows() {
            let (Some(bytes), Some(idx)) = (
                crate::arrow_io::blob_val(blob, i)?,
                crate::arrow_io::u64_val(entry, i)?,
            ) else {
                continue;
            };
            let Ok(Some(rec)) = mft_core::decode_one(bytes.to_vec(), idx) else {
                continue;
            };
            for s in rec.data.iter() {
                entry_b.append_value(rec.entry);
                name.append_option(s.name.as_deref());
                logical.append_value(s.logical_size);
                physical.append_value(s.physical_size);
                resident.append_value(s.resident);
                match &s.data {
                    Some(b) => data.append_value(b),
                    None => data.append_null(),
                }
            }
        }

        let columns: Vec<ArrayRef> = vec![
            Arc::new(entry_b.finish()),
            Arc::new(name.finish()),
            Arc::new(logical.finish()),
            Arc::new(physical.finish()),
            Arc::new(resident.finish()),
            Arc::new(data.finish()),
        ];
        Ok(vec![RecordBatch::try_new(
            params.output_schema.clone(),
            columns,
        )
        .map_err(|e| RpcError::runtime_error(e.to_string()))?])
    }
}
