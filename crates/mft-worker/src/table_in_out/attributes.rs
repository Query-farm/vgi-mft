//! `attributes((FROM rel)) -> TABLE(entry, attribute_id, type_id, type_name,
//! resident, name, logical_size, physical_size, flags)` — fan every attribute of
//! each `(blob, entry)` row of the input relation into one output row (the
//! `mft_dump`-style deep view).
//!
//! Because DuckDB table functions reject correlated column arguments, this is a
//! table-in-out function: pass a relation carrying a `blob` BLOB column and an
//! `entry` UBIGINT column, e.g.
//! `FROM mft.attributes((FROM (SELECT my_blob AS blob, 0 AS entry)))`.

use std::sync::Arc;

use arrow_array::builder::{
    BooleanBuilder, StringBuilder, UInt16Builder, UInt32Builder, UInt64Builder,
};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Schema, SchemaRef};
use vgi::table_in_out::TableInOutFunction;
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams};
use vgi_rpc::{Result, RpcError};

use crate::table_in_out::{commented, find_blob_col, find_entry_col};

pub struct Attributes;

fn output_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        commented(
            "entry",
            DataType::UInt64,
            false,
            "MFT record number this attribute belongs to.",
        ),
        commented(
            "attribute_id",
            DataType::UInt16,
            true,
            "The attribute instance id within the record.",
        ),
        commented(
            "type_id",
            DataType::UInt32,
            true,
            "NTFS attribute type code (e.g. 0x10, 0x30, 0x80).",
        ),
        commented(
            "type_name",
            DataType::Utf8,
            true,
            "Canonical attribute name (e.g. $STANDARD_INFORMATION, $FILE_NAME, $DATA).",
        ),
        commented(
            "resident",
            DataType::Boolean,
            true,
            "Whether the attribute value is stored inside the record (resident).",
        ),
        commented(
            "name",
            DataType::Utf8,
            true,
            "The attribute name (e.g. an ADS name); NULL when unnamed.",
        ),
        commented(
            "logical_size",
            DataType::UInt64,
            true,
            "The attribute's logical (data) size in bytes.",
        ),
        commented(
            "physical_size",
            DataType::UInt64,
            true,
            "The attribute's allocated/on-disk size in bytes.",
        ),
        commented(
            "flags",
            DataType::UInt32,
            true,
            "Attribute data flags (compressed/encrypted/sparse bits).",
        ),
    ]))
}

impl TableInOutFunction for Attributes {
    fn name(&self) -> &str {
        "attributes"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Attributes & Streams",
            "MFT Attributes (LATERAL)",
            "Fan every attribute of each ($MFT blob, entry) row of the input relation into one \
             output row: attribute_id, type_id, type_name (e.g. $STANDARD_INFORMATION, \
             $FILE_NAME, $DATA), resident flag, name (an ADS name when present), logical/physical \
             size, and flags. The mft_dump-style deep per-attribute view. Pass a relation with a \
             `blob` column of $MFT bytes and an `entry` column of record indexes (DuckDB table \
             functions cannot take correlated column args, so the relation form is used).",
            "Fan every attribute of each `(blob, entry)` input row into one output row — columns \
             `entry`, `attribute_id`, `type_id`, `type_name` (e.g. `$STANDARD_INFORMATION`, \
             `$FILE_NAME`, `$DATA`), `resident`, `name` (an ADS name when present), `logical_size`, \
             `physical_size`, and `flags`. Pass a relation carrying a `blob` column of $MFT bytes \
             and an `entry` column of record numbers; the `ntfs_attribute_types` view maps each \
             `type_id` to its meaning. See the example queries for ready-to-run SQL.",
            "attributes, mft attributes, attribute list, type_id, resident, non-resident, deep \
             view, mft_dump, ntfs, lateral",
        );
        tags.push((
            "vgi.result_columns_schema".into(),
            crate::meta::result_columns_schema_json(&output_schema()),
        ));
        tags.push((
            "vgi.example_queries".into(),
            "SELECT entry, type_name, resident, name, logical_size\n\
             FROM mft.main.attributes((FROM (SELECT content AS blob, 22::UBIGINT AS entry\n\
             FROM read_blob('data/sample.mft'))));"
                .into(),
        ));
        // A guaranteed-runnable, verified example over the committed sample $MFT
        // (run from the repo root, where data/ lives). Entry 22 carries
        // $STANDARD_INFORMATION + two $FILE_NAME + a primary $DATA + an ADS $DATA.
        tags.push((
            "vgi.executable_examples".into(),
            r#"[
  {"description": "List every attribute (type, residency, ADS name, size) of one sample $MFT record.",
   "sql": "SELECT type_name, resident, name, logical_size FROM mft.main.attributes((FROM (SELECT content AS blob, 22::UBIGINT AS entry FROM read_blob('data/sample.mft')))) ORDER BY attribute_id"}
]"#
            .into(),
        ));
        FunctionMetadata {
            description: "Fan each MFT record's attributes into rows (relation in/out)".into(),
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
            .ok_or_else(|| RpcError::value_error("attributes: requires an input relation"))?;
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
        let mut attr_id = UInt16Builder::new();
        let mut type_id = UInt32Builder::new();
        let mut type_name = StringBuilder::new();
        let mut resident = BooleanBuilder::new();
        let mut name = StringBuilder::new();
        let mut logical = UInt64Builder::new();
        let mut physical = UInt64Builder::new();
        let mut flags = UInt32Builder::new();

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
            for a in &rec.attributes {
                entry_b.append_value(rec.entry);
                attr_id.append_value(a.attribute_id);
                type_id.append_value(a.type_id);
                type_name.append_value(&a.type_name);
                resident.append_value(a.resident);
                name.append_option(a.name.as_deref());
                logical.append_value(a.logical_size);
                physical.append_value(a.physical_size);
                flags.append_value(u32::from(a.flags));
            }
        }

        let columns: Vec<ArrayRef> = vec![
            Arc::new(entry_b.finish()),
            Arc::new(attr_id.finish()),
            Arc::new(type_id.finish()),
            Arc::new(type_name.finish()),
            Arc::new(resident.finish()),
            Arc::new(name.finish()),
            Arc::new(logical.finish()),
            Arc::new(physical.finish()),
            Arc::new(flags.finish()),
        ];
        Ok(vec![RecordBatch::try_new(
            params.output_schema.clone(),
            columns,
        )
        .map_err(|e| RpcError::runtime_error(e.to_string()))?])
    }
}
