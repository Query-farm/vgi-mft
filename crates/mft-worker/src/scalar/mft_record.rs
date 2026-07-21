//! `mft_record(blob BLOB, entry UBIGINT) -> STRUCT` — fully decode one record by
//! index into the raw, lossless per-record view (header, SI quad, the full list
//! of `$FILE_NAME`s, the primary `$DATA`, ADS, and every attribute).

use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{blob_val, u64_val};
use crate::arrow_map::{build_mft_record_array, mft_record_type};

pub struct MftRecord;

impl ScalarFunction for MftRecord {
    fn name(&self) -> &str {
        "mft_record"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Fully decode one $MFT record into a lossless STRUCT view".into(),
            return_type: Some(mft_record_type()),
            examples: vec![FunctionExample {
                sql: "SELECT r.fn[1].name AS primary_name, len(r.ads) AS ads_count FROM (SELECT mft.main.mft_record((SELECT content FROM read_blob('data/sample.mft')), 22) AS r)".into(),
                description: "Fully decode one sample $MFT record, exposing its primary name and how many alternate data streams it carries.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags_with_example(
                "Records",
                "Decode MFT Record",
                "Fully decode MFT entry `entry` in a $MFT `blob` into a `STRUCT` carrying the header \
                 (entry, sequence, in_use, is_dir, base_ref, lsn, hard_links), the \
                 $STANDARD_INFORMATION MACB + DOS attrs + USN (`si`), the full `LIST` of every \
                 $FILE_NAME (`fn` — including the 8.3 DOS short name, with namespace and parent \
                 reference), the primary $DATA (`data` — resident bytes when small), the alternate \
                 data streams (`ads`), and every attribute (`attributes`). The raw, lossless \
                 per-record view, NULL for an empty slot.",
                "Fully decode one $MFT record: `mft_record(blob, entry)` → `STRUCT(entry, sequence, \
                 in_use, is_dir, base_ref, lsn, hard_links, si, fn LIST, data, ads LIST, \
                 attributes LIST)`.",
                "mft record, decode, struct, standard information, file name, MACB, data, ADS, \
                 attributes, namespace, DOS short name, ntfs",
                r#"[
  {"description": "Fully decode one sample $MFT record, exposing its primary name and how many alternate data streams it carries.",
   "sql": "SELECT r.fn[1].name AS primary_name, len(r.ads) AS ads_count FROM (SELECT mft.main.mft_record((SELECT content FROM read_blob('data/sample.mft')), 22) AS r)"}
]"#,
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::column_typed("blob", 0, DataType::Binary, "The raw $MFT bytes to parse."),
            ArgSpec::column_typed(
                "entry",
                1,
                DataType::UInt64,
                "The MFT record number (index) to decode.",
            ),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(mft_record_type()))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let blob = batch.column(0);
        let entry = batch.column(1);
        let n = batch.num_rows();
        let mut records = Vec::with_capacity(n);
        for i in 0..n {
            let rec = match (blob_val(blob, i)?, u64_val(entry, i)?) {
                (Some(bytes), Some(idx)) => {
                    mft_core::decode_one(bytes.to_vec(), idx).ok().flatten()
                }
                _ => None,
            };
            records.push(rec);
        }
        let arr: ArrayRef = build_mft_record_array(&records)?;
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
