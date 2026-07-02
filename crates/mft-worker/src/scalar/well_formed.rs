//! `well_formed(blob BLOB, entry UBIGINT) -> STRUCT(ok, error, kind)` — validate
//! one record. Never panics: a corrupt / hostile record returns `ok=false` with
//! the matching `kind`.

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_schema::{DataType, Field, Fields};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{blob_val, u64_val};

fn fields() -> Fields {
    Fields::from(vec![
        Field::new("ok", DataType::Boolean, true),
        Field::new("error", DataType::Utf8, true),
        Field::new("kind", DataType::Utf8, true),
    ])
}

pub struct WellFormedFn;

impl ScalarFunction for WellFormedFn {
    fn name(&self) -> &str {
        "well_formed"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Validate one $MFT record; never panics on corrupt input".into(),
            return_type: Some(DataType::Struct(fields())),
            examples: vec![FunctionExample {
                sql: "SELECT mft.main.well_formed((SELECT content FROM read_blob('data/sample.mft')), 20);".into(),
                description: "Validate MFT entry 20.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags_with_example(
                "Records",
                "MFT Record Well-Formed Check",
                "Validate MFT entry `entry` in a $MFT `blob`, returning a STRUCT(ok BOOLEAN, error \
                 VARCHAR, kind VARCHAR). `kind` is one of ok, baad, fixup-mismatch, bad-signature, \
                 attr-overrun, truncated, not-an-mft. Never panics — a corrupt or hostile record \
                 returns ok=false with the matching kind, so a validity scan over a whole $MFT is \
                 safe.",
                "Validate an $MFT record: `well_formed(blob, entry)` → STRUCT(ok, error, kind) with \
                 kind ∈ {ok, baad, fixup-mismatch, bad-signature, attr-overrun, truncated, \
                 not-an-mft}.",
                "well formed, validate, corrupt, baad, fixup, mismatch, bad signature, truncated, \
                 mft, ntfs, integrity",
                "SELECT mft.main.well_formed((SELECT content FROM read_blob('data/sample.mft')), 20);",
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
                "The MFT record number (index) to validate.",
            ),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let blob = batch.column(0);
        let entry = batch.column(1);
        let n = batch.num_rows();

        let mut ok = BooleanBuilder::with_capacity(n);
        let mut error = StringBuilder::new();
        let mut kind = StringBuilder::new();
        let mut validity: Vec<bool> = Vec::with_capacity(n);

        for i in 0..n {
            match (blob_val(blob, i)?, u64_val(entry, i)?) {
                (Some(bytes), Some(idx)) => {
                    let wf = mft_core::well_formed(bytes.to_vec(), idx);
                    ok.append_value(wf.ok);
                    error.append_option(wf.error.as_deref());
                    kind.append_value(wf.kind.as_str());
                    validity.push(true);
                }
                _ => {
                    ok.append_null();
                    error.append_null();
                    kind.append_null();
                    validity.push(false);
                }
            }
        }

        let st = StructArray::new(
            fields(),
            vec![
                Arc::new(ok.finish()),
                Arc::new(error.finish()),
                Arc::new(kind.finish()),
            ],
            Some(validity.into()),
        );
        let arr: ArrayRef = Arc::new(st);
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
