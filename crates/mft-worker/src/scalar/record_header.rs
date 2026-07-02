//! `record_header(blob BLOB, entry UBIGINT) -> STRUCT` — a cheap header-only
//! probe (validity scan, `$LogFile` LSN correlation) without decoding attributes.

use std::sync::Arc;

use arrow_array::builder::{
    BooleanBuilder, StringBuilder, UInt16Builder, UInt32Builder, UInt64Builder,
};
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
        Field::new("signature", DataType::Utf8, true),
        Field::new("sequence", DataType::UInt16, true),
        Field::new("in_use", DataType::Boolean, true),
        Field::new("is_dir", DataType::Boolean, true),
        Field::new("base_ref", DataType::UInt64, true),
        Field::new("lsn", DataType::UInt64, true),
        Field::new("used_size", DataType::UInt32, true),
        Field::new("allocated_size", DataType::UInt32, true),
    ])
}

pub struct RecordHeaderFn;

impl ScalarFunction for RecordHeaderFn {
    fn name(&self) -> &str {
        "record_header"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Probe one $MFT record's FILE header without decoding attributes".into(),
            return_type: Some(DataType::Struct(fields())),
            examples: vec![FunctionExample {
                sql: "SELECT mft.main.record_header((SELECT content FROM read_blob('data/sample.mft')), 12);".into(),
                description: "Probe the FILE header of MFT entry 12.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags_with_example(
                "Records",
                "MFT Record Header",
                "Decode just the FILE-record header of MFT entry `entry` in a $MFT `blob`: the \
                 signature ('FILE'/'BAAD'), sequence number, IN_USE and DIRECTORY flags, base \
                 record reference, $LogFile sequence number (LSN), and used/allocated record \
                 sizes. A cheap validity / LSN-correlation probe that does not decode attributes.",
                "Probe an $MFT record's FILE header (signature, sequence, in_use, is_dir, base_ref, \
                 lsn, sizes) without decoding attributes: `record_header(blob, entry)`.",
                "record header, FILE header, signature, sequence, in_use, is_dir, LSN, base \
                 reference, mft, ntfs, probe",
                "SELECT mft.main.record_header((SELECT content FROM read_blob('data/sample.mft')), 12);",
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
                "The MFT record number (index) to probe.",
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

        let mut signature = StringBuilder::new();
        let mut sequence = UInt16Builder::with_capacity(n);
        let mut in_use = BooleanBuilder::with_capacity(n);
        let mut is_dir = BooleanBuilder::with_capacity(n);
        let mut base_ref = UInt64Builder::with_capacity(n);
        let mut lsn = UInt64Builder::with_capacity(n);
        let mut used = UInt32Builder::with_capacity(n);
        let mut alloc = UInt32Builder::with_capacity(n);
        let mut validity: Vec<bool> = Vec::with_capacity(n);

        for i in 0..n {
            let hdr = match (blob_val(blob, i)?, u64_val(entry, i)?) {
                (Some(bytes), Some(idx)) => mft_core::record_header(bytes.to_vec(), idx),
                _ => None,
            };
            match hdr {
                Some(h) => {
                    signature.append_value(&h.signature);
                    sequence.append_value(h.sequence);
                    in_use.append_value(h.in_use);
                    is_dir.append_value(h.is_dir);
                    base_ref.append_value(h.base_ref);
                    lsn.append_value(h.lsn);
                    used.append_value(h.used_size);
                    alloc.append_value(h.allocated_size);
                    validity.push(true);
                }
                None => {
                    signature.append_null();
                    sequence.append_null();
                    in_use.append_null();
                    is_dir.append_null();
                    base_ref.append_null();
                    lsn.append_null();
                    used.append_null();
                    alloc.append_null();
                    validity.push(false);
                }
            }
        }

        let st = StructArray::new(
            fields(),
            vec![
                Arc::new(signature.finish()),
                Arc::new(sequence.finish()),
                Arc::new(in_use.finish()),
                Arc::new(is_dir.finish()),
                Arc::new(base_ref.finish()),
                Arc::new(lsn.finish()),
                Arc::new(used.finish()),
                Arc::new(alloc.finish()),
            ],
            Some(validity.into()),
        );
        let arr: ArrayRef = Arc::new(st);
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
