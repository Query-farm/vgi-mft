//! `mft_version() -> VARCHAR` — the worker version string.

use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

pub struct MftVersion;

impl ScalarFunction for MftVersion {
    fn name(&self) -> &str {
        "mft_version"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Return the running mft worker version string".into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT mft.main.mft_version();".into(),
                description: "Return the running worker version string.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags_with_example(
                "Diagnostics",
                "MFT Worker Version",
                "Return the version string of the running mft worker — useful to record which \
                 build parsed an evidence set in a chain-of-custody note.",
                "Return the worker version string, e.g. `mft_version()`.",
                "mft version, worker version, build, version string, provenance",
                "SELECT mft.main.mft_version();",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        Vec::new()
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let rows = batch.num_rows().max(1);
        let mut b = StringBuilder::new();
        for _ in 0..rows {
            b.append_value(crate::version());
        }
        let arr: ArrayRef = Arc::new(b.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
