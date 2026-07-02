//! `full_path(blob BLOB, entry UBIGINT) -> VARCHAR` — resolve a single entry's
//! reconstructed path over the resolver built from the blob. `\$Orphan\…` on a
//! missing / stale parent, `\$Cycle\…` on a loop.

use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{blob_val, u64_val};

/// A cheap content fingerprint (length + sampled bytes) to detect a repeated
/// blob across batch rows without an O(n) compare.
fn fingerprint(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.len().hash(&mut h);
    let take = bytes.len().min(64);
    bytes[..take].hash(&mut h);
    if bytes.len() > 64 {
        bytes[bytes.len() - 64..].hash(&mut h);
        let mid = bytes.len() / 2;
        bytes[mid..(mid + 64).min(bytes.len())].hash(&mut h);
    }
    h.finish()
}

pub struct FullPath;

impl ScalarFunction for FullPath {
    fn name(&self) -> &str {
        "full_path"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Reconstruct one $MFT entry's full path from parent references".into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT mft.main.full_path((SELECT content FROM read_blob('data/sample.mft')), 20);".into(),
                description: "Reconstruct the path of MFT entry 20.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags_with_example(
                "Records",
                "Reconstruct MFT Path",
                "Reconstruct the full filesystem path of MFT entry `entry` in a $MFT `blob` by \
                 walking parent references up to the volume root. Returns `\\$Orphan\\…` when a \
                 parent is missing or its slot was reused, and `\\$Cycle\\…` when a corrupt parent \
                 loop is detected (the walk is depth- and cycle-bounded, never spins). NULL when \
                 the entry has no name record.",
                "Reconstruct an $MFT entry's full path from parent references: \
                 `full_path(blob, entry)`; `\\$Orphan\\…` / `\\$Cycle\\…` when unresolved.",
                "full path, path reconstruction, parent reference, directory, orphan, cycle, mft, \
                 ntfs, filesystem path",
                "SELECT mft.main.full_path((SELECT content FROM read_blob('data/sample.mft')), 20);",
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
                "The MFT record number (index) whose path to reconstruct.",
            ),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let blob = batch.column(0);
        let entry = batch.column(1);
        let n = batch.num_rows();
        let mut out = StringBuilder::new();

        // Cache the resolver for the most-recent blob, keyed on a cheap content
        // fingerprint — the common call passes one literal blob and a varying
        // entry, so the resolver is built once for the whole batch.
        let mut cache: Option<(u64, std::collections::BTreeMap<u64, mft_core::ResolverNode>)> =
            None;

        for i in 0..n {
            match (blob_val(blob, i)?, u64_val(entry, i)?) {
                (Some(bytes), Some(idx)) => {
                    let fp = fingerprint(bytes);
                    if !matches!(&cache, Some((k, _)) if *k == fp) {
                        let mut dec = match mft_core::Decoder::new(bytes.to_vec()) {
                            Ok(d) => d,
                            Err(_) => {
                                out.append_null();
                                continue;
                            }
                        };
                        let mut resolver = std::collections::BTreeMap::new();
                        dec.build_resolver(&mut resolver);
                        cache = Some((fp, resolver));
                    }
                    let resolver = &cache.as_ref().expect("cache populated").1;
                    if resolver.contains_key(&idx) {
                        let r = mft_core::resolve_path(resolver, idx, mft_core::DEFAULT_MAX_DEPTH);
                        out.append_value(r.path);
                    } else {
                        out.append_null();
                    }
                }
                _ => out.append_null(),
            }
        }

        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
