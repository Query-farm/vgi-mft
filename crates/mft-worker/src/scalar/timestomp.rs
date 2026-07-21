//! `timestomp(si STRUCT, fn STRUCT) -> STRUCT(suspect BOOL, reasons LIST<VARCHAR>)`
//! — the SI-vs-FN heuristic (§A.6) as a pure scalar. Composable over the §B
//! columns or any pair of MACB timestamp quads.

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, StringBuilder};
use arrow_array::cast::AsArray;
use arrow_array::{ArrayRef, ListArray, RecordBatch, StructArray};
use arrow_buffer::OffsetBuffer;
use arrow_schema::{DataType, Field, Fields, TimeUnit};
use mft_core::{timestomp, Macb};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::ts_micros;

/// The STRUCT(created, modified, accessed, mft_modified) the function accepts for
/// each of `si` and `fn`.
fn quad_fields() -> Fields {
    let ts = || DataType::Timestamp(TimeUnit::Microsecond, None);
    Fields::from(vec![
        Field::new("created", ts(), true),
        Field::new("modified", ts(), true),
        Field::new("accessed", ts(), true),
        Field::new("mft_modified", ts(), true),
    ])
}

/// The returned `STRUCT(suspect BOOLEAN, reasons LIST<VARCHAR>)`.
fn result_fields() -> Fields {
    Fields::from(vec![
        Field::new("suspect", DataType::Boolean, false),
        Field::new(
            "reasons",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            false,
        ),
    ])
}

/// Read a MACB quad from a STRUCT column at `row` (children read by name, so
/// field order is tolerated; missing fields → NULL).
fn read_quad(col: &ArrayRef, row: usize) -> Macb {
    let Some(st) = col.as_struct_opt() else {
        return Macb::default();
    };
    let get = |name: &str| st.column_by_name(name).and_then(|c| ts_micros(c, row));
    Macb {
        created: get("created"),
        modified: get("modified"),
        accessed: get("accessed"),
        mft_modified: get("mft_modified"),
    }
}

pub struct Timestomp;

impl ScalarFunction for Timestomp {
    fn name(&self) -> &str {
        "timestomp"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Score the SI-vs-FN timestomp heuristic over two MACB quads".into(),
            return_type: Some(DataType::Struct(result_fields())),
            examples: vec![FunctionExample {
                sql: "SELECT mft.main.timestomp({'created': TIMESTAMP '2009-01-01', 'modified': TIMESTAMP '2009-01-01', 'accessed': TIMESTAMP '2009-01-01', 'mft_modified': TIMESTAMP '2009-01-01'}, {'created': TIMESTAMP '2020-01-01', 'modified': TIMESTAMP '2020-01-01', 'accessed': TIMESTAMP '2020-01-01', 'mft_modified': TIMESTAMP '2020-01-01'}).suspect AS suspect".into(),
                description: "Flag a record whose $STANDARD_INFORMATION quad predates its $FILE_NAME quad — the naturally-impossible ordering timestomping produces.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags_with_example(
                "Anti-Forensics",
                "Timestomp Heuristic",
                "Score the anti-forensic SI-vs-FN timestamp heuristic over a $STANDARD_INFORMATION \
                 MACB quad `si` and a $FILE_NAME MACB quad `fn` (each a `STRUCT(created, modified, \
                 accessed, mft_modified)` of `TIMESTAMP`). Returns `STRUCT(suspect BOOLEAN, reasons \
                 LIST<VARCHAR>)`; reasons ⊆ {si-before-fn, si-creation-before-fn-creation, \
                 zero-subsecond, fn-newer-than-si, all-four-equal}. SI is user-writable (tools like \
                 timestomp edit it) while FN is kernel-only, so SI earlier than FN — naturally \
                 impossible — and whole-second SI values are strong tells. Composable over the \
                 read_mft si_* / fn_* columns.",
                "Score the SI-vs-FN timestomp heuristic: `timestomp(si, fn)` → `STRUCT(suspect, \
                 reasons)`. reasons ⊆ {si-before-fn, si-creation-before-fn-creation, zero-subsecond, \
                 fn-newer-than-si, all-four-equal}.",
                "timestomp, anti-forensic, timestamp manipulation, SI, FN, standard information, \
                 file name, MACB, divergence, zero subsecond, dfir",
                r#"[
  {"description": "Flag a record whose $STANDARD_INFORMATION quad predates its $FILE_NAME quad — the naturally-impossible ordering timestomping produces.",
   "sql": "SELECT mft.main.timestomp({'created': TIMESTAMP '2009-01-01', 'modified': TIMESTAMP '2009-01-01', 'accessed': TIMESTAMP '2009-01-01', 'mft_modified': TIMESTAMP '2009-01-01'}, {'created': TIMESTAMP '2020-01-01', 'modified': TIMESTAMP '2020-01-01', 'accessed': TIMESTAMP '2020-01-01', 'mft_modified': TIMESTAMP '2020-01-01'}).suspect AS suspect"}
]"#,
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::column_typed(
                "si",
                0,
                DataType::Struct(quad_fields()),
                "The $STANDARD_INFORMATION MACB quad — its created / modified / accessed / \
                 mft_modified fields (e.g. built from the read_mft si_* columns).",
            ),
            ArgSpec::column_typed(
                "fn",
                1,
                DataType::Struct(quad_fields()),
                "The $FILE_NAME MACB quad — its created / modified / accessed / mft_modified \
                 fields (e.g. built from the read_mft fn_* columns).",
            ),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(result_fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let si_col = batch.column(0);
        let fn_col = batch.column(1);
        let n = batch.num_rows();

        let mut suspect = BooleanBuilder::with_capacity(n);
        let mut reasons = StringBuilder::new();
        let mut offsets: Vec<i32> = vec![0];
        let mut count: i32 = 0;

        for i in 0..n {
            let si = read_quad(si_col, i);
            let fna = read_quad(fn_col, i);
            let t = timestomp(&si, &fna);
            suspect.append_value(t.suspect);
            for r in &t.reasons {
                reasons.append_value(r.as_str());
                count += 1;
            }
            offsets.push(count);
        }

        let reasons_values: ArrayRef = Arc::new(reasons.finish());
        let reasons_list = ListArray::new(
            Arc::new(Field::new("item", DataType::Utf8, true)),
            OffsetBuffer::new(offsets.into()),
            reasons_values,
            None,
        );

        let st = StructArray::new(
            result_fields(),
            vec![Arc::new(suspect.finish()), Arc::new(reasons_list)],
            None,
        );
        let arr: ArrayRef = Arc::new(st);
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
