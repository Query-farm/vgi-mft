//! `read_mft(glob_or_blob, host := NULL, mode := 'files') -> TABLE` — the
//! headline: parse a collected `$MFT` into the §B forensic timeline, one row per
//! FILE record (allocated and deleted-but-resident), with both MACB quads, the
//! reconstructed path, ADS, and resident data.
//!
//! Streams a multi-GB `$MFT` across DuckDB batches, threading the §C
//! serde-serializable byte-offset cursor + parent-resolver index as scan state
//! (`encode_resume` / `restore_resume`), so HTTP rehydration is lossless and a
//! child seen in a late batch still resolves against an early parent.

use std::collections::BTreeMap;

use arrow_array::RecordBatch;
use arrow_schema::SchemaRef;
use mft_core::{resolve_path, DecodedRecord, Decoder, MftCursor, MftScanState, ResolverNode};
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::arrow_map::{build_timeline_batch, timeline_schema, EmitRow};
use crate::options::{self, Mode, Source};

/// Rows emitted per `next_batch`.
const BATCH_ROWS: usize = 2048;

pub struct ReadMft;

impl TableFunction for ReadMft {
    fn name(&self) -> &str {
        "read_mft"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Read $MFT Forensic Timeline",
            "Parse a collected NTFS $MFT (Master File Table) into a full forensic filesystem \
             timeline — one row per FILE record, with the path reconstructed from parent \
             references, both the $STANDARD_INFORMATION and $FILE_NAME MACB timestamp quads (so \
             the SI-vs-FN timestomp mismatch is a plain WHERE clause), logical/physical sizes, \
             allocated/deleted and file/dir flags, alternate data streams, and resident file \
             content. The first argument is a VARCHAR path or glob ('/cases/*/$MFT', 's3://…') or \
             a BLOB of $MFT bytes. `host :=` scopes a collection (defaults to the source \
             filename); `mode :=` is 'files' (one row per record, the default), 'streams' (one row \
             per $DATA stream — primary + each ADS), or 'allocated' (live files only). Deleted but \
             still-resident records are included by default — filter with WHERE is_allocated for \
             live files only.",
            "Parse a collected NTFS `$MFT` into a forensic timeline: one row per FILE record with \
             reconstructed `full_path`, the SI + FN MACB quads, sizes, deleted/dir flags, ADS, and \
             resident data. `read_mft(path_or_blob, host := …, mode := 'files'|'streams'|\
             'allocated')`.",
            "mft, $MFT, ntfs, master file table, dfir, forensics, timeline, windows, filesystem, \
             timestomp, MACB, deleted files, alternate data stream, ADS, path reconstruction, \
             incident response, threat hunt",
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "One row per FILE record (allocated **and** deleted-but-resident). Key columns: \
             `entry` (UBIGINT), `sequence` (USMALLINT), `parent_entry`, `full_path`, `file_name`, \
             `is_dir`, `is_allocated`, `is_deleted`, the SI quad `si_created`/`si_modified`/\
             `si_accessed`/`si_mft_modified` and the FN quad `fn_created`/`fn_modified`/\
             `fn_accessed`/`fn_mft_modified` (all TIMESTAMP), `logical_size`, `physical_size`, \
             `hard_link_count`, `dos_attributes`, `ads_name`, `resident_data` (BLOB), \
             `is_timestomp_suspect` (BOOLEAN), and `diagnostics`."
                .into(),
        ));
        tags.push((
            "vgi.example_queries".into(),
            "SELECT entry, full_path, is_deleted FROM mft.main.read_mft('data/sample.mft');\n\
             SELECT full_path FROM mft.main.read_mft('data/sample.mft') WHERE is_timestomp_suspect;\n\
             SELECT ads_name FROM mft.main.read_mft('data/sample.mft', mode := 'streams') WHERE \
             ads_name IS NOT NULL;"
                .into(),
        ));
        // A guaranteed-runnable, verified example over the committed sample $MFT
        // (run from the repo root, where data/ lives).
        tags.push((
            "vgi.executable_examples".into(),
            r#"[
  {"description": "Count the FILE records in the sample $MFT timeline.",
   "sql": "SELECT count(*) AS records FROM mft.main.read_mft('data/sample.mft')"},
  {"description": "Hunt the sample $MFT for timestomped records.",
   "sql": "SELECT full_path FROM mft.main.read_mft('data/sample.mft') WHERE is_timestomp_suspect ORDER BY full_path"}
]"#
            .into(),
        ));
        FunctionMetadata {
            description: "Parse a collected NTFS $MFT into a forensic filesystem timeline".into(),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::const_arg(
                "glob_or_blob",
                0,
                "any",
                "The $MFT source: a VARCHAR path or glob (e.g. '/cases/IR-2026/host01/$MFT', \
                 '/cases/*/$MFT'), or a BLOB of $MFT bytes (e.g. from_hex(...) or a collected dump \
                 read into a literal). A glob scans matching files in sorted order.",
            ),
            ArgSpec::const_arg(
                "host",
                -1,
                "varchar",
                "Collection scope: supply the source host id so paths and parents do not collide \
                 across hosts, and to populate the `host` column. When omitted it defaults to the \
                 source filename (or NULL for an inline BLOB).",
            ),
            ArgSpec::const_arg(
                "mode",
                -1,
                "varchar",
                "Emission mode: 'files' (one row per record using the primary stream, the \
                 default), 'streams' (one row per $DATA stream — primary + each ADS, each \
                 independently joinable), or 'allocated' (live/undeleted files only).",
            ),
        ]
    }

    fn on_bind(&self, params: &BindParams) -> Result<BindResponse> {
        // Validate args eagerly so a bad mode / missing file fails at bind.
        let _ = options::mode(&params.arguments)?;
        let _ = options::source(&params.arguments)?;
        Ok(BindResponse {
            output_schema: timeline_schema(),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        let mode = options::mode(&params.arguments)?;
        let source = options::source(&params.arguments)?;
        let host = options::host(&params.arguments);
        let files = match source {
            Source::Files(f) => f,
            Source::Blob(bytes) => {
                return Ok(Box::new(ReadMftProducer::new_blob(
                    params.output_schema.clone(),
                    bytes,
                    host,
                    mode,
                )))
            }
        };
        Ok(Box::new(ReadMftProducer::new_files(
            params.output_schema.clone(),
            files,
            host,
            mode,
        )))
    }
}

/// A single source: a named file path, or an inline blob.
enum SourceRef {
    File(String),
    Blob(Vec<u8>),
}

impl SourceRef {
    fn label(&self) -> String {
        match self {
            SourceRef::File(p) => p.clone(),
            SourceRef::Blob(_) => "<blob>".to_string(),
        }
    }
    fn load(&self) -> Result<Vec<u8>> {
        match self {
            SourceRef::File(p) => {
                std::fs::read(p).map_err(|e| RpcError::value_error(format!("read {p}: {e}")))
            }
            SourceRef::Blob(b) => Ok(b.clone()),
        }
    }
}

/// The streaming producer: decodes one batch of records per `next_batch`,
/// advancing across sources, threading the §C cursor + resolver.
pub struct ReadMftProducer {
    schema: SchemaRef,
    sources: Vec<SourceRef>,
    host: Option<String>,
    mode: Mode,
    /// Index of the source currently being read.
    source_idx: usize,
    /// The decoder for the current source (built on first touch).
    decoder: Option<Decoder>,
    /// The parent-resolver index for the current source (carried in scan state).
    resolver: BTreeMap<u64, ResolverNode>,
    /// Next entry index within the current source.
    entry_cursor: u64,
    /// Total records emitted so far.
    records_emitted: u64,
    /// A scan state to restore on the next batch (HTTP rehydration).
    pending_resume: Option<MftScanState>,
}

impl ReadMftProducer {
    fn new_files(schema: SchemaRef, files: Vec<String>, host: Option<String>, mode: Mode) -> Self {
        ReadMftProducer {
            schema,
            sources: files.into_iter().map(SourceRef::File).collect(),
            host,
            mode,
            source_idx: 0,
            decoder: None,
            resolver: BTreeMap::new(),
            entry_cursor: 0,
            records_emitted: 0,
            pending_resume: None,
        }
    }

    fn new_blob(schema: SchemaRef, bytes: Vec<u8>, host: Option<String>, mode: Mode) -> Self {
        ReadMftProducer {
            schema,
            sources: vec![SourceRef::Blob(bytes)],
            host,
            mode,
            source_idx: 0,
            decoder: None,
            resolver: BTreeMap::new(),
            entry_cursor: 0,
            records_emitted: 0,
            pending_resume: None,
        }
    }

    /// The host label for the current source (explicit arg, else the filename).
    fn host_label(&self) -> Option<String> {
        if self.host.is_some() {
            return self.host.clone();
        }
        match self.sources.get(self.source_idx) {
            Some(SourceRef::File(p)) => Some(p.clone()),
            _ => None,
        }
    }

    /// Ensure a decoder + resolver for the current source. Returns `false` when
    /// all sources are exhausted.
    fn ensure_open(&mut self) -> Result<bool> {
        if self.decoder.is_some() {
            return Ok(true);
        }
        if self.source_idx >= self.sources.len() {
            return Ok(false);
        }
        let bytes = self.sources[self.source_idx].load()?;
        let mut dec =
            Decoder::new(bytes).map_err(|e| RpcError::value_error(format!("parse $MFT: {e}")))?;
        // Only (re)build the resolver if it was not carried in from a resume.
        if self.resolver.is_empty() {
            dec.build_resolver(&mut self.resolver);
        }
        self.decoder = Some(dec);
        Ok(true)
    }

    /// Advance to the next source, dropping per-source state.
    fn advance_source(&mut self) {
        self.decoder = None;
        self.resolver.clear();
        self.entry_cursor = 0;
        self.source_idx += 1;
    }

    /// Fan one decoded record into emitted rows per `mode`.
    fn emit(&self, rec: &DecodedRecord, rows: &mut Vec<EmitRow>) {
        if self.mode == Mode::Allocated && !rec.in_use {
            return;
        }
        let resolved = resolve_path(&self.resolver, rec.entry, mft_core::DEFAULT_MAX_DEPTH);
        // Merge the record's own diagnostics with any path diagnostic.
        let mut diags: Vec<String> = rec.diagnostics.clone();
        if let Some(d) = resolved.diagnostic {
            diags.push(d.to_string());
        }
        let diagnostics = if diags.is_empty() {
            None
        } else {
            Some(diags.join(","))
        };
        let full_path = Some(resolved.path);

        let primary_fn = rec.primary_name();
        let file_name = primary_fn.map(|f| f.name.clone());
        let parent_entry = primary_fn.map(|f| f.parent_entry);
        let si = rec
            .standard_info
            .as_ref()
            .map(|s| s.macb)
            .unwrap_or_default();
        let dos_attributes = rec
            .standard_info
            .as_ref()
            .map(|s| s.dos_attributes)
            .unwrap_or(0);
        let fna = primary_fn.map(|f| f.macb).unwrap_or_default();
        let host = self.host_label();

        let base = |ads_name: Option<String>,
                    resident_data: Option<Vec<u8>>,
                    logical_size: u64,
                    physical_size: u64|
         -> EmitRow {
            EmitRow {
                host: host.clone(),
                entry: rec.entry,
                sequence: rec.sequence,
                parent_entry,
                full_path: full_path.clone(),
                file_name: file_name.clone(),
                is_dir: rec.is_dir,
                is_allocated: rec.in_use,
                si,
                fna,
                logical_size,
                physical_size,
                hard_link_count: rec.hard_link_count,
                dos_attributes,
                ads_name,
                resident_data,
                diagnostics: diagnostics.clone(),
            }
        };

        match self.mode {
            Mode::Streams => {
                // One row per $DATA stream (primary + each ADS).
                let mut emitted = false;
                if let Some(p) = &rec.data.primary {
                    rows.push(base(None, p.data.clone(), p.logical_size, p.physical_size));
                    emitted = true;
                }
                for a in &rec.data.ads {
                    rows.push(base(
                        a.name.clone(),
                        a.data.clone(),
                        a.logical_size,
                        a.physical_size,
                    ));
                    emitted = true;
                }
                if !emitted {
                    // No $DATA at all (e.g. a directory): still emit one row.
                    rows.push(base(None, None, 0, 0));
                }
            }
            Mode::Files | Mode::Allocated => {
                let resident = rec.data.resident_bytes().map(|b| b.to_vec());
                rows.push(base(
                    None,
                    resident,
                    rec.data.logical_size(),
                    rec.data.physical_size(),
                ));
            }
        }
    }
}

impl ReadMftProducer {
    /// The real per-batch producer (collector-free, so tests can drive it
    /// without the crate-private `OutputCollector`).
    fn produce(&mut self) -> Result<Option<RecordBatch>> {
        // Apply a pending resume (HTTP rehydration) before producing.
        if let Some(state) = self.pending_resume.take() {
            self.entry_cursor = state.next_entry();
            self.records_emitted = state.cursor.records_emitted;
            // Trust the explicit source index — an end-of-scan state (index past
            // the last source) must terminate, not restart from source 0.
            self.source_idx = state.source_index as usize;
            self.resolver = state.resolver;
            self.decoder = None;
        }

        let mut rows: Vec<EmitRow> = Vec::with_capacity(BATCH_ROWS);
        while rows.len() < BATCH_ROWS {
            if !self.ensure_open()? {
                break;
            }
            let dec = self.decoder.as_mut().expect("decoder ensured");
            let count = dec.entry_count();
            if self.entry_cursor >= count {
                self.advance_source();
                continue;
            }
            // Decode a slab of entries, fanning each into rows.
            while self.entry_cursor < count && rows.len() < BATCH_ROWS {
                let n = self.entry_cursor;
                self.entry_cursor += 1;
                // Re-borrow the decoder each iteration to satisfy the borrow checker.
                let decoded = self
                    .decoder
                    .as_mut()
                    .expect("decoder ensured")
                    .decode(n)
                    .map_err(|e| RpcError::value_error(format!("decode entry {n}: {e}")))?;
                if let Some(rec) = decoded {
                    let before = rows.len();
                    self.emit(&rec, &mut rows);
                    self.records_emitted += (rows.len() - before) as u64;
                }
            }
            if self.entry_cursor >= count {
                self.advance_source();
            }
        }

        if rows.is_empty() {
            return Ok(None);
        }
        Ok(Some(build_timeline_batch(&self.schema, &rows)?))
    }
}

impl TableProducer for ReadMftProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        self.produce()
    }

    fn resume_supported(&self) -> bool {
        true
    }

    fn encode_resume(&self) -> Vec<u8> {
        let record_size = self
            .decoder
            .as_ref()
            .map(|d| d.record_size())
            .unwrap_or(1024);
        let source = self
            .sources
            .get(self.source_idx)
            .map(|s| s.label())
            .unwrap_or_default();
        let state = MftScanState {
            cursor: MftCursor {
                source,
                byte_offset: self.entry_cursor * u64::from(record_size),
                records_emitted: self.records_emitted,
            },
            resolver: self.resolver.clone(),
            pending_paths: Vec::new(),
            record_size,
            max_depth: mft_core::DEFAULT_MAX_DEPTH,
            resolver_built: !self.resolver.is_empty(),
            source_index: self.source_idx as u64,
        };
        state.to_bytes()
    }

    fn restore_resume(&mut self, bytes: &[u8]) {
        self.pending_resume = Some(MftScanState::from_bytes(bytes));
    }
}

/// Test-only: scan a blob fully into batches, without RPC.
#[cfg(test)]
pub(crate) fn scan_blob(
    bytes: Vec<u8>,
    host: Option<String>,
    mode: Mode,
) -> Result<Vec<RecordBatch>> {
    let mut p = ReadMftProducer::new_blob(timeline_schema(), bytes, host, mode);
    let mut out = Vec::new();
    while let Some(b) = p.produce()? {
        out.push(b);
    }
    Ok(out)
}

/// Test-only: build a producer over a blob (for resume round-trip tests).
#[cfg(test)]
pub(crate) fn producer_for_blob(bytes: Vec<u8>) -> ReadMftProducer {
    ReadMftProducer::new_blob(timeline_schema(), bytes, None, Mode::Files)
}

#[cfg(test)]
pub(crate) fn producer_next(p: &mut ReadMftProducer) -> Result<Option<RecordBatch>> {
    p.produce()
}

#[cfg(test)]
impl ReadMftProducer {
    pub(crate) fn encode(&self) -> Vec<u8> {
        self.encode_resume()
    }
    pub(crate) fn restore(&mut self, bytes: &[u8]) {
        self.restore_resume(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::cast::AsArray;
    use arrow_array::types::UInt64Type;
    use arrow_array::{Array, BooleanArray, RecordBatch, StringArray};
    use mft_core::synth::{ns, MftBuilder, RecordBuilder, Times};

    const F_DIR: u32 = 0x1000_0000;
    const F_ARCHIVE: u32 = 0x20;

    fn sample() -> Vec<u8> {
        let t = Times::uniform_micros(1_600_000_000_500_000);
        MftBuilder::new()
            .add(
                &RecordBuilder::new(0, 1)
                    .standard_info(t, F_ARCHIVE, 1)
                    .file_name(5, 5, t, 0, 0, F_ARCHIVE, ns::WIN32, "$MFT"),
            )
            .add(
                &RecordBuilder::new(5, 5)
                    .directory(true)
                    .standard_info(t, F_DIR, 2)
                    .file_name(5, 5, t, 0, 0, F_DIR, ns::WIN32, "."),
            )
            .add(
                &RecordBuilder::new(11, 1)
                    .directory(true)
                    .standard_info(t, F_DIR, 3)
                    .file_name(5, 5, t, 0, 0, F_DIR, ns::WIN32, "Windows"),
            )
            .add(
                &RecordBuilder::new(12, 1)
                    .directory(true)
                    .standard_info(t, F_DIR, 4)
                    .file_name(11, 1, t, 0, 0, F_DIR, ns::WIN32, "System32"),
            )
            .add(
                &RecordBuilder::new(20, 1)
                    .standard_info(t, F_ARCHIVE, 5)
                    .file_name(12, 1, t, 11, 16, F_ARCHIVE, ns::WIN32, "cmd.exe")
                    .data_resident(b"MZresident"),
            )
            .add(
                &RecordBuilder::new(23, 2)
                    .allocated(false)
                    .standard_info(t, F_ARCHIVE, 8)
                    .file_name(12, 1, t, 9, 16, F_ARCHIVE, ns::WIN32, "deleted.log")
                    .data_resident(b"logged"),
            )
            .add(
                &RecordBuilder::new(24, 1)
                    .standard_info(Times::uniform_secs(1_230_000_000), F_ARCHIVE, 9)
                    .file_name(
                        12,
                        1,
                        Times::uniform_secs(1_600_000_000),
                        100,
                        104,
                        F_ARCHIVE,
                        ns::WIN32,
                        "timestomped.exe",
                    ),
            )
            .add(
                &RecordBuilder::new(22, 1)
                    .standard_info(t, F_ARCHIVE, 7)
                    .file_name(12, 1, t, 5, 8, F_ARCHIVE, ns::WIN32, "notes.txt")
                    .data_resident(b"hi")
                    .ads_resident("hidden", b"secret"),
            )
            .finish()
    }

    fn col_str<'a>(b: &'a RecordBatch, name: &str) -> &'a StringArray {
        b.column(b.schema().index_of(name).unwrap())
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap()
    }
    fn col_bool<'a>(b: &'a RecordBatch, name: &str) -> &'a BooleanArray {
        b.column(b.schema().index_of(name).unwrap())
            .as_any()
            .downcast_ref::<BooleanArray>()
            .unwrap()
    }

    fn find_entry(b: &RecordBatch, entry: u64) -> Option<usize> {
        let col = b
            .column(b.schema().index_of("entry").unwrap())
            .as_primitive::<UInt64Type>();
        (0..b.num_rows()).find(|&i| col.value(i) == entry)
    }

    #[test]
    fn timeline_path_and_flags() {
        let batches = scan_blob(sample(), None, Mode::Files).unwrap();
        assert_eq!(batches.len(), 1);
        let b = &batches[0];
        let i = find_entry(b, 20).expect("cmd.exe row");
        assert_eq!(
            col_str(b, "full_path").value(i),
            "Windows\\System32\\cmd.exe"
        );
        assert_eq!(col_str(b, "file_name").value(i), "cmd.exe");
        assert!(!col_bool(b, "is_deleted").value(i));
    }

    #[test]
    fn deleted_included_by_default() {
        let batches = scan_blob(sample(), None, Mode::Files).unwrap();
        let b = &batches[0];
        let i = find_entry(b, 23).expect("deleted.log row present by default");
        assert!(col_bool(b, "is_deleted").value(i));
    }

    #[test]
    fn allocated_mode_excludes_deleted() {
        let batches = scan_blob(sample(), None, Mode::Allocated).unwrap();
        let b = &batches[0];
        assert!(
            find_entry(b, 23).is_none(),
            "deleted record excluded in allocated mode"
        );
        assert!(find_entry(b, 20).is_some(), "live record retained");
    }

    #[test]
    fn timestomp_flagged() {
        let batches = scan_blob(sample(), None, Mode::Files).unwrap();
        let b = &batches[0];
        let i = find_entry(b, 24).expect("timestomped.exe row");
        assert!(col_bool(b, "is_timestomp_suspect").value(i));
        // A clean file is not flagged.
        let j = find_entry(b, 20).unwrap();
        assert!(!col_bool(b, "is_timestomp_suspect").value(j));
    }

    #[test]
    fn streams_mode_surfaces_ads() {
        let batches = scan_blob(sample(), None, Mode::Streams).unwrap();
        let b = &batches[0];
        let ads = col_str(b, "ads_name");
        let found = (0..b.num_rows()).any(|i| !ads.is_null(i) && ads.value(i) == "hidden");
        assert!(found, "the 'hidden' ADS must surface in streams mode");
    }

    #[test]
    fn host_arg_populates_column() {
        let batches = scan_blob(sample(), Some("host01".into()), Mode::Files).unwrap();
        let b = &batches[0];
        assert_eq!(col_str(b, "host").value(0), "host01");
    }

    #[test]
    fn resume_state_round_trips() {
        // Open the source (builds the resolver) and encode the scan state at the
        // start of the scan — the HTTP-rehydration snapshot. The resolver must be
        // carried, and restoring it into a fresh producer must reproduce the full
        // scan WITHOUT rebuilding the resolver from scratch.
        let mut p = producer_for_blob(sample());
        assert!(p.ensure_open().unwrap());
        let bytes = p.encode();
        let state = MftScanState::from_bytes(&bytes);
        assert!(!state.resolver.is_empty(), "resolver carried in scan state");
        assert_eq!(state.cursor.byte_offset, 0, "snapshot at start of source");

        let expected_rows: usize = scan_blob(sample(), None, Mode::Files)
            .unwrap()
            .iter()
            .map(|b| b.num_rows())
            .sum();

        let mut p2 = producer_for_blob(sample());
        p2.restore(&bytes);
        let resumed: usize = std::iter::from_fn(|| producer_next(&mut p2).transpose())
            .map(|b| b.unwrap().num_rows())
            .sum();
        assert_eq!(resumed, expected_rows, "resume reproduces the full scan");
    }
}
