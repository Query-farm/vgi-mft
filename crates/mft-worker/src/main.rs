//! The `mft` VGI worker.
//!
//! A standalone binary DuckDB launches and talks to over Apache Arrow IPC
//! (`ATTACH 'vgi-mft' AS mft (TYPE vgi)`). It parses the NTFS `$MFT` (Master File
//! Table) into a forensic filesystem timeline under the catalog `mft`, schema
//! `main`:
//!
//! ```sql
//! ATTACH 'mft' (TYPE vgi, LOCATION './target/release/mft-worker');
//!
//! -- The headline: a full forensic timeline, one row per FILE record.
//! SELECT entry, full_path, is_deleted, si_created, fn_created, ads_name
//! FROM mft.main.read_mft('/cases/host01/$MFT')
//! ORDER BY si_modified DESC;
//!
//! -- Scalars over a (blob, entry) pair, plus the timestomp heuristic.
//! SELECT mft.main.full_path(mftbytes, 5);
//! SELECT mft.main.well_formed(mftbytes, 0).*;
//! SELECT mft.main.mft_version();
//! ```
//!
//! The pure NTFS engine (record decode, path reconstruction, the timestomp
//! heuristic, the externalized scan-state cursor) lives in the `mft-core` crate;
//! the `scalar/`, `table/`, and `table_in_out/` modules are thin Arrow adapters.

mod arrow_io;
mod arrow_map;
mod meta;
mod options;
mod scalar;
mod table;
mod table_in_out;

use vgi::catalog::{CatSchema, CatalogModel};
use vgi::Worker;

/// Worker version string, surfaced by `mft_version()`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Catalog + schema metadata (description, provenance) surfaced to DuckDB and the
/// `vgi-lint` metadata-quality linter.
fn catalog_metadata(name: &str) -> CatalogModel {
    CatalogModel {
        name: name.to_string(),
        comment: Some(
            "Parse the NTFS $MFT into a forensic filesystem timeline: path reconstruction, the \
             SI/FN MACB timestamp pair, timestomp detection, deleted-record recovery, and \
             alternate data streams — straight into SQL."
                .to_string(),
        ),
        tags: vec![
            (
                "vgi.title".to_string(),
                "NTFS $MFT Forensic Timeline".to_string(),
            ),
            (
                "vgi.keywords".to_string(),
                crate::meta::keywords_json(
                    "mft, $MFT, ntfs, master file table, dfir, forensics, incident response, \
                     threat hunt, timeline, windows, filesystem, timestomp, anti-forensics, MACB, \
                     standard information, file name, deleted files, file recovery, alternate data \
                     stream, ADS, path reconstruction, resident data, fixup, USN",
                ),
            ),
            (
                "vgi.doc_llm".to_string(),
                "Parse a collected NTFS $MFT (Master File Table) into a forensic filesystem \
                 timeline directly in SQL. `read_mft(path_or_blob, host := …, mode := …)` returns \
                 one row per FILE record with the full path reconstructed from parent references, \
                 both the $STANDARD_INFORMATION and $FILE_NAME MACB timestamp quads (so the SI-vs-FN \
                 timestomp mismatch is a plain WHERE clause), logical/physical sizes, \
                 allocated/deleted and file/dir flags, alternate data streams, and inline resident \
                 file content. Deleted-but-resident records are included by default. Scalars over a \
                 (blob, entry) pair: `mft_record` (full STRUCT decode), `full_path` (path \
                 reconstruction), `record_header` (header probe), `well_formed` (validate, never \
                 panics), and `timestomp(si, fn)` (the heuristic with reasons). Relation-in/out \
                 `attributes` and `streams` fan a record's attributes / $DATA streams into rows. \
                 No network, no egress — it only ever reads the bytes you collected."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "# mft — NTFS $MFT Forensic Timeline in SQL\n\n\
                 Parse a collected NTFS **`$MFT`** (Master File Table) into a full forensic \
                 filesystem timeline — one row per FILE record — without a per-host CLI run and \
                 with **zero egress**. Built for DFIR / incident-response / threat-hunt teams who \
                 want to timeline thousands of collected `$MFT`s and join the result to known-bad \
                 paths, hashes, and rules in one query.\n\n\
                 The headline `read_mft(path_or_blob, host := …, mode := …)` returns the wide \
                 timeline: `entry`, `sequence`, `parent_entry`, the reconstructed `full_path`, \
                 `file_name`, `is_dir` / `is_allocated` / `is_deleted`, the **SI** quad \
                 (`si_created` / `si_modified` / `si_accessed` / `si_mft_modified`) and the **FN** \
                 quad (`fn_*`), `logical_size` / `physical_size`, `hard_link_count`, \
                 `dos_attributes`, `ads_name`, `resident_data`, `is_timestomp_suspect`, and \
                 `diagnostics`. Deleted-but-resident records are included by default (filter with \
                 `WHERE is_allocated`).\n\n\
                 **The timestomp engine.** `$STANDARD_INFORMATION` is user-writable (the Win32 \
                 `SetFileTime` API and tools like `timestomp` rewrite it) while `$FILE_NAME` is \
                 kernel-only, so SI earlier than FN — naturally impossible — and whole-second SI \
                 values are strong anti-forensic tells. Both quads are first-class columns, and \
                 `timestomp(si, fn)` scores multiple reasons rather than a single boolean.\n\n\
                 **Scalars** (over a `(blob, entry)` pair): `mft_record`, `full_path`, \
                 `record_header`, `well_formed` (never panics on corrupt input), `mft_version`, and \
                 the `timestomp` heuristic. **Relation-in/out**: `attributes` and `streams` fan a \
                 record's attributes / `$DATA` streams (primary + each ADS) into rows.\n\n\
                 Built on the permissively-licensed `mft` crate (omerbenamram). The NTFS on-disk \
                 layout is documented openly by Microsoft and the forensics community. Part of the \
                 [Query.Farm](https://query.farm) VGI ecosystem — the seed of a Windows-DFIR bundle \
                 alongside `vgi-evtx` (event logs)."
                    .to_string(),
            ),
            (
                "vgi.agent_test_tasks".to_string(),
                crate::meta::agent_test_tasks_json(&[
                    (
                        "worker_version",
                        "Before relying on the mft worker in a pipeline, record which build is \
                         attached. Return the worker version string as a single row with one \
                         column named version.",
                        "SELECT mft.main.mft_version() AS version",
                    ),
                    (
                        "timeline_row_count",
                        "Parse the sample $MFT at data/sample.mft and tell me how many FILE records \
                         it contains. Return one row with a single column named records.",
                        "SELECT count(*) AS records FROM mft.main.read_mft('data/sample.mft')",
                    ),
                    (
                        "list_deleted_files",
                        "From the sample $MFT at data/sample.mft, list the names of the deleted \
                         (not-allocated) non-directory files. Return a column named file_name, \
                         ordered alphabetically.",
                        "SELECT file_name FROM mft.main.read_mft('data/sample.mft') WHERE \
                         is_deleted AND NOT is_dir ORDER BY file_name",
                    ),
                    (
                        "timestomp_hunt",
                        "Hunt the sample $MFT at data/sample.mft for timestomping: return the \
                         full_path of every record flagged is_timestomp_suspect. Return a single \
                         column named full_path ordered alphabetically.",
                        "SELECT full_path FROM mft.main.read_mft('data/sample.mft') WHERE \
                         is_timestomp_suspect ORDER BY full_path",
                    ),
                    (
                        "alternate_data_streams",
                        "Surface every alternate data stream in the sample $MFT at data/sample.mft \
                         using streams mode. Return the ads name in a column named ads_name for \
                         rows where ads_name is not null, ordered alphabetically.",
                        "SELECT ads_name FROM mft.main.read_mft('data/sample.mft', mode := \
                         'streams') WHERE ads_name IS NOT NULL ORDER BY ads_name",
                    ),
                ]),
            ),
            ("vgi.author".to_string(), "Query.Farm".to_string()),
            (
                "vgi.copyright".to_string(),
                "Copyright 2026 Query Farm LLC - https://query.farm".to_string(),
            ),
            ("vgi.license".to_string(), "MIT".to_string()),
            (
                "vgi.support_contact".to_string(),
                "https://github.com/Query-farm/vgi-mft/issues".to_string(),
            ),
            (
                "vgi.support_policy_url".to_string(),
                "https://github.com/Query-farm/vgi-mft/blob/main/README.md".to_string(),
            ),
        ],
        source_url: Some("https://github.com/Query-farm/vgi-mft".to_string()),
        schemas: vec![CatSchema {
            name: "main".to_string(),
            comment: Some(
                "NTFS $MFT parsing: read_mft timeline, per-record scalars, the timestomp \
                 heuristic, and attribute / stream fan-out."
                    .to_string(),
            ),
            tags: vec![
                ("vgi.title".to_string(), "MFT — main".to_string()),
                (
                    "vgi.keywords".to_string(),
                    crate::meta::keywords_json(
                        "read_mft, mft_record, full_path, timestomp, record_header, well_formed, \
                         attributes, streams, mft_version, ntfs, $MFT, dfir, timeline",
                    ),
                ),
                ("domain".to_string(), "security-and-forensics".to_string()),
                ("category".to_string(), "digital-forensics".to_string()),
                ("topic".to_string(), "ntfs-mft-timeline".to_string()),
                (
                    "vgi.doc_llm".to_string(),
                    "NTFS $MFT functions: `read_mft` (forensic timeline, one row per FILE record), \
                     `mft_record` / `full_path` / `record_header` / `well_formed` scalars over a \
                     (blob, entry) pair, `timestomp(si, fn)` (the SI-vs-FN heuristic), \
                     `mft_version`, and the `attributes` / `streams` relation-in/out fan-outs."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "The single schema for the `mft` worker — qualify calls as \
                     `mft.main.<fn>(...)`. It holds the `read_mft` timeline table function, the \
                     per-record scalars (`mft_record`, `full_path`, `record_header`, \
                     `well_formed`, `mft_version`), the `timestomp` heuristic scalar, and the \
                     `attributes` / `streams` relation-in/out fan-outs."
                        .to_string(),
                ),
                (
                    "vgi.example_queries".to_string(),
                    "SELECT mft.main.mft_version();\n\
                     SELECT entry, full_path, is_deleted FROM mft.main.read_mft('data/sample.mft');\n\
                     SELECT full_path FROM mft.main.read_mft('data/sample.mft') WHERE \
                     is_timestomp_suspect;\n\
                     SELECT ads_name FROM mft.main.read_mft('data/sample.mft', mode := 'streams') \
                     WHERE ads_name IS NOT NULL;"
                        .to_string(),
                ),
            ],
            views: Vec::new(),
            macros: Vec::new(),
            tables: Vec::new(),
        }],
        ..Default::default()
    }
}

fn main() {
    // Logs MUST go to stderr — stdout is the Arrow-IPC channel.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().filter_or("VGI_LOG", "info"))
        .format_timestamp_millis()
        .try_init();

    // Silence panics from the third-party parsing crates (caught per-record by
    // mft-core); real-bug panics still surface.
    mft_core::quiet_parser_panics();

    if std::env::var_os("VGI_WORKER_CATALOG_NAME").is_none() {
        std::env::set_var("VGI_WORKER_CATALOG_NAME", "mft");
    }
    let catalog_name =
        std::env::var("VGI_WORKER_CATALOG_NAME").unwrap_or_else(|_| "mft".to_string());

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    table::register(&mut worker);
    table_in_out::register(&mut worker);
    worker.set_catalog(catalog_metadata(&catalog_name));
    worker.run();
}
