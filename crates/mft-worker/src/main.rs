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
                 timeline directly in SQL — no per-host CLI run, no network, no egress; it only \
                 ever reads the bytes you already collected. The $MFT is NTFS's index of every \
                 file and directory, so parsing it reconstructs full paths from parent references, \
                 exposes both the user-writable $STANDARD_INFORMATION and the kernel-only \
                 $FILE_NAME MACB timestamp quads (making an SI-vs-FN timestomp mismatch a plain \
                 WHERE clause), recovers deleted-but-resident records, and surfaces alternate data \
                 streams and inline resident file content. Reach for it to timeline thousands of \
                 collected $MFTs for DFIR, incident response, and threat hunting, and to join the \
                 result to known-bad paths, hashes, and detection rules. List the schema to \
                 discover the available functions and their signatures."
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
                 **Key concepts.** The `$MFT` is NTFS's index of every file and directory. Each \
                 FILE record carries the metadata this worker turns into columns: the full path \
                 reconstructed by walking parent references, logical and physical sizes, \
                 allocated / deleted and file / directory flags, alternate data streams, and \
                 inline resident content. Deleted-but-resident records are recovered by default.\n\n\
                 **The timestomp engine.** `$STANDARD_INFORMATION` is user-writable (the Win32 \
                 `SetFileTime` API and anti-forensic tools rewrite it) while `$FILE_NAME` is \
                 kernel-only, so a standard-information timestamp that predates its file-name \
                 counterpart — naturally impossible — and whole-second values are strong \
                 anti-forensic tells. Both MACB timestamp quads are first-class columns.\n\n\
                 Built on the permissively-licensed `mft` crate (omerbenamram); the NTFS on-disk \
                 layout is documented openly by Microsoft and the forensics community. Part of the \
                 [Query.Farm](https://query.farm) VGI ecosystem — the seed of a Windows-DFIR bundle \
                 alongside `vgi-evtx` (event logs)."
                    .to_string(),
            ),
            (
                "vgi.agent_test_tasks".to_string(),
                crate::meta::agent_test_tasks_json(&[
                    crate::meta::AgentTask {
                        name: "worker_version",
                        prompt: "Before relying on the mft worker in a pipeline, record which \
                                 build is attached. Return the worker version string as a single \
                                 row with one column named version.",
                        reference_sql: "SELECT mft.main.mft_version() AS version",
                        // Single scalar row; order is irrelevant, values must match.
                        unordered: true,
                        ignore_column_names: false,
                    },
                    crate::meta::AgentTask {
                        name: "timeline_row_count",
                        prompt: "Parse the sample $MFT at data/sample.mft and tell me how many \
                                 FILE records it contains. Return one row with a single column \
                                 named records.",
                        reference_sql:
                            "SELECT count(*) AS records FROM mft.main.read_mft('data/sample.mft')",
                        // A single count value; tolerate a differently-named column.
                        unordered: true,
                        ignore_column_names: true,
                    },
                    crate::meta::AgentTask {
                        name: "list_deleted_files",
                        prompt: "From the sample $MFT at data/sample.mft, list the names of the \
                                 deleted (not-allocated) non-directory files. Return a column \
                                 named file_name, ordered alphabetically.",
                        reference_sql: "SELECT file_name FROM mft.main.read_mft('data/sample.mft') \
                                        WHERE is_deleted AND NOT is_dir ORDER BY file_name",
                        // Reference pins the order with ORDER BY.
                        unordered: false,
                        ignore_column_names: false,
                    },
                    crate::meta::AgentTask {
                        name: "timestomp_hunt",
                        prompt: "Hunt the sample $MFT at data/sample.mft for timestomping: return \
                                 the full_path of every record flagged is_timestomp_suspect. \
                                 Return a single column named full_path ordered alphabetically.",
                        reference_sql: "SELECT full_path FROM mft.main.read_mft('data/sample.mft') \
                                        WHERE is_timestomp_suspect ORDER BY full_path",
                        unordered: false,
                        ignore_column_names: false,
                    },
                    crate::meta::AgentTask {
                        name: "alternate_data_streams",
                        prompt: "Surface every alternate data stream in the sample $MFT at \
                                 data/sample.mft using streams mode. Return the ads name in a \
                                 column named ads_name for rows where ads_name is not null, \
                                 ordered alphabetically.",
                        reference_sql: "SELECT ads_name FROM mft.main.read_mft('data/sample.mft', \
                                        mode := 'streams') WHERE ads_name IS NOT NULL ORDER BY \
                                        ads_name",
                        unordered: false,
                        ignore_column_names: false,
                    },
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
                "NTFS $MFT forensics: a filesystem timeline, per-record decode and validation, \
                 the timestomp heuristic, and attribute / $DATA-stream fan-out."
                    .to_string(),
            ),
            tags: vec![
                ("vgi.title".to_string(), "MFT — main".to_string()),
                (
                    "vgi.keywords".to_string(),
                    crate::meta::keywords_json(
                        "ntfs, $MFT, master file table, dfir, forensics, incident response, \
                         threat hunt, timeline, timestomp, MACB, deleted files, alternate data \
                         stream, ADS, path reconstruction, windows",
                    ),
                ),
                ("domain".to_string(), "security-and-forensics".to_string()),
                ("topic".to_string(), "ntfs-mft-timeline".to_string()),
                (
                    "vgi.categories".to_string(),
                    crate::meta::CATEGORIES_JSON.to_string(),
                ),
                (
                    "vgi.doc_llm".to_string(),
                    "The single schema for the mft worker (qualify calls as \
                     `mft.main.<fn>(...)`). It turns a collected NTFS $MFT into a forensic \
                     filesystem timeline: full-path reconstruction from parent references, the \
                     SI-vs-FN MACB timestomp heuristic, deleted-record recovery, per-record decode \
                     and never-panic validation, and attribute / $DATA-stream fan-out. List the \
                     schema to discover the available functions and their signatures."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "The single schema for the `mft` worker — qualify calls as \
                     `mft.main.<fn>(...)`. It turns a collected NTFS `$MFT` into a forensic \
                     filesystem timeline: full paths reconstructed from parent references, the \
                     user-writable-SI vs kernel-only-FN MACB timestomp heuristic, deleted-record \
                     recovery, per-record decode and never-panic validation, and attribute / \
                     `$DATA`-stream fan-out. List the schema to discover the available functions \
                     and their signatures."
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
