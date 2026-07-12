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

use vgi::catalog::{CatSchema, CatView, CatalogModel};
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
                    crate::meta::AgentTask {
                        name: "reconstruct_path",
                        prompt: "In the sample $MFT at data/sample.mft, reconstruct the full \
                                 filesystem path of MFT record 20. Return one row with a single \
                                 column named path.",
                        reference_sql: "SELECT mft.main.full_path((SELECT content FROM \
                                        read_blob('data/sample.mft')), 20) AS path",
                        // A single deterministic path string.
                        unordered: true,
                        ignore_column_names: false,
                    },
                    crate::meta::AgentTask {
                        name: "decode_record_ads",
                        prompt: "Fully decode MFT record 22 in the sample $MFT at data/sample.mft \
                                 and tell me how many alternate data streams (ADS) it carries. \
                                 Return one row with a single column named ads_count.",
                        reference_sql: "SELECT len(mft.main.mft_record((SELECT content FROM \
                                        read_blob('data/sample.mft')), 22).ads) AS ads_count",
                        // A single count; tolerate a differently-named column.
                        unordered: true,
                        ignore_column_names: true,
                    },
                    crate::meta::AgentTask {
                        name: "probe_header_is_dir",
                        prompt: "Probe just the FILE-record header of MFT record 12 in the sample \
                                 $MFT at data/sample.mft. Is it a directory? Return one row with a \
                                 single boolean column named is_dir.",
                        reference_sql: "SELECT mft.main.record_header((SELECT content FROM \
                                        read_blob('data/sample.mft')), 12).is_dir AS is_dir",
                        unordered: true,
                        ignore_column_names: false,
                    },
                    crate::meta::AgentTask {
                        name: "validate_record",
                        prompt: "Validate MFT record 20 in the sample $MFT at data/sample.mft. Is \
                                 the record well-formed? Return one row with a single boolean \
                                 column named ok.",
                        reference_sql: "SELECT mft.main.well_formed((SELECT content FROM \
                                        read_blob('data/sample.mft')), 20).ok AS ok",
                        unordered: true,
                        ignore_column_names: false,
                    },
                    crate::meta::AgentTask {
                        name: "timestomp_heuristic",
                        prompt: "Using the timestomp heuristic, decide whether a record whose \
                                 $STANDARD_INFORMATION timestamps are all 2009-01-01 while its \
                                 $FILE_NAME timestamps are all 2020-01-01 is a timestomp suspect \
                                 (its SI predates its FN). Return one row with a single boolean \
                                 column named suspect.",
                        reference_sql: "SELECT mft.main.timestomp({'created': TIMESTAMP \
                                        '2009-01-01', 'modified': TIMESTAMP '2009-01-01', \
                                        'accessed': TIMESTAMP '2009-01-01', 'mft_modified': \
                                        TIMESTAMP '2009-01-01'}, {'created': TIMESTAMP '2020-01-01', \
                                        'modified': TIMESTAMP '2020-01-01', 'accessed': TIMESTAMP \
                                        '2020-01-01', 'mft_modified': TIMESTAMP '2020-01-01'}).suspect \
                                        AS suspect",
                        unordered: true,
                        ignore_column_names: false,
                    },
                    crate::meta::AgentTask {
                        name: "count_record_attributes",
                        prompt: "In the sample $MFT at data/sample.mft, count how many NTFS \
                                 attributes MFT record 22 has. Return one row with a single column \
                                 named attribute_count.",
                        reference_sql: "SELECT count(*) AS attribute_count FROM \
                                        mft.main.attributes((FROM (SELECT content AS blob, \
                                        22::UBIGINT AS entry FROM read_blob('data/sample.mft'))))",
                        // A single count; tolerate a differently-named column.
                        unordered: true,
                        ignore_column_names: true,
                    },
                    crate::meta::AgentTask {
                        name: "detect_alternate_data_stream",
                        prompt: "In the sample $MFT at data/sample.mft, determine whether MFT \
                                 record 22 has an alternate data stream — a $DATA stream whose name \
                                 is not null. Return one row with a single boolean column named \
                                 has_ads.",
                        reference_sql: "SELECT count(*) FILTER (WHERE name IS NOT NULL) > 0 AS \
                                        has_ads FROM mft.main.streams((FROM (SELECT content AS blob, \
                                        22::UBIGINT AS entry FROM read_blob('data/sample.mft'))))",
                        unordered: true,
                        ignore_column_names: false,
                    },
                    crate::meta::AgentTask {
                        name: "attribute_type_lookup",
                        prompt: "Using the NTFS attribute-type reference table, look up the \
                                 canonical attribute name for attribute type id 128. Return one row \
                                 with a single column named type_name.",
                        reference_sql: "SELECT type_name FROM mft.main.ntfs_attribute_types WHERE \
                                        type_id = 128",
                        unordered: true,
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
                    "## The `mft` worker\n\n\
                     Turns a collected NTFS `$MFT` into a forensic filesystem timeline you can \
                     query with SQL. Point it at a captured `$MFT` — a path, a glob across many \
                     hosts, or an in-memory `BLOB` — and it reconstructs what the filesystem \
                     looked like, and what was tampered with. Qualify calls as \
                     `mft.main.<fn>(...)`.\n\n\
                     **Key concepts**\n\n\
                     - *Path reconstruction* — parent-reference walking rebuilds absolute paths, \
                     flagging orphans and reference cycles.\n\
                     - *MACB timelines* — the `$STANDARD_INFORMATION` and `$FILE_NAME` timestamp \
                     quads surfaced side by side.\n\
                     - *Timestomp heuristic* — the user-writable-SI vs kernel-only-FN comparison \
                     that flags manipulated timestamps.\n\
                     - *Recovery & robustness* — deleted-record recovery and never-panic decode \
                     over hostile or truncated input, plus attribute and `$DATA` / alternate-data-\
                     stream fan-out.\n\n\
                     **When to use it** — DFIR triage, threat hunting, and incident response over \
                     Windows hosts. List the schema to discover the available functions and their \
                     signatures."
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
            views: vec![attribute_types_view()],
            macros: Vec::new(),
            tables: Vec::new(),
        }],
        ..Default::default()
    }
}

/// A curated, browsable reference view (VGI146): the NTFS attribute-type registry.
///
/// A worker that exposes only table functions makes an agent guess arguments
/// before it can see any data. This VALUES-backed view is a real, browsable
/// relation — no `$MFT`, no arguments, no network or credential — that documents
/// the vocabulary behind the `type_id` / `type_name` columns of the `attributes()`
/// function. Being VALUES-backed (not a wrapper over a parameterless table
/// function) it satisfies VGI146 without tripping VGI145, and it scans instantly,
/// clearing VGI911/VGI903 for free.
fn attribute_types_view() -> CatView {
    CatView {
        name: "ntfs_attribute_types".to_string(),
        // `type_id` is cast to UINTEGER in the first row so the view column type
        // matches the `type_id` column the attributes() function emits (VGI205).
        definition: r#"SELECT * FROM (VALUES
  (16::UINTEGER, '$STANDARD_INFORMATION', 'Standard information: the SI MACB timestamp quad, DOS file attributes, USN, and quota/security ids. User-writable, so it is what the timestomp heuristic watches.'),
  (32, '$ATTRIBUTE_LIST', 'A pointer list to attributes held in other FILE records, used when a single record overflows.'),
  (48, '$FILE_NAME', 'A name (Win32, DOS 8.3, or POSIX namespace), the parent-directory reference used to reconstruct paths, and the kernel-only FN MACB quad.'),
  (64, '$OBJECT_ID', 'The 64-bit object id / distributed-link-tracking GUID.'),
  (80, '$SECURITY_DESCRIPTOR', 'A per-file security descriptor (modern volumes centralize these in the $Secure metafile).'),
  (96, '$VOLUME_NAME', 'The volume label (carried by the $Volume metadata file).'),
  (112, '$VOLUME_INFORMATION', 'The NTFS version and the volume dirty/state flags (carried by $Volume).'),
  (128, '$DATA', 'File content: the unnamed primary stream plus any named alternate data streams (ADS).'),
  (144, '$INDEX_ROOT', 'The resident root of a B-tree index — directory entries and other indexes.'),
  (160, '$INDEX_ALLOCATION', 'The non-resident B-tree blocks of a large index, such as a big directory.'),
  (176, '$BITMAP', 'An allocation bitmap for the $MFT itself or for an index allocation.'),
  (192, '$REPARSE_POINT', 'Reparse data: symbolic links, junctions, mount points, and filter-driver tags.'),
  (208, '$EA_INFORMATION', 'Size and packing metadata for extended attributes.'),
  (224, '$EA', 'Extended-attribute name/value pairs (OS/2 and application metadata).'),
  (256, '$LOGGED_UTILITY_STREAM', 'A logged stream used by EFS ($EFS encryption metadata) and other utilities.')
) AS t(type_id, type_name, purpose)"#
            .to_string(),
        comment: Some(
            "Reference registry mapping each NTFS attribute type code to its canonical name and \
             purpose — the vocabulary behind the `type_id` / `type_name` columns of the \
             attributes() function. A static, credential-free lookup you can browse or join."
                .to_string(),
        ),
        tags: vec![
            ("vgi.category".to_string(), "Attributes & Streams".to_string()),
            (
                "vgi.title".to_string(),
                "NTFS Attribute Type Reference".to_string(),
            ),
            ("domain".to_string(), "security-and-forensics".to_string()),
            ("topic".to_string(), "ntfs-attribute-types".to_string()),
            (
                "vgi.keywords".to_string(),
                crate::meta::keywords_json(
                    "ntfs attribute types, attribute type code, type_id, type_name, \
                     $STANDARD_INFORMATION, $FILE_NAME, $DATA, $INDEX_ROOT, $REPARSE_POINT, \
                     reference, registry, lookup, mft",
                ),
            ),
            (
                "vgi.doc_llm".to_string(),
                "A browsable reference table (no arguments, no $MFT needed) listing the fifteen \
                 standard NTFS attribute type codes with their canonical `$`-prefixed name and a \
                 one-line purpose. Columns: `type_id` (UINTEGER, e.g. 128), `type_name` (VARCHAR, \
                 e.g. `$DATA`), `purpose` (VARCHAR). It is the vocabulary behind the `type_id` and \
                 `type_name` columns of the attributes() function — join or filter it to explain a \
                 record's attributes without parsing bytes. Type codes are the on-disk NTFS values \
                 (16 = 0x10 = $STANDARD_INFORMATION, 48 = 0x30 = $FILE_NAME, 128 = 0x80 = $DATA)."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "# `ntfs_attribute_types`\n\n\
                 A static, browsable reference of the fifteen standard NTFS attribute type codes — \
                 the vocabulary behind the `type_id` / `type_name` columns of the `attributes()` \
                 function. No arguments, no `$MFT`, no network.\n\n\
                 ## Columns\n\n\
                 - `type_id` (UINTEGER) -- the on-disk NTFS attribute type code, e.g. `128` \
                 (`0x80`).\n\
                 - `type_name` (VARCHAR) -- the canonical `$`-prefixed name, e.g. `$DATA`.\n\
                 - `purpose` (VARCHAR) -- a one-line description of what the attribute stores.\n\n\
                 Join it to the `attributes()` output on `type_id` to label each attribute, or \
                 browse it on its own. See the example queries for ready-to-run SQL."
                    .to_string(),
            ),
            (
                "vgi.example_queries".to_string(),
                r#"[
  {"description": "Browse the whole NTFS attribute-type registry, lowest code first.",
   "sql": "SELECT type_id, type_name, purpose FROM mft.main.ntfs_attribute_types ORDER BY type_id"},
  {"description": "Look up the name and purpose of attribute type 128 (the $DATA attribute).",
   "sql": "SELECT type_name, purpose FROM mft.main.ntfs_attribute_types WHERE type_id = 128"}
]"#
                .to_string(),
            ),
        ],
        column_comments: vec![
            (
                "type_id".to_string(),
                "The on-disk NTFS attribute type code (the same value the attributes() function \
                 reports in its `type_id` column), e.g. 128 = $DATA."
                    .to_string(),
            ),
            (
                "type_name".to_string(),
                "The canonical attribute name, e.g. $STANDARD_INFORMATION, $FILE_NAME, $DATA."
                    .to_string(),
            ),
            (
                "purpose".to_string(),
                "What the attribute stores and what it is used for in NTFS.".to_string(),
            ),
        ],
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
