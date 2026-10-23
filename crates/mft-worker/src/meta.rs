//! Shared helpers for the per-object discovery/description metadata that the
//! `vgi-lint` strict profile expects on **every** function and table.
//!
//! Each function/table surfaces these in its `FunctionMetadata.tags`:
//! - `vgi.title` (VGI124)            — human-friendly display name
//! - `vgi.doc_llm` (VGI112)          — concise prose aimed at LLMs
//! - `vgi.doc_md` (VGI113)           — short Markdown description
//! - `vgi.keywords` (VGI126/VGI138)  — a JSON array of search terms/synonyms
//!
//! Per-object `vgi.source_url` is intentionally NOT emitted here: `vgi.source_url`
//! belongs on the catalog object only (VGI139).

use arrow_schema::{DataType, Schema, TimeUnit};

/// Map an Arrow `DataType` to the DuckDB type name `DESCRIBE` reports for it, for
/// the column types this worker actually emits. Keeps the declared
/// `vgi.result_columns_schema` types identical to what the function returns
/// (VGI910), sourced from the same Arrow schema so they cannot drift.
fn duckdb_type_name(dt: &DataType) -> &'static str {
    match dt {
        DataType::Utf8 | DataType::LargeUtf8 => "VARCHAR",
        DataType::Binary | DataType::LargeBinary => "BLOB",
        DataType::Boolean => "BOOLEAN",
        DataType::UInt8 => "UTINYINT",
        DataType::UInt16 => "USMALLINT",
        DataType::UInt32 => "UINTEGER",
        DataType::UInt64 => "UBIGINT",
        DataType::Int8 => "TINYINT",
        DataType::Int16 => "SMALLINT",
        DataType::Int32 => "INTEGER",
        DataType::Int64 => "BIGINT",
        DataType::Timestamp(TimeUnit::Microsecond, None) => "TIMESTAMP",
        // Only the types above are emitted by this worker's table functions; any
        // future type must be added here so the declared schema stays exact.
        _ => "VARCHAR",
    }
}

/// Build the structured `vgi.result_columns_schema` (VGI307; migrated from the
/// retired `vgi.result_columns_md`, VGI414) as a JSON array of
/// `{name, type, description}` — one entry per output column, its `type` the
/// DuckDB type and its `description` sourced from the field's `comment` metadata.
/// Generating it from the function's own output Arrow schema guarantees the
/// declared schema matches the emitted columns (VGI910) and never drifts.
pub fn result_columns_schema_json(schema: &Schema) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
    let items: Vec<String> = schema
        .fields()
        .iter()
        .map(|f| {
            let desc = f
                .metadata()
                .get("comment")
                .map(String::as_str)
                .unwrap_or("");
            format!(
                "{{\"name\":\"{}\",\"type\":\"{}\",\"description\":\"{}\"}}",
                esc(f.name()),
                duckdb_type_name(f.data_type()),
                esc(desc),
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// The schema's `vgi.categories` navigation registry (VGI413): an ordered JSON
/// array of `{"name","description"}`. Every object's `vgi.category` must name one
/// of these (VGI409), and every category must own at least one object (VGI412).
pub const CATEGORIES_JSON: &str = r#"[
  {"name": "Timeline", "description": "The headline forensic timeline over a collected $MFT — one row per FILE record with reconstructed paths, both MACB timestamp quads, sizes, flags, and streams."},
  {"name": "Records", "description": "Per-record work over a single (blob, entry): full decode, header probe, path reconstruction, and never-panic validation."},
  {"name": "Anti-Forensics", "description": "Timestomp detection — the SI-vs-FN MACB heuristic that flags manipulated timestamps."},
  {"name": "Attributes & Streams", "description": "Fan a record's NTFS attributes or $DATA streams (primary + alternate data streams) into rows."}
]"#;

/// Encode comma-separated keywords as the JSON array of strings that
/// `vgi.keywords` requires (VGI138).
pub fn keywords_json(keywords: &str) -> String {
    let items: Vec<String> = keywords
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(|k| {
            let escaped = k.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\"")
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// A single `vgi.agent_test_tasks` entry: the analyst-visible `name` + `prompt`.
/// Only this public half is published in the catalog tag; each task's grader
/// (`reference_sql` plus the `unordered` / `ignore_column_names` result-compare
/// policy) lives in `vgi-agent-tests.yaml` at the repo root, keyed by task name,
/// so the agent being graded never sees it (VGI416).
pub struct AgentTask {
    pub name: &'static str,
    pub prompt: &'static str,
}

/// Build the `vgi.agent_test_tasks` JSON value: the fixed suite of analyst tasks
/// that `vgi-lint simulate` runs. Only `name` + `prompt` are emitted; the grader
/// for each task is in `vgi-agent-tests.yaml`.
pub fn agent_test_tasks_json(tasks: &[AgentTask]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
    let items: Vec<String> = tasks
        .iter()
        .map(|t| {
            format!(
                "{{\"name\":\"{}\",\"prompt\":\"{}\"}}",
                esc(t.name),
                esc(t.prompt),
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// The standard tags plus a `vgi.example_queries` demo (VGI306/VGI506) for a
/// scalar/table function. `category` names one of the schema's `vgi.categories`
/// (VGI409/VGI411).
pub fn object_tags_with_example(
    category: &str,
    title: &str,
    description_llm: &str,
    description_md: &str,
    keywords: &str,
    example_queries: &str,
) -> Vec<(String, String)> {
    let mut tags = object_tags(category, title, description_llm, description_md, keywords);
    tags.push((
        "vgi.example_queries".to_string(),
        example_queries.to_string(),
    ));
    tags
}

/// Build the standard per-object discovery/description tags. `category` names one
/// of the enclosing schema's `vgi.categories` (VGI409/VGI411 navigation layer).
pub fn object_tags(
    category: &str,
    title: &str,
    description_llm: &str,
    description_md: &str,
    keywords: &str,
) -> Vec<(String, String)> {
    vec![
        ("vgi.category".to_string(), category.to_string()),
        ("vgi.title".to_string(), title.to_string()),
        ("vgi.doc_llm".to_string(), description_llm.to_string()),
        ("vgi.doc_md".to_string(), description_md.to_string()),
        ("vgi.keywords".to_string(), keywords_json(keywords)),
    ]
}
