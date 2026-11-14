//! Example queries shared between the schema-level `vgi.example_queries` list and
//! the per-object example lists, defined once so the copies cannot drift.
//!
//! The *composed* examples chain the worker's own objects the way an analyst
//! would: the `read_mft` timeline supplies the entries that `attributes()`,
//! `mft_record()`, and `timestomp()` then work over, and the
//! `ntfs_attribute_types` view labels the result. Every one reads the committed
//! synthetic `data/sample.mft` over HTTPS from a pinned tag, so it runs offline of
//! a checkout and its output is deterministic.

use vgi::FunctionExample;

/// One documented example: a description plus its SQL.
pub struct Example {
    pub description: &'static str,
    pub sql: &'static str,
}

/// The statement that loads the committed sample `$MFT` into the `mft_sample`
/// session variable. DuckDB forbids a subquery argument to a table function, so
/// `read_mft` takes the bytes from the variable.
macro_rules! load_sample {
    () => {
        "SET VARIABLE mft_sample = (SELECT content FROM read_blob('https://raw.githubusercontent.com/Query-farm/vgi-mft/v0.2.0/data/sample.mft'));\n"
    };
}

/// Composed (read_mft → attributes → ntfs_attribute_types): the attribute makeup
/// of the whole volume. On the sample: $STANDARD_INFORMATION on 10 records,
/// $FILE_NAME on 10 (11 instances — notes.txt also has a DOS name), $DATA on 5
/// (6 instances — notes.txt also has an ADS).
pub const ATTRIBUTE_PROFILE: Example = Example {
    description: "Profile the attribute makeup of a whole $MFT: feed every record entry from the read_mft timeline into attributes(), label each attribute type with its purpose from the ntfs_attribute_types reference view, and count the records and attribute instances per type.",
    sql: concat!(
        load_sample!(),
        "SELECT a.type_id, t.type_name, t.purpose, count(DISTINCT a.entry) AS records, count(*) AS instances FROM mft.main.attributes((FROM (SELECT getvariable('mft_sample') AS blob, entry FROM mft.main.read_mft(getvariable('mft_sample'))))) AS a JOIN mft.main.ntfs_attribute_types AS t ON t.type_id = a.type_id GROUP BY ALL ORDER BY a.type_id"
    ),
};

/// Composed (read_mft → timestomp): explain *why* each suspect is flagged. The
/// timeline only carries the `is_timestomp_suspect` boolean; re-scoring its SI
/// and FN columns with `timestomp()` returns the reasons. On the sample:
/// timestomped.exe, SI created 2008-12-23 vs FN created 2020-09-13.
pub const TIMESTOMP_REASONS: Example = Example {
    description: "Explain each timestomp suspect in the read_mft timeline: re-score its $STANDARD_INFORMATION and $FILE_NAME MACB columns with timestomp() to list which heuristic reasons fired (the timeline itself only carries the is_timestomp_suspect flag).",
    sql: concat!(
        load_sample!(),
        "SELECT full_path, si_created, fn_created, mft.main.timestomp({'created': si_created, 'modified': si_modified, 'accessed': si_accessed, 'mft_modified': si_mft_modified}, {'created': fn_created, 'modified': fn_modified, 'accessed': fn_accessed, 'mft_modified': fn_mft_modified}).reasons AS reasons FROM mft.main.read_mft(getvariable('mft_sample')) WHERE is_timestomp_suspect ORDER BY full_path"
    ),
};

/// Composed (read_mft → mft_record): recover DOS 8.3 short names. The timeline
/// keeps only the primary (Win32) name; `mft_record().fn` lists every
/// `$FILE_NAME`. On the sample: Windows\System32\notes.txt → NOTES~1.TXT.
pub const DOS_SHORT_NAMES: Example = Example {
    description: "Pair each path in the read_mft timeline with its DOS 8.3 short name, unnesting the full $FILE_NAME list that mft_record() decodes for the entry (the timeline keeps only the primary Win32 name).",
    sql: concat!(
        load_sample!(),
        "SELECT t.full_path, f.name AS short_name FROM mft.main.read_mft(getvariable('mft_sample')) AS t, unnest(mft.main.mft_record(getvariable('mft_sample'), t.entry).fn) AS u(f) WHERE f.namespace = 'DOS' ORDER BY t.full_path"
    ),
};

/// The composed examples, in the order the schema-level list shows them.
pub const COMPOSED: [&Example; 3] = [&ATTRIBUTE_PROFILE, &TIMESTOMP_REASONS, &DOS_SHORT_NAMES];

/// Encode examples as the `vgi.example_queries` JSON list of
/// `{"description", "sql"}` objects.
pub fn example_queries_json(examples: &[&Example]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
    let items: Vec<String> = examples
        .iter()
        .map(|e| {
            format!(
                "  {{\"description\": \"{}\",\n   \"sql\": \"{}\"}}",
                esc(e.description),
                esc(e.sql)
            )
        })
        .collect();
    format!("[\n{}\n]", items.join(",\n"))
}

/// The same examples as the function's `FunctionMetadata::examples`.
pub fn function_examples(examples: &[&Example]) -> Vec<FunctionExample> {
    examples
        .iter()
        .map(|e| FunctionExample {
            sql: e.sql.into(),
            description: e.description.into(),
            expected_output: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_queries_json_escapes_and_lists_every_example() {
        let json = example_queries_json(&COMPOSED);
        for e in COMPOSED {
            // The statement separator is JSON-escaped, never a raw newline in a string.
            assert!(
                json.contains(&e.sql.replace('\n', "\\n")),
                "{}",
                e.description
            );
            assert!(json.contains(e.description));
        }
        assert!(json.starts_with("[\n") && json.ends_with("\n]"));
    }

    #[test]
    fn composed_examples_load_the_sample_then_query_qualified_objects() {
        for e in COMPOSED {
            let (load, query) = e.sql.split_once('\n').expect("two statements");
            assert!(load.starts_with("SET VARIABLE mft_sample"));
            assert!(query.contains("mft.main.read_mft("), "{}", e.description);
            assert!(query.contains("ORDER BY"), "{}", e.description);
        }
    }
}
