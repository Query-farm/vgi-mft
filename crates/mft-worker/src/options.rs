//! Argument parsing for `read_mft`: the path/glob-or-blob source, the `host`
//! scope, and the emission `mode`.

use vgi::arguments::Arguments;
use vgi_rpc::{Result, RpcError};

/// Emission mode for `read_mft`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// One row per record, primary stream (default).
    Files,
    /// One row per `$DATA` stream (primary + each ADS).
    Streams,
    /// Only live (allocated) records.
    Allocated,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Mode> {
        match s.to_ascii_lowercase().as_str() {
            "files" => Ok(Mode::Files),
            "streams" => Ok(Mode::Streams),
            "allocated" => Ok(Mode::Allocated),
            other => Err(RpcError::value_error(format!(
                "mode must be 'files', 'streams', or 'allocated', got '{other}'"
            ))),
        }
    }
}

/// The first-argument source: a VARCHAR path/glob, or an inline `$MFT` BLOB.
pub enum Source {
    /// One or more resolved local file paths (a glob expands here).
    Files(Vec<String>),
    /// Inline `$MFT` bytes (a literal / `from_hex(...)` BLOB).
    Blob(Vec<u8>),
}

/// The named `mode` argument (default `files`).
pub fn mode(args: &Arguments) -> Result<Mode> {
    match args.named_str("mode") {
        Some(s) => Mode::parse(&s),
        None => Ok(Mode::Files),
    }
}

/// The named `host` argument (collection scope), if given.
pub fn host(args: &Arguments) -> Option<String> {
    args.named_str("host")
}

/// Resolve the first positional argument to a [`Source`]. Prefers a VARCHAR
/// path/glob; falls back to an inline BLOB.
pub fn source(args: &Arguments) -> Result<Source> {
    if let Some(path) = args.const_str(0) {
        let files = resolve_local(&path)?;
        return Ok(Source::Files(files));
    }
    if let Some(bytes) = args.const_bytes(0) {
        return Ok(Source::Blob(bytes));
    }
    Err(RpcError::value_error(
        "read_mft: first argument must be a VARCHAR path/glob or a BLOB of $MFT bytes",
    ))
}

/// Expand a local path spec to a sorted list of files (a glob expands; a literal
/// path must exist).
pub fn resolve_local(spec: &str) -> Result<Vec<String>> {
    if spec.contains('*') || spec.contains('?') || spec.contains('[') {
        let mut out = Vec::new();
        let entries = glob::glob(spec)
            .map_err(|e| RpcError::value_error(format!("bad glob '{spec}': {e}")))?;
        for entry in entries.flatten() {
            out.push(entry.to_string_lossy().into_owned());
        }
        out.sort();
        if out.is_empty() {
            return Err(RpcError::value_error(format!(
                "no files match glob '{spec}'"
            )));
        }
        Ok(out)
    } else if std::path::Path::new(spec).exists() {
        Ok(vec![spec.to_string()])
    } else {
        Err(RpcError::value_error(format!("File not found: {spec}")))
    }
}
