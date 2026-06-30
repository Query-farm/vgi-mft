//! Fixture generator: writes `data/sample.mft` — a small, byte-accurate
//! synthetic NTFS `$MFT` used by the worker tests and the haybarn SQLLogic E2E.
//!
//! Run from the repo root:  `cargo run -p mft-worker --example gen_fixture`
//!
//! The sample is deliberately curated so the documented SQL examples have
//! deterministic answers: a directory tree (Windows\System32), resident +
//! non-resident `$DATA`, a file with a Win32 long name + DOS short name + an ADS,
//! a deleted-but-resident record, a timestomped record (SI rewound before FN,
//! whole-second SI), and an orphan whose parent is missing.

use std::path::PathBuf;

use mft_core::synth::{ns, MftBuilder, RecordBuilder, Times};

const F_DIR: u32 = 0x1000_0000;
const F_ARCHIVE: u32 = 0x20;

fn main() {
    let bytes = build();
    // data/ sits at the repo root (two levels up from this crate).
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/sample.mft")
        .canonicalize()
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/sample.mft")
        });
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    std::fs::write(&out, &bytes).unwrap();
    eprintln!("wrote {} ({} bytes)", out.display(), bytes.len());
}

/// The canonical sample `$MFT` (kept in sync with the golden core tests).
pub fn build() -> Vec<u8> {
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
                .data_resident(b"MZ\x90\x00resident!"),
        )
        .add(
            &RecordBuilder::new(21, 1)
                .standard_info(t, F_ARCHIVE, 6)
                .file_name(
                    12,
                    1,
                    t,
                    1_048_576,
                    1_052_672,
                    F_ARCHIVE,
                    ns::WIN32,
                    "big.bin",
                )
                .data_non_resident(1_048_576, 1_052_672),
        )
        .add(
            &RecordBuilder::new(22, 1)
                .standard_info(t, F_ARCHIVE, 7)
                .file_name(12, 1, t, 5, 8, F_ARCHIVE, ns::WIN32, "notes.txt")
                .file_name(12, 1, t, 5, 8, F_ARCHIVE, ns::DOS, "NOTES~1.TXT")
                .data_resident(b"hello")
                .ads_resident("hidden", b"secret-stream"),
        )
        .add(
            &RecordBuilder::new(23, 2)
                .allocated(false)
                .standard_info(t, F_ARCHIVE, 8)
                .file_name(12, 1, t, 9, 16, F_ARCHIVE, ns::WIN32, "deleted.log")
                .data_resident(b"logged..."),
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
            &RecordBuilder::new(25, 1)
                .standard_info(t, F_ARCHIVE, 10)
                .file_name(999, 7, t, 4, 8, F_ARCHIVE, ns::WIN32, "orphan.dat")
                .data_resident(b"orph"),
        )
        .finish()
}
