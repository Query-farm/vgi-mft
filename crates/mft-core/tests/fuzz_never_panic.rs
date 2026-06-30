//! Zero-panic property test: the decoder must NEVER panic on arbitrary or
//! truncated bytes — a `$MFT` collected from a compromised or failing host can
//! be corrupt or hostile. Every entry point is exercised against random buffers
//! and against mutilated copies of a valid record.

use mft_core::synth::{ns, RecordBuilder, Times};
use mft_core::{decode_one, full_path, record_header, well_formed, Decoder};
use proptest::prelude::*;

/// Install the quiet-parser-panic hook once, so any caught upstream panic does
/// not flood the test output (the assertion is simply "we did not abort").
fn init() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(mft_core::quiet_parser_panics);
}

/// Drive every public entry point over `bytes` for entry indices around 0.
fn exercise(bytes: &[u8]) {
    init();
    for n in [0u64, 1, 2, 5, 7, 100, u64::MAX] {
        let _ = record_header(bytes.to_vec(), n);
        let _ = well_formed(bytes.to_vec(), n);
        let _ = decode_one(bytes.to_vec(), n);
        let _ = full_path(bytes.to_vec(), n, 256);
        if let Ok(mut dec) = Decoder::new(bytes.to_vec()) {
            let _ = dec.decode(n);
            let _ = dec.raw_entry(n);
            let mut resolver = std::collections::BTreeMap::new();
            dec.build_resolver(&mut resolver);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Arbitrary byte buffers of any length never panic.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        exercise(&bytes);
    }

    /// A valid record truncated at any length never panics.
    #[test]
    fn truncated_valid_record_never_panics(cut in 0usize..1024) {
        let rec = RecordBuilder::new(0, 1)
            .standard_info(Times::uniform_secs(1_600_000_000), 0x20, 1)
            .file_name(5, 5, Times::uniform_secs(1_600_000_000), 5, 8, 0x20, ns::WIN32, "x.txt")
            .data_resident(b"hello")
            .build();
        exercise(&rec[..cut]);
    }

    /// A valid record with a single mutated byte never panics (bit-flip fuzz of
    /// lengths, offsets, the fixup, and attribute headers).
    #[test]
    fn single_byte_flip_never_panics(pos in 0usize..1024, val in any::<u8>()) {
        let mut rec = RecordBuilder::new(0, 1)
            .standard_info(Times::uniform_secs(1_600_000_000), 0x20, 1)
            .file_name(5, 5, Times::uniform_secs(1_600_000_000), 5, 8, 0x20, ns::WIN32, "x.txt")
            .ads_resident("ads", b"streamy")
            .data_non_resident(4096, 8192)
            .build();
        rec[pos] = val;
        exercise(&rec);
    }
}
