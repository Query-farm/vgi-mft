//! Golden fixtures asserted through the decoder: a synthetic `$MFT` with a
//! directory tree, resident + non-resident `$DATA`, multiple `$FILE_NAME`s, an
//! ADS, a deleted-but-resident record, an orphan, and the centerpiece timestomp
//! cases (SI rewound before FN, zeroed sub-second, and the rename bypass).

use std::collections::BTreeMap;

use mft_core::synth::{ns, MftBuilder, RecordBuilder, Times};
use mft_core::{resolve_path, timestomp, Decoder, ROOT_ENTRY};

const F_DIR: u32 = 0x1000_0000; // FILE_ATTRIBUTE_IS_DIRECTORY (FN flags)
const F_ARCHIVE: u32 = 0x20;

/// Build a representative `$MFT`:
/// - entry 0: `$MFT` itself (self/root-ish), present so the stride is read.
/// - entry 5: volume root `.`
/// - entry 11: `Windows` (dir, child of root)
/// - entry 12: `System32` (dir, child of Windows)
/// - entry 20: `cmd.exe` (file, resident data, child of System32)
/// - entry 21: `big.bin` (file, NON-resident data, child of System32)
/// - entry 22: `notes.txt` with a Win32 long name + DOS short name + an ADS
/// - entry 23: `deleted.log` (deleted-but-resident, child of System32)
/// - entry 24: `timestomped.exe` (SI rewound before FN — suspect)
/// - entry 25: `orphan.dat` (parent 999 missing → \$Orphan)
fn sample_mft() -> Vec<u8> {
    let t = Times::uniform_micros(1_600_000_000_500_000); // sub-second fraction

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
                .hard_links(1)
                .standard_info(t, F_ARCHIVE, 7)
                .file_name(12, 1, t, 5, 8, F_ARCHIVE, ns::WIN32, "notes.txt")
                .file_name(12, 1, t, 5, 8, F_ARCHIVE, ns::DOS, "NOTES~1.TXT")
                .data_resident(b"hello")
                .ads_resident("hidden", b"secret-stream"),
        )
        .add(
            &RecordBuilder::new(23, 2)
                .allocated(false) // deleted, but still resident
                .standard_info(t, F_ARCHIVE, 8)
                .file_name(12, 1, t, 9, 16, F_ARCHIVE, ns::WIN32, "deleted.log")
                .data_resident(b"logged..."),
        )
        .add(
            &RecordBuilder::new(24, 1)
                .standard_info(
                    // SI created/modified rewound to whole seconds in 2009.
                    Times::uniform_secs(1_230_000_000),
                    F_ARCHIVE,
                    9,
                )
                // FN created later (2020) → SI-before-FN, impossible naturally.
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

fn decoder() -> Decoder {
    Decoder::new(sample_mft()).expect("sample $MFT parses")
}

fn resolver() -> BTreeMap<u64, mft_core::ResolverNode> {
    let mut dec = decoder();
    let mut r = BTreeMap::new();
    dec.build_resolver(&mut r);
    r
}

#[test]
fn record_stride_is_1024() {
    assert_eq!(decoder().record_size(), 1024);
}

#[test]
fn resident_data_extracted() {
    let mut dec = decoder();
    let rec = dec.decode(20).unwrap().unwrap();
    assert_eq!(rec.primary_name().unwrap().name, "cmd.exe");
    assert!(!rec.is_dir);
    assert!(rec.in_use);
    let prim = rec.data.primary.as_ref().unwrap();
    assert!(prim.resident);
    assert_eq!(prim.data.as_deref(), Some(&b"MZ\x90\x00resident!"[..]));
}

#[test]
fn non_resident_data_is_size_only() {
    let mut dec = decoder();
    let rec = dec.decode(21).unwrap().unwrap();
    let prim = rec.data.primary.as_ref().unwrap();
    assert!(!prim.resident);
    assert_eq!(prim.logical_size, 1_048_576);
    assert_eq!(prim.physical_size, 1_052_672);
    assert!(prim.data.is_none());
}

#[test]
fn multiple_file_names_and_ads() {
    let mut dec = decoder();
    let rec = dec.decode(22).unwrap().unwrap();
    assert_eq!(rec.file_names.len(), 2, "Win32 long + DOS short");
    // Primary prefers the Win32 long name.
    assert_eq!(rec.primary_name().unwrap().name, "notes.txt");
    // One ADS named "hidden" with resident bytes.
    assert_eq!(rec.data.ads.len(), 1);
    let ads = &rec.data.ads[0];
    assert_eq!(ads.name.as_deref(), Some("hidden"));
    assert_eq!(ads.data.as_deref(), Some(&b"secret-stream"[..]));
}

#[test]
fn deleted_record_present_and_flagged() {
    let mut dec = decoder();
    let rec = dec.decode(23).unwrap().unwrap();
    assert!(!rec.in_use, "IN_USE clear ⇒ deleted");
    // Still resident: name + data survive.
    assert_eq!(rec.primary_name().unwrap().name, "deleted.log");
    assert_eq!(rec.data.resident_bytes(), Some(&b"logged..."[..]));
}

#[test]
fn path_reconstruction() {
    let r = resolver();
    assert_eq!(resolve_path(&r, 20, 256).path, "Windows\\System32\\cmd.exe");
    assert_eq!(resolve_path(&r, 12, 256).path, "Windows\\System32");
    assert_eq!(resolve_path(&r, ROOT_ENTRY, 256).path, ".");
}

#[test]
fn orphan_path() {
    let r = resolver();
    let res = resolve_path(&r, 25, 256);
    assert!(res.path.starts_with("\\$Orphan\\999\\"), "{}", res.path);
    assert_eq!(res.diagnostic, Some("orphan-parent"));
}

#[test]
fn timestomp_centerpiece() {
    let mut dec = decoder();
    let rec = dec.decode(24).unwrap().unwrap();
    let si = rec.standard_info.as_ref().unwrap().macb;
    let fna = rec.primary_name().unwrap().macb;
    let t = timestomp(&si, &fna);
    assert!(t.suspect, "SI rewound before FN must be suspect");
    let reasons: Vec<&str> = t.reasons.iter().map(|r| r.as_str()).collect();
    assert!(reasons.contains(&"si-creation-before-fn-creation"));
    assert!(reasons.contains(&"zero-subsecond"), "{reasons:?}");
}

#[test]
fn clean_record_not_suspect() {
    let mut dec = decoder();
    let rec = dec.decode(20).unwrap().unwrap();
    let si = rec.standard_info.as_ref().unwrap().macb;
    let fna = rec.primary_name().unwrap().macb;
    assert!(!timestomp(&si, &fna).suspect);
}

#[test]
fn baad_and_fixup_diagnostics() {
    use mft_core::decode_one;

    // A BAAD record and a fixup-mismatch record decode to diagnostics, not panics.
    let baad = RecordBuilder::new(0, 1).baad().build();
    let rec = decode_one(baad, 0).unwrap().unwrap();
    assert!(rec.diagnostics.iter().any(|d| d == "baad"));

    let torn = RecordBuilder::new(0, 1)
        .standard_info(Times::uniform_secs(1), F_ARCHIVE, 1)
        .break_fixup()
        .build();
    let rec = decode_one(torn, 0).unwrap().unwrap();
    assert!(rec.diagnostics.iter().any(|d| d == "fixup-mismatch"));
}
