# CLAUDE.md — vgi-mft

A VGI worker that parses the NTFS `$MFT` into a forensic filesystem timeline in
DuckDB over Apache Arrow. Catalog `mft`, schema `main`.

## Workspace layout

Two crates (`*-core` pure engine + `*-worker` Arrow adapter), mirroring the
`vgi-fixedformat` / `vgi-units` fleet template.

```
crates/mft-core/         # pure NTFS engine — no Arrow, no VGI, no I/O policy
  src/
    filetime.rs          # jiff::Timestamp (FILETIME) → Option<i64> µs; zero-subsecond tell
    standard_info.rs     # $STANDARD_INFORMATION (0x10): SI MACB + DOS attrs + USN
    file_name.rs         # $FILE_NAME (0x30): parent ref, FN MACB, name + namespace
    data.rs              # $DATA (0x80) streams + the generic attribute view
    record.rs            # FILE-record decode + the allocation-bounded attribute pre-scan
    parse.rs             # panic-safe parse (catch_unwind backstop) + quiet panic hook
    resolver.rs          # parent-reference path walk; \$Orphan / \$Cycle, depth/cycle bound
    cursor.rs            # MftScanState / MftCursor / ResolverNode — the §C serde scan state
    timestomp.rs         # the SI-vs-FN heuristic + reasons (THE DFIR value)
    errors.rs            # well_formed kinds; per-record diagnostics
    synth.rs             # byte-accurate synthetic $MFT builder (feature `synth`, test-only)
    lib.rs               # Decoder over a $MFT buffer + the scalar entry points
  tests/golden.rs        # decode/path/timestomp/deleted/ADS golden assertions
  tests/fuzz_never_panic.rs  # proptest: NEVER panics on arbitrary/truncated/flipped bytes

crates/mft-worker/       # thin Arrow adapter + VGI registration
  src/
    main.rs              # catalog metadata + Worker registration
    meta.rs              # vgi-lint per-object metadata helpers
    arrow_io.rs          # BLOB / UBIGINT cell readers; timestamp-unit scaling
    arrow_map.rs         # §B timeline schema + EmitRow batch builder + mft_record STRUCT
    options.rs           # read_mft arg parsing (path/glob/blob, host, mode) + glob expand
    scalar/              # mft_record, full_path, timestomp, record_header, well_formed, version
    table/read_mft.rs    # the headline table fn + producer with the externalized cursor
    table_in_out/        # attributes, streams (relation in / fanned table out)
  examples/gen_fixture.rs  # writes data/sample.mft
```

## Key design decisions

- **Engine vs. adapter.** All correctness (decode, path reconstruction,
  timestomp, scan state) lives in `mft-core` and is unit-tested directly without
  Arrow or RPC. The worker crate only maps to/from Arrow.
- **Panic-safety is a hard gate.** The upstream `mft` crate is *not* panic-safe
  on hostile input (stride-arithmetic overflow, fixup underflow, a 4 GB resident
  `$DATA` allocation, a zero-length-attribute infinite loop). `mft-core` slices
  records itself, runs a cheap allocation-free attribute **pre-scan**
  (`attributes_within_bounds`) before the crate ever allocates, and wraps both
  the record parse *and* the attribute content decode in `catch_unwind`. The
  `fuzz_never_panic` proptest is the gate; `quiet_parser_panics()` suppresses the
  (caught) third-party panic noise on stderr.
- **Externalized cursor (§C).** `read_mft` streams across DuckDB batches and
  (HTTP transport) survives worker tear-down: `MftScanState` is plain owned data
  (byte-offset cursor + parent-resolver index + explicit `source_index`),
  round-tripped via `encode_resume` / `restore_resume`. **Gotcha learned:** the
  end-of-scan state must carry the source index explicitly — matching the source
  by *label* let an exhausted scan restart from source 0 and loop forever under
  HTTP. There is a serde round-trip test and a producer resume test.
- **`attributes` / `streams` are table-in-out, not table functions.** DuckDB
  table functions reject correlated column args ("only supports literals"), so
  per-`(blob, entry)` fan-out is delivered as a relation-in/table-out function:
  `FROM mft.attributes((FROM (SELECT blob, entry)))`. The per-record scalars
  (`mft_record`, `full_path`, …) take `(blob, entry)` column args directly.
- **`read_mft` arg is a literal** (a VARCHAR path/glob or a const BLOB), per the
  same table-function constraint — pass blobs as a literal / `read_blob(...)`.

## Conventions (fleet)

- **LICENSE = MIT** (the whole built fleet is MIT; the spec's "source-available"
  line is superseded).
- Catalog name defaults to `mft` via `VGI_WORKER_CATALOG_NAME`.
- `read_text` is a DuckDB *table* function, not a scalar — pass `$MFT` bytes via
  `read_blob(...).content` or a literal BLOB, never `read_text(...)` as an arg.
- Built on `omerbenamram/mft` (MIT/Apache-2.0); permissive tree only.

## Gates (all green)

```bash
cargo build --release
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
# metadata: uvx --prerelease=allow --from vgi-lint-check vgi-lint lint <bin> --execute --ai --ai-concurrency 1 --fail-on info
# SQL E2E: ci/run-integration.sh over TRANSPORT=subprocess|http|unix
```

The `http` E2E exercises the cursor/resolver resume round-trip; run the linter
and the E2E from the **repo root** (the `data/sample.mft` fixture is referenced
repo-relative).
