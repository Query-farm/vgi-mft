# vgi-mft

Parse the NTFS **`$MFT`** (Master File Table) into a forensic filesystem
timeline — directly in DuckDB SQL, at fleet scale, with **zero egress**.

`vgi-mft` is a [VGI](https://query.farm) worker (the seed of a Windows-DFIR
bundle alongside `vgi-evtx`). It turns a collected `$MFT` blob or a glob of
`$MFT` dumps into one wide row per FILE record: the path reconstructed from
parent-reference chains, both the `$STANDARD_INFORMATION` (SI) and `$FILE_NAME`
(FN) **MACB** timestamp quads — so the **timestomp** mismatch that exposes
anti-forensic tampering is a plain `WHERE` clause — logical/physical sizes,
allocated/deleted and file/dir flags, **alternate data streams** (ADS), and
inline **resident** file content.

The value is fleet-scale, in-SQL triage: timeline thousands of collected `$MFT`s
and join the result to known-bad paths, hashes, CVEs, YARA/Sigma rules, and
leaked-secret patterns in one query — the compute a per-host CLI gives you one
CSV at a time, glued together by hand. The worker opens no socket, reads no
secret provider, and calls nothing: it only ever parses the bytes you already
collected — safe for air-gapped / chain-of-custody evidence.

## Quick start

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'mft' AS mft (TYPE vgi, LOCATION '/path/to/mft-worker');
SET search_path = 'mft.main';
```

## SQL surface

```sql
-- 1. Read a collected $MFT into a full forensic timeline (one row per FILE record).
SELECT t.entry, t.full_path, t.is_dir, t.is_deleted,
       t.si_created, t.si_modified, t.fn_created, t.fn_modified,
       t.logical_size, t.ads_name
FROM read_mft('/cases/IR-2026-04/host01/$MFT') AS t
ORDER BY t.si_modified DESC;

-- 2. Timestomp hunt across an estate: SI created EARLIER than FN created,
--    or a zero-microsecond SI tell — both classic anti-forensic signatures.
SELECT host, full_path, si_created, fn_created
FROM read_mft('s3://collections/*/$MFT', host := 'estate') AS t   -- glob: one file per host
WHERE t.is_allocated
  AND ( t.si_created < t.fn_created                       -- SI predates FN: impossible naturally
     OR date_part('microsecond', t.si_modified) = 0 )     -- automated-tool sub-second tell
ORDER BY host;

-- Or just use the convenience flag, which folds the heuristic into a boolean:
SELECT full_path, si_created, fn_created
FROM read_mft('/cases/host01/$MFT')
WHERE is_timestomp_suspect;

-- 3. List deleted records still resident in the table (recoverable artifacts).
SELECT entry, sequence, full_path, logical_size, fn_modified
FROM read_mft('/cases/host01/$MFT')
WHERE is_deleted AND NOT is_dir;

-- 4. Surface every alternate data stream (a classic malware hiding spot),
--    then join hidden paths to a known-bad IOC table — fleet-wide, one query.
SELECT t.host, t.full_path, t.ads_name, t.logical_size
FROM read_mft('/cases/host01/$MFT', mode := 'streams') AS t
WHERE t.ads_name IS NOT NULL;            -- non-default $DATA streams only

-- 5. Carve resident file content (small files live inside the MFT record itself).
SELECT entry, full_path, resident_data
FROM read_mft('/cases/host01/$MFT')
WHERE resident_data IS NOT NULL AND full_path LIKE '%\Temp\%';
```

### `read_mft(glob_or_blob, host := NULL, mode := 'files')`

The headline table function. The first argument is a **VARCHAR path or glob**
(`'/cases/*/$MFT'`) or a **`BLOB`** of `$MFT` bytes. `host :=` scopes a
collection (defaults to the source filename); `mode :=` is `'files'` (one row per
record, the default), `'streams'` (one row per `$DATA` stream — primary + each
ADS), or `'allocated'` (live files only). Deleted-but-resident records are
**included by default** — filter with `WHERE is_allocated` for live files only.

Returns one wide row per FILE record: `entry`, `sequence`, `parent_entry`,
`full_path`, `file_name`, `is_dir`, `is_allocated`, `is_deleted`, the SI quad
(`si_created` / `si_modified` / `si_accessed` / `si_mft_modified`), the FN quad
(`fn_*`), `logical_size`, `physical_size`, `hard_link_count`, `dos_attributes`,
`ads_name`, `resident_data`, `is_timestomp_suspect`, and `diagnostics`.

### Scalars (over a `(blob, entry)` pair)

```sql
-- Pass the $MFT bytes as a BLOB (e.g. from DuckDB's read_blob table function).
WITH m AS (SELECT content AS b FROM read_blob('/cases/host01/$MFT'))
SELECT
  mft_record((SELECT b FROM m), 5),        -- full lossless STRUCT decode of a record
  full_path((SELECT b FROM m), 5),         -- path reconstruction for one entry
  record_header((SELECT b FROM m), 0).*,   -- cheap FILE-header probe (LSN, flags, sizes)
  well_formed((SELECT b FROM m), 0).*;     -- validate; never panics on corrupt input

SELECT mft_version();                       -- the running worker version

-- The timestomp heuristic as a pure scalar, scoring multiple reasons:
SELECT timestomp(
  {'created': si_created, 'modified': si_modified,
   'accessed': si_accessed, 'mft_modified': si_mft_modified},
  {'created': fn_created, 'modified': fn_modified,
   'accessed': fn_accessed, 'mft_modified': fn_mft_modified}).*
FROM read_mft('/cases/host01/$MFT');
```

### Attribute / stream fan-out (relation in / table out)

DuckDB table functions cannot take correlated column arguments, so the
`mft_dump`-style deep views are **table-in-out** functions: pass a relation
carrying a `blob` BLOB column and an `entry` UBIGINT column.

```sql
-- Every attribute of one record:
SELECT * FROM attributes((FROM (
  SELECT content AS blob, 5::UBIGINT AS entry FROM read_blob('/cases/host01/$MFT'))));

-- Every $DATA stream (primary + each ADS) of one record:
SELECT * FROM streams((FROM (
  SELECT content AS blob, 5::UBIGINT AS entry FROM read_blob('/cases/host01/$MFT'))));
```

## How it works

`vgi-mft` is built on the permissively-licensed [`mft`
crate](https://crates.io/crates/mft) (omerbenamram — also the author of the
`evtx` crate behind `vgi-evtx`), which owns the per-record byte-slicing, fixup
application, and header validation. `vgi-mft` owns the **path-reconstruction
resolver** (`\$Orphan` / `\$Cycle` handling, depth- and cycle-bounded), the
normalized timeline schema, the **externalized byte-offset scan state** (a
serde-serializable cursor + parent-resolver index carried across DuckDB batches
and HTTP rehydration), the **SI-vs-FN timestomp heuristic**, and the SQL surface.

**Untrusted-input discipline.** A `$MFT` collected from a compromised or failing
host can be corrupt or hostile, so every record decodes inside a per-record
catch — a malformed record yields a row with `diagnostics` set, the scan never
aborts, and a property test asserts the parser **never panics** on arbitrary or
truncated bytes (with bounded allocation: a record claiming a 4 GB resident
`$DATA` allocates nothing).

## Non-goals (v1)

No live disk / volume-image reading (the worker parses a collected `$MFT` blob,
not a mounted NTFS volume), so non-resident `$DATA` runlists are reported by size
but not followed into clusters; no `$Secure`/SID-to-owner resolution; no
directory-index B-tree reconstruction. The NTFS-journal siblings (`$UsnJrnl`,
`$LogFile`) are on the roadmap as separate workers.

## Development

```bash
cargo build --release                     # build the worker binary
cargo test --workspace                    # unit + golden + zero-panic fuzz tests
cargo run -p mft-worker --example gen_fixture   # regenerate data/sample.mft

# SQL end-to-end across every transport (needs a haybarn-unittest binary):
HAYBARN_UNITTEST=/path/to/haybarn-unittest TRANSPORT=subprocess ci/run-integration.sh
```

See [ci/README.md](ci/README.md) for the transport matrix and [CLAUDE.md](CLAUDE.md)
for the architecture.

## License

MIT — see [LICENSE](LICENSE). Copyright 2026 Query Farm LLC — https://query.farm
