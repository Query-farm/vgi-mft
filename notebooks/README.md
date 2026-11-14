# Review scope and timestamp clues

[Open the executed notebook](01_scope_and_timestamp_review.ipynb). It decodes a
synthetic NTFS Master File Table, compares SI and FN creation timestamps, displays
the worker's heuristic reasons, and traces which records and resident streams
remain when deleted entries are excluded from review.

## Run from this folder

Install [uv](https://docs.astral.sh/uv/), then:

```bash
uv sync --frozen
uv run python execute.py
```

The locked environment uses Python 3.13–3.14 and published Haybarn 2.0.0rc11.
The visible SQL contains the pinned native release:

```sql
ATTACH 'mft' (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-mft@v0.4.0');
```

VGI downloads the correct asset, verifies its checksum and caches it. Published
assets cover Apple-silicon macOS and Linux x86-64/arm64. No worker checkout, source
build, Windows host, credentials or live volume access is needed. First use needs
network access to package indexes, GitHub release assets and community extensions;
the MFT input itself is bundled locally. This folder runs independently of the
surrounding repository. To upgrade, change the literal tag and repeat both runs
and repository checks.

For an editor, register and select the notebook environment:

```bash
uv run python -m ipykernel install --user --name mft-examples \
  --display-name "Python (vgi-mft notebooks)"
```

Restart and run all after editing parameters. Python setup and plotting source are
folded; parameter, connection and analytical SQL stay visible. The runner uses a
fresh temporary kernel with this folder as cwd and writes only after success.
Overrides require a separate destination, which receives fixture, asset, helper
and environment/documentation companions. Generated artifacts are ignored.

## Scope experiment

```bash
uv run python execute.py --parameters '{"INCLUDE_DELETED":false}' \
  --output-dir validation/allocated-only
```

`INCLUDE_DELETED` accepts a Boolean, default `true`. Both runs decode the full
fixture before selecting non-directory records. Compare the coverage table,
timeline, signal matrix and resident stream count/bytes. Excluding unallocated
records removes the retained deleted log from the selected population, while
leaving the timestamps and heuristic results of retained records unchanged.
Restore `True` for the saved default. This is a review filter, not deletion or
modification of the source bytes.

## Exact fixture provenance

[fixtures/sample.mft](fixtures/sample.mft) is an unchanged 26,624-byte copy of
`data/sample.mft` at revision `577c3df0d916bc442cc22dfa50bc4394cf69c0e1`.
[provenance.json](fixtures/provenance.json) records its SHA-256 and source generator,
`crates/mft-worker/examples/gen_fixture.rs`. The notebook verifies that hash.

The generator creates a directory tree, resident and non-resident data, an alternate
data stream, a deleted resident log, a record with deliberately divergent SI/FN
timestamps, and an orphan whose parent is absent. All names, contents and timestamps
are invented. This is not an incident collection, a real disk image or a provenance
claim about any person or system. The internal fixture timestamps are not a capture
date. Hash verification identifies these exact bytes; it does not establish a
forensic chain of custody.

All decoding, timeline fields, timestamp heuristic results and stream fan-out come
from the real worker through Haybarn/VGI. Visible SQL materializes the complete
input once, selects the scope, calls the scalar heuristic and table-in-out stream
function, and reconciles their outputs. Python handles presentation only.

## Interpretation limits

NTFS FILETIME values are decoded to timezone-free SQL `TIMESTAMP` columns carrying
UTC values. The chart preserves that convention without local conversion. Its
connecting segment is the difference between two creation fields, not a lifetime.
Missing timestamps remain missing and would be excluded from the paired plot with
its coverage count displayed.

The worker flag is a heuristic. SI/FN differences and whole-second values are
review clues, not proof of tampering or attribution; all four SI fields being equal
does not alone raise the flag. The matrix keeps these reasons separate from
allocation, alternate-stream presence and path diagnostics. It is not a risk score
or a detection-quality evaluation. File names do not drive the heuristic.

A reconstructed orphan path is not a verified live-volume location. Deleted does
not mean content is absent. Conversely, non-resident logical size does not mean
those bytes were recovered: the worker does not follow runlists into disk clusters.
The stream table can have more or fewer rows than the record table, so counts are
aggregated by entry before joining. The `$MFT` record itself remains in this
non-directory population; directory records are excluded explicitly.

See the pinned [worker README](https://github.com/Query-farm/vgi-mft/blob/577c3df0d916bc442cc22dfa50bc4394cf69c0e1/README.md)
and [STANDARD.md](STANDARD.md).
