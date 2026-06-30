# CI: the vgi-mft worker integration suite

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs fmt/clippy/build,
the Rust unit + integration tests, and this repo's sqllogictest suite
(`test/sql/*.test`) against the vgi-mft VGI worker through the **real DuckDB
`vgi` extension** on every push / PR.

## Transport matrix

The integration suite runs over **every transport the vgi extension supports**.
The exact same `test/sql/*.test` files run three ways; the only thing that
changes is what LOCATION the `.test` files `ATTACH` (set by
[`run-integration.sh`](run-integration.sh) from the `TRANSPORT` env var):

| `TRANSPORT`  | `VGI_MFT_WORKER` (the ATTACH LOCATION) | how the worker is launched |
|--------------|----------------------------------------|----------------------------|
| `subprocess` | `…/target/release/mft-worker`          | DuckDB spawns the stdio binary (default) |
| `http`       | `http://127.0.0.1:<port>`              | `mft-worker --http` (auto port; prints `PORT:<n>` on stdout) |
| `unix`       | `unix:///tmp/mft.<pid>.sock`           | `mft-worker --unix <sock>` (prints `UNIX:<sock>` + creates the socket) |

CI runs `transport: [subprocess, http, unix]` × `os: [ubuntu, macos]` as a
matrix. Build the worker once with a plain `cargo build --release` — the
workspace already pins `vgi-rpc = { features = ["macros", "http"] }`, so the one
binary serves all three transports; **no extra cargo feature is needed**.

The `http` leg additionally needs DuckDB's `httpfs` (the vgi extension's HTTP
client is built on it); [`preprocess-require.awk`](preprocess-require.awk)
injects a signed `INSTALL httpfs FROM core; LOAD httpfs;` after each `LOAD vgi;`
on that leg so a missing `httpfs` fails loudly rather than being silently
auto-skipped.

## Fixtures

The `.test` files read a committed synthetic `$MFT` at `data/sample.mft`,
referenced via `${VGI_MFT_DATA}` (exported by `run-integration.sh` as the repo's
`data/` dir) so the path resolves regardless of the runner's cwd. Regenerate it
with `cargo run -p mft-worker --example gen_fixture`.

## Running locally

```bash
cargo build --release
# point HAYBARN_UNITTEST at a downloaded haybarn-unittest binary
HAYBARN_UNITTEST=/path/to/haybarn-unittest TRANSPORT=subprocess ci/run-integration.sh
```
