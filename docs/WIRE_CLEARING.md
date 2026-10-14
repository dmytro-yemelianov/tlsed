# Public wire-buffer clearing — measured follow-up

Latest source: [aligned volatile secret wiping](SECRET_WIPING.md) resolves the
remaining receive hotspot while preserving erasure. This report retains its
historical source-specific timings and validation counts.

After the two [plaintext backing optimizations](READ_OPTIMIZATION.md), two
remaining public wire clears were profiled and changed. AES128/X25519 16 KiB
transmit improves **1.640x** and receive **1.475x** against that already optimized
engine. Transmit is now **1.018x native rustls pair time**; receive remains
**1.538x**. This is the next local step, not a cumulative ratio derived by
multiplying independent experiments.

## Change and classification

`ClientConnection::receive_record` clears the completed network prefix using
`fill(0)` after successful processing. This buffer receives only caller network
bytes and is passed immutably to processing. ProtectedReader copies ciphertext
into a separate plaintext loan before decryption. No plaintext/key writer
mutates the wire loan. Failed processing still zeroizes its entire capacity.

`drain_output` copies a queued range to caller output and fills exactly that
consumed range with zero. A positive `out_len` publishes only an encoded
ClientHello, a successfully sealed record, or an initial plaintext fatal alert.
The finished wire bytes are already peer-visible. Pending suffixes, output
backpressure, Finished handoff and nonce/key sequencing are unchanged.

These ordinary fills preserve the live buffer's observable zero state, including
partial drains. They do **not** retain zeroize's compiler-resistant erasure
property for these public bytes. Outbound storage temporarily contains sensitive
plaintext during sealing; failed seals/core cleanup, abort and full Drop retain
`zeroize`. Plaintext consumption, keys, secrets, handshake buffers and constructor
clearing also retain `zeroize`. Neither authentication/PKI nor provider primitives,
record limits or key-use limits changed.

## Profiling evidence

The harness adds optional `--only bulk-tx-16384` / `bulk-rx-16384` diagnostics;
default `all` keeps the existing nine workloads. Both canonical before/after
binaries use the identical harness with that filter. The prior executable is
preserved separately; the new before binary was built before the engine edit.

Two independent two-second Apple `sample` windows observe TLSed 16 KiB pair
traffic. TX contains 554/1409 main-thread samples directly in the outgoing
clear loop; RX contains 397/1493 in successful wire clearing, plus 406 in the
separate consumed-plaintext clearing loop. The retained disassembly confirms
byte-store/decrement/branch loops at these locations. These are sampled narrow
windows including transport/server/output work, not calibrated whole-run CPU
percentages. Partial diagnostic CSVs are deliberately terminated and excluded
from all performance summaries.

After the change, sampled public clearing calls use platform memset and the old
large wire loops disappear from these hotspots. Receive plaintext clearing remains
prominent. Removing its compiler-resistant wiping would change the secret contract;
that is not part of this change. Copies and maintained encryption/decryption remain
visible. [CPU samples, disassembly and exact diagnostic commands](../crates/tls-bench/results/2026-10-14-wire-clearing/)
are retained for source review, including the shared native-server allocation path.

## Paired results

Six paired repeats alternate version and TLSed/native order in fresh processes.
Each process keeps the identical native server and strict native-client control.
There are 100 samples per workload, 256 records per bulk batch, three profiles,
36 successful processes and **64,800 observations**. Compilation, fuzzing and
agent builds were stopped during timing. Every bulk record's authenticated
plaintext is compared exactly. Configuration/fixture generation is outside timing;
handshake/lifecycle construction domains remain as previously documented.

Times below are medians of process medians divided by the 256-record batch.
Speedups are medians of six paired ratios, so aggregated column ratios can differ.
These are batch-average endpoint-pair costs, not individual record latency or
isolated client CPU.

| AES128/X25519 | Before µs/record | After µs/record | Native µs/record | Paired speedup (range) | After/native time |
|---|---:|---:|---:|---:|---:|
| Transmit 64 B | 0.209 | 0.200 | 0.224 | 1.056x (1.030–1.089) | 0.892x |
| Transmit 1 KiB | 0.691 | 0.449 | 0.471 | 1.535x (1.523–1.554) | 0.951x |
| Transmit 16 KiB | 9.312 | 5.650 | 5.549 | 1.639x (1.585–1.763) | 1.018x |
| Receive 64 B | 0.220 | 0.201 | 0.215 | 1.109x (1.062–1.117) | 0.934x |
| Receive 1 KiB | 0.911 | 0.667 | 0.458 | 1.353x (1.330–1.405) | 1.455x |
| Receive 16 KiB | 11.721 | 7.831 | 5.083 | 1.475x (1.459–1.516) | 1.538x |

The 16 KiB transmit/receive gains normalized by each repeat's native control are
1.648x/1.461x. The paired ranges stay above parity. ChaCha20 16 KiB transmit/receive
improve 1.217x/1.189x and finish at 1.004x/1.162x native pair time. With 64-byte
network fragments, AES128 16 KiB improves 1.408x/1.141x and finishes at
0.727x/0.980x; fragment driver/Vec costs contribute to those workload-specific ratios.
Handshake/lifecycle gains cross parity and have no improvement claim.

This is Apple M5 ARM64 on AC power, without affinity/frequency/scheduler isolation.
Pooled CV reaches 43.60% in AES128 and 55.27% in ChaCha because some observations
have long tails; retain raw samples, percentiles and pair ranges rather than
claiming universal superiority from medians. The explicit remaining large receive
gap and roughly 1.36x connection-lifecycle gap require separate work.

[Paired ratios](../crates/tls-bench/results/2026-10-14-wire-clearing/paired/before-after.csv),
[commands and binary hashes](../crates/tls-bench/results/2026-10-14-wire-clearing/paired/run.json),
[before source hashes](../crates/tls-bench/results/2026-10-14-wire-clearing/before-source-hashes.sha256),
[after source/proof hashes](../crates/tls-bench/results/2026-10-14-wire-clearing/after-source-hashes.sha256)
and [host controls](../crates/tls-bench/results/2026-10-14-wire-clearing/environment.txt)
identify this experiment. Exact source snapshots are stored with the results;
historical manifests redirect changed files to byte-identical archived snapshots.

```sh
python3 crates/tls-bench/compare_versions.py \
  --before /path/to/pre-wire-change/client_compare \
  --after target/release/client_compare \
  --output crates/tls-bench/results/NEW_PAIRED_RUN \
  --repeats 6 --samples 100 --bulk-records 256
```

## Assurance

[WireClearing.lean](../lean/Tls13/WireClearing.lean) adds ten standalone theorems:
independently modeled sequential byte stores equal range fill; bounds,
zero/partial/complete drains and untouched suffixes hold; exact changed support
is minimal under a live consumed-bytes-zero contract. The mandatory touched-region
lower bound assumes consumed bytes initially nonzero: already-zero bytes need not
be stored again merely to meet that final-state contract. This is a byte-state/
footprint result, not CPU optimality or volatile/compiler erasure verification.
Public-data classification, Rust/provider/slice fidelity and noalias remain external
obligations. The six linked production helpers and their 21 theorems are unchanged.
All **148 audited closures = 127 model + 21 linked** use only standard foundations.

[Three new private-buffer regressions](../crates/tls-client/src/wire_wiping_unit.rs)
use actual authenticated AWS-LC/rustls peers. They inspect partial/zero ClientHello,
Finished and large-to-short application drains; preserve exact queued suffixes;
require the native peer to authenticate/recover assembled wire; inspect fragmented
incoming wire before completion and whole-loan zero afterward; and require
full-capacity wipe/no release on a tampered final byte. Nonzero extra-capacity loans
also verify constructor/Drop clearing. Existing partial-read, HRR/KeyUpdate,
nonce/alert/provider-fault regressions remain in debug and release.

[Final checks](../verification/results/2026-10-14-wire-clearing/checks.json) pass
112 Rust unit/integration tests, 14 compile-fail doctests, 24 client tests in release,
formatting, strict Clippy, proof source guard and translation freshness. Rust/Lean
agreement still passes 4,923 cases across ten operations. The fresh
[Rust-ASan campaign](../fuzz/results/2026-10-14-wire-clearing/README.md) passes
14,546 executions in 16 seconds; native C/assembly sanitizer coverage remains
unestablished. No complete engine refinement, external audit or broader platform/
server/OpenSSL endpoint gate follows from this local result.

See [the source comparison](SOURCE_COMPARISON.md) for the measured next targets
and separate rustls/webpki hypotheses with their memory/policy obligations.
