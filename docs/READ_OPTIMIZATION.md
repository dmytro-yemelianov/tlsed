# Measured plaintext-buffer optimization

Latest source: [aligned volatile secret wiping](SECRET_WIPING.md) resolves the
remaining receive hotspot while preserving erasure. This report retains its
historical source-specific timings and validation counts.

Latest follow-up: [public wire clearing](WIRE_CLEARING.md) has separate paired
measurements against the already optimized engine. This report retains its
historical source-specific measurements and validation counts.

Two small engine changes remove repeated clearing while retaining the declared
memory and authentication behavior. In the final paired AES128/X25519 run,
64-byte receive improves **36.54x**,1KiB **9.17x**, and16KiB **1.34x** against
the preserved original binary.64-byte receive is now about **1.03x native
rustls pair time**, rather than the earlier36x gap. Larger records remain slower.

## Changes and invariants

1. `ClientConnection::read_plaintext` clears the precise consumed range. Once
   all content has been read, its prefix has already been cleared and the core
   has cleared the tail. The repeated final whole-loan wipe was removed.
2. `process_record` lends `ProtectedReader::open` only the actual ciphertext
   payload prefix, obtained by checked subtraction of the five-byte header and
   `get_mut` bounds checking. Untouched backing is already clean. Core success
   still clears type, padding and tag through the active prefix. A debug
   assertion checks initial whole backing cleanliness before every protected open.

`ProtectedReader` itself is unchanged. Each provider receives the same actual
ciphertext slice as before. Full error/abort/Drop, handshake-completion and
control-message wipes remain. No read API, verification, key/nonce limit,
cryptographic primitive or record limit was relaxed. `drive` blocks new input
while application plaintext remains unread or handshake plaintext remains
pending; zero-length and partial reads preserve that gate. CCS does not mutate
plaintext; other completed control messages clear it fully.

These rules establish the full-loan invariant: its consumed prefix and tail
are zero; only unread authenticated content may be nonzero. On completion the
whole backing is zero and can start another active-prefix record operation.
For a64-byte unpadded record, the former core cleared16576 tail bytes and the
reader additionally cleared the entire16640-byte loan. The active-prefix core
now clears17 type/tag bytes, and the reader clears64 consumed content bytes.
Actual wire-buffer clearing and nonce/secret retirement remain separate.

## Paired measurements

The final comparison alternates old/new binary order and tlsed/native order
across six paired repeats. Each version runs in a fresh process and retains its
own identical-server/native-client control.100 samples per workload,256 records
per bulk batch, three profiles and36 processes yield64800 observations. Before
and after bytes are authenticated and compared exactly; no competing agent
compilation/fuzzing runs during timing.

Table times are medians of process medians, divided by256 for receive batches.
Speedups are medians of six paired ratios, so ratios of the separately aggregated
time columns can differ slightly. They are batch-average pair costs, not
individual record-latency quantiles.

| AES128/X25519 receive | Before µs/record | After µs/record | Native control µs/record | Speedup, repeat range | After/native time |
|---|---:|---:|---:|---:|---:|
|64 B |8.090 |0.223 |0.217 |36.540x (35.540–36.777) |1.031x |
|1KiB |8.622 |0.941 |0.469 |9.168x (8.927–9.230) |2.010x |
|16KiB |15.791 |11.742 |5.170 |1.344x (1.340–1.351) |2.271x |

Normalizing each paired old/new ratio by its native control yields36.235x,
9.132x and1.342x respectively. This supports the same large/small receive
effect even with host noise. Transmit time is unchanged within small differences;
fresh/reused handshake ratios cross parity in some repeats and have no isolated
speed claim. Constructor and Drop still clear their full storage.

| Other profile |64 B receive speedup |1KiB receive speedup |16KiB receive speedup |64 B after/native |
|---|---:|---:|---:|---:|
|ChaCha20/X25519 |18.265x |4.904x |1.161x |1.032x |
|AES128/X25519,64-byte network fragments |33.901x |7.702x |1.083x |0.911x |

The fragmented workload includes Vec shifting and additional driver calls;
its small apparent advantage is workload-specific. ChaCha1KiB repeat speedups
range3.04–6.36x; keep those raw observations rather than treating every median
as equally precise. Host affinity, frequency and scheduler isolation are not
controlled. One native16KiB transmit pooled CV is49.35%; bulk medians, paired
controls and complete repeat ranges are reported, with no blanket transmit win.
This is a local M5 experiment with shared strict PKI, not portable superiority,
isolated client CPU, Internet latency or identical full endpoint behavior.

Stage1 was measured independently before stage2: removing only the final
whole-loan read wipe improved64B/1KiB/16KiB receive1.96x/1.89x/1.34x.
Stage1's raw64800 observations and preserved source/proof snapshots remain in
[its result directory](../crates/tls-bench/results/2026-10-14-read-wipe-optimization/).
Final stage2 compares the original pre-optimization binary with both changes,
so these stage gains must not be multiplied from independent noisy runs.

Retained final [paired ratios](../crates/tls-bench/results/2026-10-14-active-slice-optimization/before-after.csv),
[after summary](../crates/tls-bench/results/2026-10-14-active-slice-optimization/aes128-x25519/after-summary.csv),
[commands/binary hashes](../crates/tls-bench/results/2026-10-14-active-slice-optimization/run.json),
[source/fixture/proof hashes](../crates/tls-bench/results/2026-10-14-active-slice-optimization/after-source-hashes.sha256)
and [environment](../crates/tls-bench/results/2026-10-14-active-slice-optimization/environment.txt)
identify the run. Exact before/after production-source snapshots and raw CSVs
are stored alongside them. Binaries are retained locally under ignored target
paths; source hashes and binary hashes are portable evidence artifacts.

To rerun after building the respective source snapshots with the same toolchain:

```sh
python3 crates/tls-bench/compare_versions.py \
  --before /path/to/original/client_compare \
  --after target/release/client_compare \
  --output crates/tls-bench/results/NEW_PAIRED_RUN \
  --repeats 6 --samples 100 --bulk-records 256
```

## Lean and Rust evidence

Lean adds25 byte-memory model theorems:

- [Zeroization](../lean/Tls13/Zeroization.lean):14 theorems for exact consumed
  clears, zero/partial read progress, representable offset arithmetic,
  multi-read invariant preservation, full-loan zero at completion and equality
  after a redundant final wipe.
- [PlainBacking](../lean/Tls13/PlainBacking.lean):11 theorems for prefix-only
  mutation, untouched-backing cleanliness, full-tail recombination and arbitrary
  completed-record/full-clear/identity cycles. Incomplete reads do not authorize
  another record boundary.

All138 theorem audits pass:117 standalone model plus21 linked over the same six
production guards, using only standard foundations. This is a model proof of
the optimization's state equivalence under explicit initial cleanliness,
provider footprint, byte-write fidelity, noalias and admission-gate assumptions.
The actual Rust engine/provider/slice/zeroization orchestration is tested and
reviewed, not translated/refined. No CPU-optimality, complete erasure,
constant-time or whole TLS-security proof follows. The existing fixed-record
count and mandatory-label-footprint linked optimality claims remain unchanged.

[Private-buffer regression](../crates/tls-client/src/read_wiping_unit.rs)
inspects the whole live loan after an actual verified native handshake, open,
every partial/zero read and authentication failure. It checks preserved unread
bytes, exact caller output, clean tails/prefixes and fully clean completion,
using extra-capacity nonzero-seeded buffers and large-to-short records.
[Four public regressions](../crates/tls-client/tests/read_wiping.rs) cover unread
input backpressure, partial reads, live Drop, tamper/EOF refusal and all-loan
Drop erasure. Existing HRR/KeyUpdate/fault/alerts/identity tests still pass.

Final [checks](../verification/results/2026-10-14-active-slice/checks.json)
pass109 Rust unit/integration tests,14 compile-fail doctests,21 client tests
in release, formatting, strict workspace Clippy, proof source guard and unchanged
translation freshness. [The final Rust-ASan campaign](../fuzz/results/2026-10-14-active-slice/README.md)
passes11759 executions in16 seconds from fresh retained seeds. AWS-LC native
C/assembly sanitizer coverage remains unestablished.

Next measured targets are the remaining larger-record copy/clearing costs and
connection construction/Drop. Their security effects and allocation domains
need profiling before another change; neither strong secret wiping nor PKI
policy will be dropped to improve a number. Server/mTLS and broader platform/
OpenSSL endpoint gates remain open.
