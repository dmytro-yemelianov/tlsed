# Final aligned volatile-wipe client fuzz evidence

Final source passed **23,054 Rust-ASan/libFuzzer executions in16 seconds** on
2026-10-14, Apple M5 ARM64/macOS27.2, nightly-2026-09-17/cargo-fuzz0.13.1.
Requested budget15 seconds, seed71515, max input4096. Fresh corpus starts from
all28 retained milestone4 files (27 nonempty plus one empty), with no generated
corpus reused. [Raw log](client_engine.log), [metadata](run.json),
[source/fixture/seed hashes](source-hashes.sha256) and
[native coverage diagnostic](native-sanitizer-check.txt) identify the campaign.

The unchanged client_engine target exercises bounded raw traces and authenticated
local maintained-rustls peers with real cryptography: three suites, two groups/HRR,
partial/zero output, partial plaintext reads, KeyUpdate, application bytes,
mutation/CCS/EOF/close and accepted-loan Drop erasure. This exercises the client
aligned volatile-wipe helper and pinned bytemuck1.25.2 view. Fuzzer payloads remain
bounded to512 bytes; deterministic regressions separately inspect16KiB records,
unaligned caller loans and outside guards. No socket/Internet target is involved.

Native sanitizer flags remain unset; both retained AWS-LC archives have zero
undefined ASan/sanitizer references. Native C/assembly coverage remains
unestablished. Short Rust crash-free fuzzing does not prove TLS security, full
coverage, erasure or deployment readiness. RNG and scheduling change counts,
so counts from different fuzzer seeds are not optimization throughput evidence.

To reproduce starting conditions, copy every file from
`fuzz/results/2026-10-14-milestone4/client-engine-seeds/` into a new empty corpus
folder and run:

```sh
cargo +nightly-2026-09-17 fuzz run client_engine /path/to/fresh-corpus -- -max_total_time=15 -max_len=4096 -seed=71515
```

Historical manifests point changed source/lock/proof paths to exact retained
snapshots. The compiler-resistant erasure implementation and timing scope are
in [the measured report](../../../docs/SECRET_WIPING.md).
