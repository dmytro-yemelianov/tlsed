# Optimized client fuzz evidence

Final source passed11759 Rust-ASan/libFuzzer executions in16 seconds on
2026-10-14, Apple M5 ARM64/macOS27.2, nightly-2026-09-17/cargo-fuzz0.13.1.
Requested budget15 seconds, seed71513, max input4096, fresh copy of28 retained
milestone4 seeds (27 nonempty plus one empty); no generated corpus was reused.
See [raw log](client_engine.log), [metadata](run.json),
[source/fixture/seed hashes](source-hashes.sha256) and
[native coverage diagnostic](native-sanitizer-check.txt).

The unchanged client_engine target runs bounded raw/codec/loan traces and actual
authenticated maintained-rustls peers through the optimized client. It covers
three suites, two groups/HRR, partial/zero output, partial plaintext reads,
KeyUpdate, application bytes, mutation/CCS/EOF/close and accepted-loan Drop wiping.
Exact published vectors and deterministic live-buffer/partial-read regressions
are separate evidence. No external socket or Internet target is involved.

Native builds still have no supplied sanitizer flags and zero undefined ASan/
sanitizer references in both retained AWS-LC archives. Native C/assembly ASan
coverage is not established. Short Rust crash-free runs establish neither
cryptographic security, full state-space coverage, erasure nor general deployment
readiness. RNG and scheduling change execution counts despite a fixed fuzzer seed.

```sh
mkdir -p fuzz/corpus/client_engine_active_slice
cp fuzz/results/2026-10-14-milestone4/client-engine-seeds/seed-* fuzz/corpus/client_engine_active_slice/
cargo +nightly-2026-09-17 fuzz run client_engine fuzz/corpus/client_engine_active_slice -- -max_total_time=15 -max_len=4096 -seed=71513
```

Use a fresh corpus directory for the stated starting conditions. Historical
milestone4 logs describe the pre-optimization source; their hashes and original
root lock snapshots are preserved separately.
