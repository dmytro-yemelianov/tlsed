# Final public-wire-clearing client fuzz evidence

Final source passed **14,546 Rust-ASan/libFuzzer executions in 16 seconds** on
2026-10-14, Apple M5 ARM64/macOS27.2, nightly-2026-09-17/cargo-fuzz0.13.1.
Requested budget15 seconds, seed71514, max input4096. A fresh corpus starts from
all28 retained milestone4 files (27 nonempty and one empty), with no generated
corpus reused. See [raw log](client_engine.log), [metadata](run.json),
[source/fixture/seed hashes](source-hashes.sha256) and
[native coverage diagnostic](native-sanitizer-check.txt).

The unchanged client_engine target exercises bounded raw traces and authenticated
local maintained-rustls peers with real cryptography: three suites, two groups/HRR,
partial/zero network output, partial plaintext reads, KeyUpdate, application bytes,
mutation/CCS/EOF/close and accepted-loan Drop wiping. The deterministic tests separately
inspect wire and plaintext loans, including16KiB records; fuzzer payloads remain
bounded to512 bytes. This is local memory transport, with no socket/Internet target.

Native builds receive no added sanitizer flags; both AWS-LC archives have zero
undefined ASan/sanitizer references and unchanged retained hashes. Native C/assembly
sanitizer coverage remains unestablished. A short Rust crash-free campaign does not
prove TLS security, full coverage, erasure or deployment readiness. RNG and host
scheduling change counts despite fixed libFuzzer seed.

To reproduce the starting conditions, copy every file from
`fuzz/results/2026-10-14-milestone4/client-engine-seeds/` into a new, empty corpus
folder and run:

```sh
cargo +nightly-2026-09-17 fuzz run client_engine /path/to/fresh-corpus -- -max_total_time=15 -max_len=4096 -seed=71514
```

Earlier logs and source hashes describe their original pre-change source; changed
source paths in historical manifests point to exact retained snapshots.
