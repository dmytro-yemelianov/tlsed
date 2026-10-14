# Authenticated client fuzz evidence

Final source run on 2026-10-14, Apple M5 / ARM64 / macOS27.2, pinned
nightly-2026-09-17, cargo-fuzz0.13.1 and libfuzzer-sys0.4.10.
The Rust ASan/libFuzzer campaign passed **9,804 executions in 11 seconds**,
with requested budget10 seconds, seed71513 and max input4096.
See [raw log](client_engine.log), [run metadata](client-engine-run.json),
[source/fixture/seed hashes](client-engine-source-hashes.sha256) and
[native diagnostic](native-sanitizer-check.txt).

The initial corpus was a fresh copy of28 retained curated cases in
`client-engine-seeds`;27 are nonempty and one is empty. LibFuzzer reports27
loaded files and handles the empty input separately. No generated corpus from
the earlier campaign was reused. Exact native RNG and scheduling affect run
counts; the fixed fuzzer seed does not make fresh key generation deterministic.

## Oracles and scope

`client_engine` checks raw bounded input, borrowed codec fields, certificate
slot clearing on rejection, atomic ClientHello output, independent undersized
buffer loans and full accepted-loan wiping on connection Drop. Its structured
mode uses an actual rustls0.23.45 AWS-LC server with trusted public local
fixtures/time and the real client certificate/name/CV/Finished/provider paths.
It exercises three suites, two groups, HRR, fragmented and zero-capacity output,
verified duplex bytes, tiny sending limits, automatic/requested KeyUpdate and
the NeedWork/InputPending ordering gate. Record mutations, late CCS, truncated
EOF and clean close have terminal/no-release oracles. No socket or Internet
target is involved; all credentials are public local test fixtures.

Per-case input is bounded to4096 bytes, raw driving to512 steps, structured
pumping to12000 steps, reassembly work to1..64 bytes and application payloads
to512 bytes. These small budgets and the short campaign do not establish
complete malformed-input/state-space coverage or sustained resource safety.
The maintained peer shares AWS-LC with the client; interop and independent
published known-answer tests provide different evidence from primitive security.

Native build logs show unset C flags; both retained AWS-LC native archive
variants have zero undefined ASan/sanitizer symbol references. Native C/assembly
sanitizer coverage is **not established**. Passing Rust ASan does not establish
provider memory safety, erasure, constant-time execution or cryptographic security.

The files containing `before-alert-review` or `before-harness-lint` are
historical evidence from earlier source versions; only `client_engine.log` and
its matching hashes identify this final run. Previous component campaigns also retain historical sources.

## Reproduce from fresh seeds

Use an empty corpus directory before copying seeds:

```sh
mkdir -p fuzz/corpus/client_engine_final_linted
cp fuzz/results/2026-10-14-milestone4/client-engine-seeds/seed-* fuzz/corpus/client_engine_final_linted/
cargo +nightly-2026-09-17 fuzz run client_engine fuzz/corpus/client_engine_final_linted -- -max_total_time=10 -max_len=4096 -seed=71513
```

CI adds this eighth target as a10000-run smoke campaign. A remote run has not
been observed; local source/harness compilation and strict linting pass.

The later benchmark adds dependencies only to tls-bench. The original root
Cargo.lock is retained as snapshot-root-Cargo.lock with its exact original hash;
the compiled fuzz workspace uses its unchanged independent fuzz/Cargo.lock.
No production-module or fuzz-harness changes accompanied that benchmark.

The later buffer optimization retains this original client source as
snapshot-client-lib-before-optimization.rs.txt. New optimized-source fuzz evidence
is in ../2026-10-14-active-slice/README.md; these older counts remain historical.
