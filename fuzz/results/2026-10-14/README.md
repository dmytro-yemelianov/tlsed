# ASan/libFuzzer smoke campaign, 2026-10-14

Source milestone: initial `tls-core` wire/framer/count/counter/auth foundations.
These short campaigns found no crashes. They do not establish sustained fuzz
coverage, cryptographic security, complete TLS correctness, or an audit.

Environment: Darwin 27.2.0 arm64; cargo-fuzz 0.13.1; libfuzzer-sys 0.4.10;
`nightly-2026-09-17`, reporting rustc 1.100.0-nightly
(923c95cdf 2026-09-16). Cargo-fuzz's default sanitizer is `address`.
`fragmented_records` and `auth_counter` ran concurrently. Generated seed corpora
remain locally available in ignored `fuzz/corpus`; the parser used an earlier
smoke corpus before its oracle was improved. Raw logs are adjacent.

| Target | Requested seconds | Actual reported seconds | Executions | Seed | Result |
|---|---:|---:|---:|---:|---|
| record_parser | 10 | 11 | 14,491,572 | 2044453750 | exit 0, no crash |
| fragmented_records | 10 | 11 | 5,021,153 | 2004012483 | exit 0, no crash |
| auth_counter | 10 | 11 | 5,268,607 | 2005024825 | exit 0, no crash |

Commands from root:

```sh
cargo +nightly-2026-09-17 fuzz run record_parser -- -max_total_time=10 -max_len=20000
cargo +nightly-2026-09-17 fuzz run fragmented_records -- -max_total_time=10 -max_len=20000
cargo +nightly-2026-09-17 fuzz run auth_counter -- -max_total_time=10 -max_len=4096
```

Execution counts and corpus evolution depend on machine load and initial corpus;
these are recorded observations, not reproducible performance claims. The harness
compiles with stable Rust 1.98.1 as well. Miri, additional sanitizers, long campaigns,
structured protected-record/handshake fuzzing, and external protocol fuzzing remain
future work.
