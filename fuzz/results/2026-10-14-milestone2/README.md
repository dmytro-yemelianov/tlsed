# Protected-record/reassembly ASan smoke campaign, 2026-10-14

These short campaigns completed without a crash. They exercise experimental
components, not a full TLS endpoint, global nonce freshness, identity verification,
or a security audit. The final source includes immediate key/IV retirement on
terminal protected-direction failure. Exact relevant source/lockfile hashes are in
`source-hashes.sha256`; raw final logs use the plain target names below.

Environment: Darwin 27.2.0 arm64; cargo-fuzz 0.13.1; libfuzzer-sys 0.4.10;
`nightly-2026-09-17`, rustc 1.100.0-nightly (923c95cdf 2026-09-16);
AWS-LC Rust 1.18.2/sys 0.46.0. Cargo-fuzz's default sanitizer is address.

| Final target | Requested seconds | Reported seconds | Executions | Seed | Result |
|---|---:|---:|---:|---:|---|
| handshake_reassembly | 10 | 11 | 1,829,643 | 301673991 | exit 0, no crash |
| protected_records | 10 | 11 | 62,093 | 224469606 | exit 0, no crash |

Commands from root:

```sh
cargo +nightly-2026-09-17 fuzz run handshake_reassembly -- -max_total_time=10 -max_len=4096
cargo +nightly-2026-09-17 fuzz run protected_records -- -max_total_time=10 -max_len=20000
```

Both final targets build with stable 1.98.1 via
`cargo check --manifest-path fuzz/Cargo.toml --locked --bins`; strict Clippy and
formatting also pass. Reassembly checks byte-for-byte transcript reconstruction
across generated physical-record and input fragments, coalesced messages, bounded
work, exact alignment rules, epoch/interleaving rejection and raw advertised u24
lengths. Protected records use all three real provider suites with isolated
fixture keys, bounded roundtrip, incomplete/short-buffer retry, replay/mutation,
terminal wipe and arbitrary outer header/length input. The protected run's
libFuzzer growth limit only reached 752 bytes during this smoke window; deterministic
unit tests cover full-size records, and sustained fuzzing remains open.

`*.pre-retirement.log` retains earlier exploratory campaigns before immediate
key retirement landed. `handshake_reassembly.first-oracle.log` retains the first
post-retirement campaign before strengthening the malformed-alignment oracle.
Those logs are historical observations, not final-source evidence. Generated seed
corpora are available locally under ignored `fuzz/corpus`; final campaigns reused
them, so execution counts and corpus evolution are not reproducible performance
claims. There were no discovered crash inputs to curate.

Native-provider coverage is limited. No C sanitizer flags were explicitly supplied;
retained build output reported unset CFLAGS, and `nm -u` found no ASan/sanitizer
references in the built AWS-LC native archive. `native-sanitizer-check.txt` records
the exact paths/commands. Treat AWS-LC C and assembly as outside the demonstrated
ASan coverage. A passing Rust ASan campaign does not prove complete backend
instrumentation, provider erasure, constant-time behavior, or cryptographic security.
Repeated deterministic keys/IVs across isolated harness cases are test fixtures,
not a valid production pattern or proof of key freshness.
