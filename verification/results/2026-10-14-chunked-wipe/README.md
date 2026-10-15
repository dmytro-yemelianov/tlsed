# Final aligned-wipe checks and isolated Miri scope

[checks.json](checks.json) records114 Rust tests,14 compile-fail docs,26 client
release tests, strict Clippy/fmt/source guard/translation freshness and4,923
Rust/Lean cases. The proof agent reports Lake33jobs and168 audited closures;
[exact audit](axiom-audit.json) has147 model+21 linked theorem dependencies.

Miri runs the exact body of production `zeroize_secret` copied into a dependency-only
probe, avoiding native crypto/PKI FFI. [Body hash/scope](miri-helper-source.json),
[commands/statuses](miri-checks.json), source and Cargo manifest/lock are retained.
2,304 guarded ranges pass on ARM64,32-bit i686 and big-endian powerpc64 targets.
It is helper memory-behavior evidence, not whole-engine/native erasure verification.

To reproduce, create a fresh directory with `src/`, copy `miri-probe-Cargo.toml`
as `Cargo.toml`, `miri-probe-Cargo.lock` as `Cargo.lock` and
`isolated-helper-miri-source.rs.txt` as `src/lib.rs`, then run from that directory:

```sh
cargo +nightly-2026-09-17 miri test --locked --lib --target aarch64-apple-darwin
cargo +nightly-2026-09-17 miri test --locked --lib --target i686-unknown-linux-gnu
cargo +nightly-2026-09-17 miri test --locked --lib --target powerpc64-unknown-linux-gnu
```

The archived probe's helper text hash must match the current production body
before using these results for changed source. Native endpoint tests/ASan and
[paired timing](../../../docs/SECRET_WIPING.md) remain separate evidence.
