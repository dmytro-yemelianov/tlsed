# Authenticated client validation — 2026-10-14

Validated locally on Apple M5 / ARM64, Rust1.98.1, macOS27.2.
Remote CI is configured but has not been observed running. Historical component
evidence remains in [the previous milestone](VALIDATION-milestone3.md).

| Check | Result | Evidence / command |
|---|---|---|
| Rust formatting | Passed | `cargo fmt --all -- --check` |
| Strict Rust linting | Passed | `cargo clippy --locked --workspace --all-targets -- -D warnings` |
| Rust unit/integration | Passed: 109 tests | `cargo test --locked --workspace --all-targets`; [final optimization checks](2026-10-14-active-slice/checks.json) |
| Ownership/logging doctests | Passed: 14 compile-fail cases | `cargo test --locked --workspace --doc` |
| Client release integration | Passed: 21 tests: 1 live-buffer + 4 partial-read + 13 interop + 3 fault | `cargo test --locked --release -p tls-client --tests` |
| Standalone Lean | Passed: 117 model theorem audits | `(cd lean && lake build)` |
| Linked production Rust guards | Passed: 21 theorem audits, six helpers | `(cd verification/aeneas && lake build)` |
| Assumption audit | Passed: 138 closures, standard foundations only | `python3 verification/check_axioms.py`; [audit](axiom-audit.json) |
| Proof placeholders / extraction freshness | Passed | `check_proof_sources.py`, `check_translation.py`; [proof commands](milestone4-proof-checks.json) |
| Rust/Lean executable agreement | Passed: 4,923 cases across ten operations | [model-comparison.json](model-comparison.json) |
| Authenticated native rustls client interop | Passed: 18 suite/group/fragmentation matrix cases plus focused regressions | [interop evidence](../../docs/CLIENT_INTEROP.md) |
| Injected provider/EOF failures | Passed: eight cases, immediate key-owner retirement | [fault evidence](../../docs/CLIENT_INTEROP.md#provider-failures-and-transaction-boundaries) |
| Fresh native key agreement | Passed: X25519/P256 pairs, invalid shares, RFC7748 static KAT and ownership cases | [key agreement scope](../../docs/KEY_AGREEMENT.md) |
| Maintained PKI | Passed: 16 integration tests plus owned-token compile-fail | [strict policy and ownership](../../docs/PKI.md) |
| Published composition and known answers | Passed: RFC8448 transcript/keys/records/Finished/HRR and provider vectors | [provenance](../../docs/RFC8448_VECTORS.md), [provider](../../docs/CRYPTO_PROVIDER.md) |
| Final optimized client Rust-ASan | Passed: 11,759 executions in 16 seconds from fresh 28-seed corpus | [exact hashes/logs/native coverage](../../fuzz/results/2026-10-14-active-slice/README.md) |
| Earlier component fuzzing | Historical source-specific smoke campaigns retained | [milestone3](../../fuzz/results/2026-10-14-milestone3/README.md), [milestone2](../../fuzz/results/2026-10-14-milestone2/README.md), [initial](../../fuzz/results/2026-10-14/README.md) |
| Original client comparison | Historical 54,000 TLS observations, six profiles, five process repeats | [baseline report](../../docs/CLIENT_BENCHMARKS.md) |
| Paired buffer optimization | Passed: 64,800 final timing observations, three profiles, six paired repeats | [measured changes/invariants](../../docs/READ_OPTIMIZATION.md), [raw paired ratios](../../crates/tls-bench/results/2026-10-14-active-slice-optimization/before-after.csv) |
| Standalone PKI comparison | Passed: 3,000 batches, explicit policy difference | [PKI costs](../../docs/PKI_BENCHMARKS.md) |

The real transport-independent `tls-client` library checks chain plus DNS/IP
reference identity and strict usage, CertificateVerify and server Finished
before its private phase advances. It exposes application access only after
the last ClientFinished wire byte reaches caller output. HRR, three suites,
X25519/P256, duplex bytes, automatic/requested KeyUpdate, partial input/output,
ignored framed tickets, CCS, advisory/fatal alerts and EOF/close have local
native-record evidence. No permissive certificate verifier is used.

Provider-fault tests require native rustls to authenticate the expected fatal
alert at the correct old-key sequence. Application-key and automatic-update
imports complete before the old-key control record is sealed. Queued/partly
handed-off output is discarded on failure with no substitute record; all counted
key owners Drop while the failed connection remains alive. These are ownership
and sequencing checks, not proofs of native erasure or allocator behavior.

Linked verification applies only to `record_count`, `checked_handshake_total`,
`inner_length`, `valid_content_type`, `hkdf_label_encoded_len` and
`client_phase_next`. Record-count and fixed HKDF-format byte-footprint optimality
retain their explicit cost assumptions. The phase guard has exact translated
semantics; whole-engine verification evidence, atomic retry bookkeeping,
ClientFinished I/O, key installation, buffers, erasure and release composition
remain tested/model assumptions. Full endpoint refinement, PKIX and primitive
security are not proved. All 138 theorem closures contain only standard Lean
foundations; no custom axiom/admission appears. Compiler, Charon/Aeneas/backend,
Lean kernel, maintained crypto/PKI, native FFI, RNG, trusted time/roots, OS and
hardware remain trusted. External Aeneas cache emits namespace-style warnings;
project proof/generated files enforce warnings as errors.

PKI explicitly uses `NoRevocationData`, with no CRL/OCSP validation. Native C/
assembly ASan coverage is unestablished; the final campaign instruments Rust.
Short tests/fuzzing do not establish general Internet compatibility, constant
time, sustained adversarial resource safety, independent review or full RFC
conformance. Server/mTLS, OpenSSL endpoint interoperability, transport adapters/
examples, negotiated record_size_limit and the remaining v1 matrix are open.
Resumption/0-RTT/hybrid KEX/QUIC remain deferred. The first controlled client and PKI measurements now precede source review.
The buffer optimization is measured against the retained original binary: 64 B
receive improves36.54x and is near native parity;1KiB/16KiB improve9.17x/1.34x.
Whole-memory invariant models require provider footprint/noalias and faithful
Rust admission/write semantics; no global speed or whole-Rust proof follows. Broader
platform/role/algorithm/path and allocation profiling remains open.
