# Authenticated client validation — 2026-10-14

Validated locally on Apple M5 / ARM64, Rust1.98.1, macOS27.2.
Remote CI is configured but has not been observed running. Historical component
evidence remains in [the previous milestone](VALIDATION-milestone3.md).

| Check | Result | Evidence / command |
|---|---|---|
| Rust formatting | Passed | `cargo fmt --all -- --check` |
| Strict Rust linting | Passed | `cargo clippy --locked --workspace --all-targets -- -D warnings` |
| Rust unit/integration | Passed: 114 tests | `cargo test --locked --workspace --all-targets`; [final aligned-wipe checks](2026-10-14-chunked-wipe/checks.json) |
| Ownership/logging doctests | Passed: 14 compile-fail cases | `cargo test --locked --workspace --doc` |
| Client release integration | Passed: 26 tests: 1 plaintext-buffer + 3 wire-buffer + 2 aligned-wipe + 4 partial-read + 13 interop + 3 fault | `cargo test --locked --release -p tls-client --tests` |
| Standalone Lean | Passed: 147 model theorem audits | `(cd lean && lake build)` |
| Linked production Rust guards | Passed: 21 theorem audits, six helpers | `(cd verification/aeneas && lake build)` |
| Assumption audit | Passed: 168 closures, standard foundations only | `python3 verification/check_axioms.py`; [audit](axiom-audit.json) |
| Proof placeholders / extraction freshness | Passed | `check_proof_sources.py`, `check_translation.py`; [final source/freshness checks](2026-10-14-chunked-wipe/checks.json) |
| Rust/Lean executable agreement | Passed: 4,923 cases across ten operations | [model-comparison.json](model-comparison.json) |
| Authenticated native rustls client interop | Passed: 18 suite/group/fragmentation matrix cases plus focused regressions | [interop evidence](../../docs/CLIENT_INTEROP.md) |
| Injected provider/EOF failures | Passed: eight cases, immediate key-owner retirement | [fault evidence](../../docs/CLIENT_INTEROP.md#provider-failures-and-transaction-boundaries) |
| Fresh native key agreement | Passed: X25519/P256 pairs, invalid shares, RFC7748 static KAT and ownership cases | [key agreement scope](../../docs/KEY_AGREEMENT.md) |
| Maintained PKI | Passed: 16 integration tests plus owned-token compile-fail | [strict policy and ownership](../../docs/PKI.md) |
| Published composition and known answers | Passed: RFC8448 transcript/keys/records/Finished/HRR and provider vectors | [provenance](../../docs/RFC8448_VECTORS.md), [provider](../../docs/CRYPTO_PROVIDER.md) |
| Final optimized client Rust-ASan | Passed: 23,054 executions in 16 seconds from fresh 28-seed corpus | [exact hashes/logs/native coverage](../../fuzz/results/2026-10-14-chunked-wipe/README.md) |
| Earlier component fuzzing | Historical source-specific smoke campaigns retained | [milestone3](../../fuzz/results/2026-10-14-milestone3/README.md), [milestone2](../../fuzz/results/2026-10-14-milestone2/README.md), [initial](../../fuzz/results/2026-10-14/README.md) |
| Original client comparison | Historical 54,000 TLS observations, six profiles, five process repeats | [baseline report](../../docs/CLIENT_BENCHMARKS.md) |
| Paired aligned volatile secret wiping | Passed: 64,800 final timing observations, three profiles, six paired repeats | [measured changes/invariants](../../docs/SECRET_WIPING.md), [raw paired ratios](../../crates/tls-bench/results/2026-10-14-chunked-wipe/paired/before-after.csv) |
| Earlier public-wire optimization | Historical 64,800 observations against prior plaintext-optimized engine | [source-specific report](../../docs/WIRE_CLEARING.md) |
| Isolated aligned-wipe Miri | Passed: 2,304 ranges each on ARM64, 32-bit and big-endian targets | [exact copied helper/scope](2026-10-14-chunked-wipe/miri-helper-source.json), [logs](2026-10-14-chunked-wipe/miri-checks.json) |
| Earlier paired plaintext optimization | Historical 64,800 observations against original engine | [source-specific report](../../docs/READ_OPTIMIZATION.md) |
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
security are not proved. All 168 theorem closures contain only standard Lean
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
The final aligned volatile-wipe helper preserves compiler-resistant erasure
and exact slice footprint via maintained zeroize on a safe bytemuck head/u128-middle/
tail view. It covers client byte-slice constructor/read/control/error/abort/Drop
clears; typed secrets and core/provider erasure are unchanged. New dependency
view/representation and compiler lowering remain trusted. Twenty new standalone
proofs establish partition/range equality and conditional chunk count, not native
erasure or CPU optimality. The final paired AES12816KiB receive improves1.853x
over the public-wire-optimized binary and takes0.835x native pair time; lifecycle
improves1.227x and still takes1.119x native. Independent experiment gains are not
multiplied. The source-hashed copied helper passes isolated Miri on three targets;
real native peer tests inspect unaligned live loans and complete cleanup.
Earlier plaintext/public-wire results retain their exact source-specific snapshots
and ratios in linked historical reports. Full-model correspondence still requires
provider/view footprint, noalias and faithful Rust admission/write semantics.
[Source review](../../docs/SOURCE_COMPARISON.md) scopes native capacity and strict
alternative-issuer PKI experiments; no upstream patch or win is claimed. Broader
platform/role/algorithm/path, lifecycle and full-v1 gates remain open.
