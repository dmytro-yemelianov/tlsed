# Transcript, key schedule and PKI validation — 2026-10-14

Validated locally on Apple M5 / ARM64, Rust1.98.1, macOS27.2.
Remote CI is configured but has not been observed running.

| Check | Result | Evidence / command |
|---|---|---|
| Rust formatting | Passed | `cargo fmt --all -- --check` |
| Strict Rust linting | Passed | `cargo clippy --locked --workspace --all-targets -- -D warnings` |
| Rust regressions | Passed: 70 unit/integration tests | `cargo test --locked --workspace --all-targets` |
| Ownership/logging doctests | Passed: 10 compile-fail cases | `cargo test --locked --workspace --doc` |
| Standalone Lean | Passed: 75 model theorem dependency audits | `(cd lean && lake build)` |
| Linked Rust guards | Passed: 16 theorem dependency audits | `(cd verification/aeneas && lake build)` |
| Automated assumption audit | Passed: all 91 theorem closures | `python3 verification/check_axioms.py`; [dependency report](axiom-audit.json) |
| Proof-source guard | Passed | `python3 verification/check_proof_sources.py` |
| Production translation freshness | Passed after fifth-helper extraction | `python3 verification/check_translation.py` |
| Executable Rust/Lean agreement | Passed: 4,047 cases, nine operations | [model-comparison.json](model-comparison.json) |
| Provider/record/schedule known answers | Passed: NIST, RFC8439/5869/4231/8448 and SHA vectors | [provider scope](../../docs/CRYPTO_PROVIDER.md), [key schedule](../../docs/KEY_SCHEDULE.md) |
| Published component composition | Passed: §3 transcript→keys→records→Finished and §5 HRR hash | [RFC8448 provenance](../../docs/RFC8448_VECTORS.md), [fixture hashes](rfc8448-fixture-provenance.json) |
| PKI adapter | Passed: 15 positive/negative integration tests | [PKI scope](../../docs/PKI.md) |
| Corrected transcript construction | Debug/release regressions passed | Resets preloaded context; reset failure/algorithm change retires context |
| Transcript/label ASan | Passed: 463,286 executions in11 seconds | [current source logs and native coverage caveats](../../fuzz/results/2026-10-14-milestone3/README.md) |
| Bounded server PKI ASan | Passed: 370,269 executions in11 seconds | [current source/fixture logs, oracles and coverage caveats](../../fuzz/results/2026-10-14-milestone3/README.md) |
| Earlier component ASan | Passed: two protected/reassembly and three foundation campaigns | [milestone2](../../fuzz/results/2026-10-14-milestone2/README.md), [initial](../../fuzz/results/2026-10-14/README.md) |
| Authenticated reference benchmarks | Historical30-sample baselines; current smoke passed | [report/raw observations](../../docs/BENCHMARKS.md); `cargo run --locked --release -p tls-bench -- --samples 3 --bulk-records 8` |

Every enumerated theorem closure contains only standard Lean foundations or no
axioms; no custom assumption or admitted proof appears. The pinned external
Aeneas backend replays three namespace-style warnings; project files enforce
warnings as errors. Charon/Aeneas, compiler, Lean kernel and external crypto/PKI
remain trusted.

Linked verification covers only `record_count`, `checked_handshake_total`,
`inner_length`, `valid_content_type` and `hkdf_label_encoded_len`. The latter's
minimum concerns the mandatory fixed-format footprint; actual encoder writes
are tested. Full record/transcript/HKDF/HMAC paths, ownership/erasure and PKIX
are not formally refined. Conditional transcript/Finished model proofs do not
prove collision resistance or HMAC security.

The strict PKI supplement checks leaf digitalSignature and selected issuing-CA
keyCertSign when KeyUsage exists, including unique extension, exact consumption,
canonical DER named-bit encoding and bit0..8 bounds. Native candidate-path
callbacks retry alternative issuers and keep trust anchors separate. Revocation
is explicitly absent; arbitrary PKIX/service-identity features remain outside
the documented DNS/IP Web PKI profile. No Internet endpoint or full compliance
claim follows from these tests.

Protected directions retire keys and wipe IV/output on terminal failure.
Native AWS-LC C/assembly sanitizer coverage is not established. Full endpoints,
fresh provider-backed KEX, offered-selection/extension validation, automatic
KeyUpdate, alerts/shutdown, external endpoint interoperability, sustained fuzzing,
additional sanitizer/Miri coverage, controlled equivalent-policy rustls/webpki
comparisons and independent security review remain open. Record-tag validity,
Finished success or a standalone certificate token alone does not authorize
application-data release.
