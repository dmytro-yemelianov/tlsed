# tlsed

Experimental, transport-independent TLS 1.3 Rust library with required Lean 4
proofs. See [the execution plan](docs/PLAN.md) for completed milestones and gates.

The implemented components include bounded record/handshake framing, directional
counters, protected records through AWS-LC, streaming transcripts with HRR,
typed TLS key derivation/Finished checks, and bounded server PKI verification.
Published TLS records, intermediate secrets and Finished vectors match exactly.
The reusable `tls-client` crate now performs an authenticated full handshake,
HRR, application traffic, KeyUpdate, alerts and shutdown through caller buffers.
It interoperates locally with rustls across three suites and two groups.
The server role, mTLS, OpenSSL endpoint interoperability and transport adapters
remain open. The benchmark harness now compares our authenticated client with
rustls using the same server/provider and strict certificate policy. Results
vary by workload; see [the original comparison](docs/CLIENT_BENCHMARKS.md)
and [PKI measurements](docs/PKI_BENCHMARKS.md). The first
[buffer-clearing optimization](docs/READ_OPTIMIZATION.md) brings64-byte
receive close to native rustls in this local workload. The subsequent
[public wire clearing change](docs/WIRE_CLEARING.md) brings 16 KiB transmit
close to native pair time. The latest [aligned volatile secret wiping](docs/SECRET_WIPING.md)
brings AES128 16 KiB receive to about 0.835x native pair time in this local run,
while preserving compiler-resistant erasure. The subsequent full handshake-loan
Drop optimization improves paired lifecycle throughput by 11–13% on the measured
M5 and brings it close to the native pair, with no confirmed bulk gain; see the
[audit and handover](docs/HANDOVER.md).

## Build and verify

Rust is pinned in `rust-toolchain.toml`, Lean in `lean/lean-toolchain`, and Rust
dependencies in `Cargo.lock`. Install Rustup and Elan, then run:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo test --locked --workspace --doc
cd lean
lake build
cd ..
python3 verification/check_proof_sources.py
python3 verification/check_models.py
python3 verification/check_translation.py
python3 verification/aeneas/bootstrap_dependencies.py
cd verification/aeneas
lake exe cache get
lake build
cd ../..
python3 verification/check_axioms.py
cargo run --locked --release -p tls-bench -- --samples 30 --bulk-records 256
```

## Assurance

Lean checks 147 model theorems and 21 linked theorems about six translated Rust
guards. This includes minimum record count under fixed positive
capacity, checked handshake/inner-record lengths, and exact bounded HKDF-label
size with its mandatory-format footprint, and exact client phase transitions.
New byte-memory models prove completed-read wipe redundancy and clean backing
for an active ciphertext prefix. A further public-wire model proves byte-loop/fill
equality and minimal changed-byte support under a live zero-state contract.
A further aligned partition model proves exact head/middle/tail clearing and
conditional minimum chunk count; safe views, volatile/compiler semantics and
Rust orchestration/provider footprint remain
tested and assumed rather than linked. The full endpoint wiring is tested;
the phase proof assumes truthful verification
evidence and atomic retry bookkeeping. Charon/Aeneas translation,
the compiler and external cryptography remain trusted. The full framing and
sealing/decryption paths are tested rather than linked/proved. See the
[proof ledger](verification/PROOF_LEDGER.md),
[correspondence boundary](verification/CORRESPONDENCE.md),
[RFC matrix](docs/RFC_MATRIX.md), and [threat model](docs/THREAT_MODEL.md).

Component APIs and current limits are documented in
[protected records](docs/PROTECTED_RECORDS.md),
[client engine](docs/CLIENT_ENGINE.md), [client interoperability](docs/CLIENT_INTEROP.md),
[hello codecs](docs/HELLO_CODEC.md), [key agreement](docs/KEY_AGREEMENT.md),
[handshake reassembly](docs/REASSEMBLY.md),
[transcripts](docs/TRANSCRIPT.md), [TLS key schedule](docs/KEY_SCHEDULE.md),
[PKI](docs/PKI.md), and
[the maintained provider](docs/CRYPTO_PROVIDER.md). Local validation and known
remaining gates are recorded in [milestone evidence](verification/results/VALIDATION.md).
The [rustls/webpki comparison plan](docs/RUSTLS_COMPARISON_PLAN.md) requires
controlled benchmarks before performance-driven source changes.

Security status: **experimental until externally reviewed**.
