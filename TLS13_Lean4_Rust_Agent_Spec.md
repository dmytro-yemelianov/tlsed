# Project Specification: Verified, High-Performance TLS 1.3 Library (Lean 4 + Rust)

**Status:** Engineering specification / agent execution brief  
**Baseline date:** 2026-10-14  
**Deliverable:** Reusable, transport-independent Rust TLS library with Lean 4 formal models, machine-checked invariants, an explicit implementation-to-proof correspondence, and reproducible performance benchmarks.

## 1. Mission

Design and implement a TLS 1.3 library from the protocol layer upward, with three coequal priorities:

1. **Correctness and security:** conform to the current TLS 1.3 specification; prevent invalid state transitions, record/length violations, nonce reuse, secret exposure, and authentication bypass.
2. **Efficiency:** minimize CPU cycles, allocations, memory per connection, copies, syscalls, and handshake latency without relaxing security.
3. **Auditability:** use Lean 4 to specify and prove meaningful properties of protocol logic, then connect those proofs to the actual Rust implementation wherever tooling permits.

The output is a **library, not merely a TLS client, proxy, or benchmark executable**. It must work as a component in HTTP clients/servers, embedded networking applications, and eventually QUIC stacks. Favor clear layering and small verifiable modules over a monolithic implementation.

**Design principle:** The implementation is not "secure because Rust" or "verified because a Lean model exists." Every security and verification claim must identify exactly what is proven, what is tested, and what remains trusted.

## 2. Normative references and competitive baseline

Read and maintain an RFC compliance/traceability matrix before coding:

- **RFC 9846** (July 2026): primary TLS 1.3 specification, replacing RFC 8446: https://www.rfc-editor.org/rfc/rfc9846.html
- **RFC 9325**: secure TLS configuration recommendations: https://www.rfc-editor.org/rfc/rfc9325.html
- **RFC 5280**: X.509 path validation: https://www.rfc-editor.org/rfc/rfc5280.html
- **RFC 9525**: service identity and hostname verification: https://www.rfc-editor.org/rfc/rfc9525.html
- **RFC 8449**: record_size_limit extension: https://www.rfc-editor.org/rfc/rfc8449.html
- **RFC 7301**: ALPN: https://www.rfc-editor.org/rfc/rfc7301.html
- **RFC 9001**: TLS integration into QUIC; architectural input for future work, **not** a requirement to implement QUIC: https://www.rfc-editor.org/rfc/rfc9001.html
- **RFC 9954** and **RFC 10024** (2026): hybrid key exchange and standardized X25519MLKEM768 etc.; optional second-stage feature: https://www.rfc-editor.org/rfc/rfc9954.html and https://www.rfc-editor.org/rfc/rfc10024.html
- **RFC 9963**: legacy client-only RSA PKCS#1 v1.5 signature code points, disabled by default if ever implemented: https://www.rfc-editor.org/rfc/rfc9963.html

Bench against **rustls**, **OpenSSL**, and, where feasible, **s2n-tls/BoringSSL**. Reuse rustls's published benchmark methodology as a starting point: https://github.com/rustls/rustls/blob/main/BENCHMARKING.md . Do not claim a performance win without a controlled comparison.

## 3. Scope

### 3.1 Mandatory v1

- TLS **1.3 only** over a reliable, ordered byte stream; both client and server endpoints.
- Authenticated full 1-RTT handshake, transcript hashing, Finished verification, and HelloRetryRequest.
- Server X.509 certificate-chain verification, hostname/service-identity verification, SNI, and ALPN.
- Optional authenticated client certificates (mTLS) through an explicit policy.
- At least `TLS_AES_128_GCM_SHA256` and `TLS_CHACHA20_POLY1305_SHA256`; support `TLS_AES_256_GCM_SHA384` if the selected provider supports it.
- X25519 key agreement; P-256 interoperability where needed. Never reuse ephemeral KeyShare material across connections.
- Compatible server certificate signature verification using maintained cryptographic providers (e.g. ECDSA P-256, RSA-PSS, Ed25519 as available).
- Incremental handshake/record parser that tolerates arbitrary TCP fragmentation/coalescing without unbounded buffering.
- Authenticated record protection, distinct inbound/outbound sequence counters, automatic key-limit enforcement and KeyUpdate, alerts, orderly shutdown, and strict error handling.
- Nonblocking, transport-independent core; optional synchronous and Tokio adapter crates.
- A runnable reference client and server **solely as examples** of the library.

### 3.2 v1.1 after security/interoperability gate

- TLS 1.3 session resumption via PSK/session tickets with bounded caches and defined ticket lifetime/rotation behavior; prefer PSK + ephemeral key exchange for forward secrecy.
- Client and server certificate selection, richer PKI policies, configurable record sizing, and session reuse benchmarks.
- Hybrid post-quantum key exchange `X25519MLKEM768` via RFC 10024 when supported by the chosen provider. Record its bandwidth, CPU, memory, and interoperability costs independently.
- QUIC-oriented handshake/secret-export adapter per RFC 9001, with no TLS record layer applied to QUIC CRYPTO data.

### 3.3 Explicit exclusions from initial releases

- TLS 1.2 and older, DTLS, QUIC transport, HTTP/2 or HTTP/3 implementations, ECH, custom cipher design, and protocol-breaking shortcuts.
- 0-RTT early application data **disabled** until an explicit replay and application-safety policy, proofs, and tests are ready.
- Custom cryptographic primitives and homemade X.509/PKIX verification. Use established providers; study verified cryptographic components later if useful.
- Automatic fallback to insecure versions or disabled verification; no public "accept invalid certificates" option in a production configuration.
- Formal verification claims covering external crypto, certificate libraries, FFI, the Rust compiler, hardware, or operating system unless independently substantiated.

## 4. Architecture

```text
Application (HTTP / RPC / CLI / user code)
             |
       Public Rust API
             |
  Transport-independent TLS Engine
  +--------------------------------------+
  | Handshake FSM       Session / Policy |
  | Transcript / HKDF   Record Layer     |
  | Incremental Codec   Alert / Closure  |
  +--------------------------------------+
         |                    |
  CryptoProvider          IdentityVerifier
  (audited backend)       (maintained X.509/PKIX)
         |
  Optional adapters: std::io / Tokio / QUIC handshaking

Lean 4: formal protocol model + proof obligations
         ^
         | model correspondence / extracted or translated
         | Rust subset via Aeneas when viable
         v
Rust: small deterministic protocol components
```

Suggested workspace:

```text
/Cargo.toml
/crates/tls-core           # FSM, parser, record framing, key schedule orchestration
/crates/tls-crypto         # backend-neutral traits; no custom crypto
/crates/tls-crypto-awslc   # default high-performance provider
/crates/tls-pki           # thin adapter to a maintained cert verifier
/crates/tls-io             # optional sync and async adapters
/crates/tls-bench          # library-level and end-to-end benches
/examples/client
/examples/server
/lean/Tls13/              # specifications, invariants, proofs
/verification/            # translation tooling, correspondence, proof ledger
/fuzz/                    # structured and raw protocol fuzz targets
/docs/                    # RFC matrix, architecture, threat model, results
```

Rules:

- A protocol engine does **not** own sockets, runtimes, or a thread pool.
- Drive each connection using explicit input/output buffers and progress events. Never require Tokio in `tls-core`.
- Reuse connection-local scratch buffers; avoid global synchronization and per-record heap allocation.
- Encapsulate secrets in types with restricted debug/logging and controlled lifecycle/zeroization where supported. Document residual risks (compiler copies, external providers, swapping, core dumps).
- Restrict `unsafe` to isolated, measured components with written safety arguments and dedicated tests; safe Rust is the default.
- Prefer a narrow, stable backend boundary (`CryptoProvider`, `IdentityVerifier`, secure RNG, time source); validate provider capabilities at configuration time.

## 5. API sketch (illustrative; refine after prototype)

The public API should conceptually support:

```rust
let config = ClientConfig::builder()
    .with_system_roots()?
    .with_alpn([b"h2", b"http/1.1"])?
    .build()?;

let mut tls = ClientConnection::new(config, "example.com".try_into()?)?;

// Caller supplies encrypted network input and a bounded output buffer.
let step = tls.drive(encrypted_input, network_output)?;
// step reports bytes consumed/produced and NeedInput/NeedOutput/
// HandshakeProgress/HandshakeComplete/Closed, etc.

// Decrypted data is readable only after authentication and AEAD validation.
let n = tls.read_plaintext(&mut plaintext_buf)?;
let write = tls.write_plaintext(app_bytes, &mut network_output)?;
```

Design constraints: explicit backpressure; bounded work per call; clean partial-record semantics; non-panicking network-input handling; no hidden network reads or writes; reusable configuration via `Arc` where appropriate; connection-owned mutable state. Document thread-safety and cancellation. Keep application visibility separate from unauthenticated/unfinished handshakes.

## 6. Lean 4 verification strategy

Implement the model **before or alongside** the corresponding Rust component. Suggested modules:

```text
Tls13/Wire.lean          # length-bounded parsing and serialization
Tls13/Handshake.lean     # endpoint states and legal transitions
Tls13/Transcript.lean    # ordering and transcript-binding abstraction
Tls13/KeySchedule.lean   # key epochs, derivation labels, key lifecycle
Tls13/Record.lean        # record sizes, sequence numbers, AEAD preconditions
Tls13/Policies.lean      # authentication and negotiation requirements
Tls13/Security.lean      # principal safety invariants
```

At minimum, prove (for the modeled operations and assumptions):

1. **Parsing safety:** consumed ranges are within input bounds; integer/length conversions cannot overflow; invalid frames do not yield a successful parsed message; codec round trips for supported messages.
2. **Handshake state safety:** illegal messages never advance the endpoint; no established client connection without successful server Finished, certificate and identity verification (or explicitly authenticated PSK in a later phase).
3. **Authenticated data release:** a client does not expose 1-RTT server data until the configured server-authentication conditions hold; received plaintext is never released on AEAD failure. Server-side client-authenticated status requires successful client proof, if requested.
4. **Record/nonce discipline:** sequence counters and key epochs cannot silently wrap; each `(traffic key, nonce)` pair is used at most once on the sending path, under the declared atomicity and provider assumptions.
5. **Key lifetime:** key updates occur before use limits; secrets/keys from distinct epochs cannot be confused; key usage and direction are typed or otherwise validated.
6. **Transcript agreement at the protocol-model level:** accepted Finished messages refer to the correct ordered transcript, including HelloRetryRequest handling, under cryptographic assumptions.
7. **Negotiation policy:** rejected/unknown/unsupported parameters cannot become selected parameters; no version downgrade to TLS 1.2 or earlier.
8. **Resource bounds:** supplied limits bound parser accumulation, certificate-chain buffering, and handshake message sizes, independently of untrusted declared lengths.

**Executable correspondence is crucial.** Investigate **Aeneas + Charon** (https://github.com/AeneasVerif/aeneas) for translating a restricted, pure Rust subset into Lean 4. Start with a tiny parser/transition function to validate the actual toolchain and semantics. Keep impure I/O, external crypto calls, and complex allocation outside the verified subset where necessary.

Track three separate assurance levels:

- **Modeled:** a Lean 4 specification and theorems exist, but Rust correspondence is not proven.
- **Tested against model:** Rust passes generated traces/property tests against a Lean reference, without a formal refinement proof.
- **Linked/proved:** the actual Rust component or a verified translation satisfies the Lean specification under recorded translation/toolchain assumptions.

Maintain `/verification/PROOF_LEDGER.md`: theorem, referenced RFC requirement, relevant Rust function, proof status, trusted assumptions, and reproducible `lake`/Cargo command. **No `sorry`, undeclared `axiom`, or unreviewed assumptions in required production proofs.** Do not advertise "formally verified TLS" if only an abstract model is proven. State precisely which Rust components have linked proofs.

## 7. Protocol and security engineering requirements

- Make client and server FSMs explicit and different where required; validate TLS 1.3 extension placement, duplicate extensions, supported versions, ALPN, cipher/group/signature consistency, and HelloRetryRequest rules.
- Perform certificate-chain and reference-identity validation with a maintained provider; handle hostname/SAN, expiration, trust roots, key usage, algorithm constraints, and time-source failures under an explicit policy. Expose validation errors rather than masking them.
- Reject oversized, truncated, malformed, inconsistent, unexpected, or unauthenticated records without panic or memory corruption. Enforce RFC 9846 plaintext/ciphertext size limits; support configurable stricter resource caps.
- Ensure correct HKDF label construction, transcript hash selection, `CertificateVerify` and Finished verification, traffic-key and IV derivation, epoch transitions, and KeyUpdate behavior.
- Never reuse KeyShare material across connections. Obtain cryptographic randomness from a secure provider; fail closed if unavailable.
- Treat plaintext, traffic secrets, session tickets, and private keys as sensitive. Do not log them in release builds. Avoid exposing secrets to debug formatters.
- Handle abort, `close_notify`, truncation/unclean EOF, cancellation, retries, and fatal alerts coherently.
- Apply per-connection limits to pending bytes, handshake size, certificate count/bytes, work per `drive` call, session tickets, and post-handshake messages; prevent allocation amplification/CPU denial of service.
- Default policies must be secure. Any nonstandard compatibility option requires a security review and explicit opt-in.
- Timing/side-channel claims must be supported by tests or by the selected backend's documented guarantees; Lean functional proofs alone do not prove constant-time execution.

## 8. Performance strategy

**Primary hypothesis:** large improvements may come from protocol overhead, buffering, allocation policy, streaming parsers, and handshake state management. Bulk AES-GCM/ChaCha20 performance is likely dominated by the chosen crypto backend and CPU acceleration; do not expect Lean proof or a Rust rewrite to magically accelerate cryptography.

Optimization order:

1. Establish a correct reference profile with **identical providers, algorithms, certificates, message sizes, and security policies**.
2. Eliminate allocations in steady-state record read/write paths where buffer ownership permits; reuse scratch memory and transcript state.
3. Use in-place authenticated encryption/decryption only where the API supports it safely. Avoid claiming end-to-end zero-copy if cryptography or transport forces copies.
4. Reduce copying via scatter/gather and batched I/O in optional adapters, without sacrificing bounded buffering or error handling.
5. Avoid excessive small writes; support configurable record coalescing and latency-sensitive flush behavior.
6. Tune cipher preference according to platform: AES-GCM on AES-accelerated systems; evaluate ChaCha20-Poly1305 on systems without equivalent acceleration.
7. Profile X.509 validation, key exchange, RNG calls, transcript hashing, and session-cache contention separately.
8. Investigate specialized parsing/encoding only after profiling. Any `unsafe` or SIMD variant is opt-in behind a safe, equivalent fallback and additional validation.

Measure, at minimum:

- **Bulk throughput:** encrypt/decrypt GiB/s and cycles/byte, small (64 B/1 KiB) and large (16 KiB) records, read and write directions.
- **Handshake:** full and resumed (when implemented) handshakes/s and p50/p95/p99 completion latency.
- **Memory:** allocations/connection, allocations/record, peak and steady-state bytes/connection, and process RSS for 100/1,000/10,000 mostly-idle connections when hardware permits.
- **CPU:** retired instructions, cycles, cache misses, context switches; profile with `perf`/Instruments as applicable.
- **Resource stress:** adversarial fragmentation, tiny I/O buffers, huge advertised lengths, repeated invalid handshakes, and connection churn.

Benchmark x86-64 with AES acceleration and at least one ARM64 platform; capture compiler, CPU, frequency settings, OS, provider versions, build flags, certificate type, workload, and raw results. Pin cores or document scheduling noise; use multiple repeated runs and report variance. Run cryptographic backend microbenchmarks separately from full TLS. No fabricated numbers or apples-to-oranges comparisons.

**Targets, not guaranteed outcomes:** match the best appropriate baseline on core TLS 1.3 interoperability cases; seek >=10% fewer allocations and/or >=10% lower connection memory at equivalent functionality, while avoiding measurable throughput regression. Treat a throughput or handshake advantage as a stretch result established only by data. If the library does not outperform existing implementations, identify exactly where the limits are and preserve the verified/lean implementation as a useful result.

## 9. Validation requirements

Use multiple independent methods:

- Unit and property tests for parsing, serialization, transcript management, state transitions, keys/epochs, and failure handling.
- RFC 9846-driven known-answer vectors for key schedule and message processing. Curate known-answer test data where RFC does not provide a directly usable vector.
- Differential tests against rustls/OpenSSL; do not mistake matching behavior for proof of RFC compliance.
- Wire interoperability matrix: our client <-> OpenSSL/rustls servers, and OpenSSL/rustls clients <-> our server; cover both successful and rejected negotiations.
- External protocol negative testing such as `tlsfuzzer` and BoringSSL Bogo **where integration is practical**.
- `cargo-fuzz`/libFuzzer, mutation-based tests, arbitrary chunking, unexpected message order, and cancellation at every boundary.
- Miri and sanitizers on supported configurations, dependency auditing, reproducible lockfiles and CI.
- Long-running soak tests, resource exhaustion, packet-loss/latency injection at the transport layer (without confusing TCP reliability with TLS records).
- Security review by an independent practitioner **before suggesting Internet-facing production deployment**. Do not state that test passage alone constitutes an audit.

A change touching parsing, handshake transitions, record counters, key scheduling, authentication, or secret handling must run the corresponding Lean proofs and Rust regression suite before merging.

## 10. Phased execution plan and agent deliverables

### Phase 0 — Research and baseline

Produce `docs/RFC_MATRIX.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, and an initial fair benchmark against rustls/OpenSSL. Record version pinning, RFC 9846 differences from RFC 8446, verification-toolchain feasibility, and performance hotspots. Select crypto/identity providers explicitly. **Gate:** reviewable architecture + runnable baseline + a small Aeneas/Lean proof-of-concept or a documented alternative.

### Phase 1 — Minimal verified wire/record foundation

Implement Rust byte readers/writers, incremental length-bounded framing, and plaintext/AEAD record framing; create Lean models and proofs for bounds, lengths, counters, and valid transitions. Unit tests, fuzz targets, and benchmark harness must run in CI. **Gate:** zero known parser panics/UB; documented resource bounds and honest proof status.

### Phase 2 — Secure TLS client

Implement full authenticated TLS 1.3 client handshake with proper PKIX/hostname verification, ALPN/SNI, HRR, Finished, traffic keys, KeyUpdate, and shutdown. Interoperate with OpenSSL and rustls servers. No 0-RTT, no insecure verifier. **Gate:** external protocol tests, fuzzing, compliance matrix, and proof ledger pass.

### Phase 3 — TLS server

Add server FSM, certificate selection, full handshake, optional mTLS, and robust resource limits; interoperate with external clients. **Gate:** bidirectional interoperability and security tests; benchmark both roles.

### Phase 4 — Optimization without regressions

Profile then optimize buffers, records, batching, transcript processing, and allocation policy; rerun proofs/fuzz/interoperability after each change. Document each optimization's isolated effect (throughput, latency, RAM, CPU). **Gate:** reproducible `BENCHMARKS.md` and no security regressions.

### Phase 5 — Expanded capabilities

Add bounded resumption, RFC 10024 hybrid KEX, optional QUIC handshake interface, and embedded/no_std suitability assessment as **separate scoped changes**. Do not trade correctness or v1 schedule against speculative extra features.

## 11. Definition of done

The agent must provide:

1. Compiling Rust workspace and Lean 4 project with pinned dependencies/toolchains.
2. Clearly documented public API and client/server examples.
3. Complete v1 RFC compliance matrix, threat model, interoperability results, fuzz/test summaries, and outstanding deviations.
4. Machine-checkable Lean proofs, a proof ledger, and explicit evidence (or caveats) of Rust-to-Lean correspondence.
5. Deterministic build/test commands: `cargo fmt --check`, `cargo clippy`, `cargo test`, benchmark commands, `lake build`, plus CI workflows.
6. A benchmark report containing environment, raw data, variance, baselines, and a concise bottleneck analysis.
7. A security status label: **experimental until externally reviewed**. Never represent the library as audited or production-safe without evidence.

## 12. Agent operating instructions

- **Start implementing; do not stop at a design essay.** Create the repo structure, compliance checklist, tiny verified parser/state-machine prototype, and reproducible baseline first.
- Execute in small compilable milestones. Keep `main` buildable and testable. Document exact commands and artifacts for each milestone.
- When blocked by a theorem, unsupported Aeneas translation, interop problem, or performance regression, report the concrete counterexample/limitation and adapt the module boundary. Do not conceal the problem with `sorry`, `axiom`, skipped tests, or unsupported claims.
- Follow RFC 9846 literally for normative behavior. Use external vetted cryptography and certificate-validation libraries; do not implement your own crypto to chase speed.
- Never optimize away authentication, encryption, randomness, key rotation, bounds checks, or failure handling.
- Prioritize **correctness -> security -> measurable efficiency**. At each milestone, report what works, what is proved, what is only tested, what remains trusted, and the next engineering task.
