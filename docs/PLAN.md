# Execution plan

Source: `TLS13_Lean4_Rust_Agent_Spec.md`. Started 2026-10-14.
Security status: experimental; authenticated client implemented, server and
external audit still open.

## Milestones and gates

1. **Research and executable foundation (initial milestone complete).** Read normative references,
   maintain the RFC matrix, select AWS-LC and rustls-webpki as candidate providers,
   pin Rust/Lean, establish a runnable baseline, and investigate Aeneas/Charon.
   Implement bounded wire framing, sequence/epoch discipline, a small guarded
   client authentication model, and record segmentation. Check meaningful Lean
   safety and optimization theorems and compare executable model results with
   Rust. Gate: formatting, linting, Rust regressions, `lake build`, model comparison,
   reproducible baseline, and an honest proof ledger all pass.
2. **Protected records and handshake orchestration.** Connect the maintained AEAD,
   transcript/HKDF, RNG, and PKI providers; implement bounded handshake reassembly,
   client messages, HRR, certificate/signature/Finished verification, KeyUpdate,
   and shutdown. Gate: known-answer vectors, fuzzing and client interoperability.
3. **Server and mTLS.** Add the distinct server FSM and policy, certificate
   selection, and reference examples. Gate: both roles interoperate with rustls
   and OpenSSL, including negative authentication/negotiation cases.
4. **Measured optimization.** Benchmark equivalent workloads against rustls first,
   then compare source and measured hotspots to find improvements for both
   implementations. Follow `docs/RUSTLS_COMPARISON_PLAN.md`. Improve buffering,
   copies, batching and allocation policy. Preserve proof obligations and rerun
   regression/interoperability checks. Publish raw samples and variance.
5. **Separate extensions.** Bounded resumption, hybrid KEX, QUIC handshake adapter
   and no_std assessment follow the v1 security/interoperability gates.

## Initial proof and optimization contract

Lean 4 is a required build, with no `sorry` or custom axioms. Claims are separated
into modeled, tested against the executable model, and linked/proved Rust.
Executable differential tests do not constitute a Rust refinement proof.

The first optimization objective is **minimum record count**, for n bytes and a
positive per-record payload capacity L. The implementation computes
`n / L + (n % L != 0)` without the overflowing `(n + L - 1)` expression.
The proof must show feasibility and that every capacity-respecting partition
needs at least this many records. This minimizes fixed per-record framing cost
in the declared model; it says nothing about globally optimal TLS CPU time,
cryptographic cost, latency-sensitive flush policy, padding, or transport I/O.

Other initial obligations: successful parse ranges stay inside input; record
lengths respect configured and protocol caps; sequence reservations are strictly
monotone within an epoch and cannot wrap; epoch rotation cannot wrap; illegal
authentication events do not establish a client; failed AEAD cannot authorize
application-data release. Fresh keys per epoch remain a provider assumption.

## Work allocation

- Frontier reasoning agent: Lean models, checked proofs, executable reference,
  and precise optimality assumptions.
- Coding agent: Rust wire/framing, bounded incremental buffering, record counter,
  guarded authentication transitions, record-count arithmetic, regression/fuzz
  targets. Owns `crates/tls-core` and `fuzz`.
- Research/benchmark agent: source-backed RFC traceability, architecture, threat
  model, provider/toolchain feasibility, and runnable rustls/OpenSSL baseline.
  Owns research documents and `crates/tls-bench`.
- Coordinator: workspace, integration, correspondence checks, CI, review and
  final verification. All edits use separate ownership boundaries.

No full TLS support, compliance, whole-library linked verification, production safety, or
competitive performance win will be claimed before its corresponding gate.

## Initial milestone evidence

The following three component milestones are historical checkpoints. Current
counts and source-specific evidence are in `verification/results/VALIDATION.md`.

- Two pinned Rust crates compile; stable formatting, strict linting, regressions
  and ownership doctests pass. The core is dependency-free, `no_std` and safe Rust.
- Standalone Lean 4.34.1 checks 33 model theorems and their dependency audits.
- Pinned Charon/Aeneas extraction of production `record_count` and Lean 4.31.0
  check four linked arithmetic/refinement/optimality theorems. Each theorem uses
  only standard Lean foundations; source/artifact hashes are retained.
- 1,908 deterministic Rust/Lean comparisons across six operations pass.
- Three short ASan/libFuzzer campaigns passed; raw logs and limits are recorded.
- Authenticated rustls/OpenSSL reference runs, fixtures, environment, raw samples
  and variance are saved. No own-endpoint performance comparison is claimed.
- CI is configured for these Rust, Lean, source-freshness, model and fuzz checks;
  a remote workflow run has not been observed in this local milestone.

Next: maintained-provider protected records and bounded handshake reassembly,
then an actual authenticated client endpoint. Full v1 remains open.

## Protected-record and reassembly milestone (components implemented)

Implement `tls-crypto` traits and the pinned AWS-LC adapter, in-place AEAD records
with exact authenticated headers and TLS inner-content/padding checks, directional
nonce consumption, conservative provider usage caps and terminal authentication
failures. Add caller-owned bounded u24 handshake reassembly, explicit record/key
boundary handling and exact partial/coalesced progress. Extend Lean models for
resource bounds, padding/release preconditions and a translated Rust length guard.
This milestone supplies components for a future real handshake; it does not
assert server identity merely because a record's AEAD tag is valid.

Ownership: coding agent handles protected records/tests; provider agent handles
AWS-LC implementation and known-answer tests; proof agent handles Lean/ledger;
coordinator handles shared traits, handshake reassembly, translation, CI and
integration. Gate: strict Rust checks, Lean builds/audits, retained translation
freshness, cross-language cases, known-answer/differential record evidence and
bounded reassembly regressions.

This milestone adds maintained AWS-LC AEAD/hash/HKDF/RNG, caller-buffer protected
records, immediate terminal key/IV retirement, and bounded handshake reassembly.
Published RFC8448 records match exactly, including the server flight and its
four reassembled messages. The proof projects now check 54 model theorems and
12 linked theorems over four pure guards, with standard-only axiom dependencies.
The executable comparison covers 3,494 cases across eight operations. New
protected-record/reassembly fuzz campaigns and their explicit native-sanitizer
limits are retained separately. See the current validation report for final
commands/status. Full client/server handshake and identity verification remain
the next phase; generic HKDF operations are not a TLS key schedule.

## Transcript, TLS key schedule and PKI milestone (components implemented)

Add streaming SHA-256/SHA-384 transcript state with strict encoded-message
lengths and single HelloRetryRequest rewriting. Implement exact bounded TLS
HKDF labels, direction/stage-specific secret ownership, handshake/application
traffic derivation, Finished generation/verification and traffic-update
derivation. Add a maintained webpki adapter for bounded server certificate
chains, DNS/IP reference identities and TLS 1.3 CertificateVerify signatures.
Use published RFC8448 intermediate hashes/secrets/Finished values and negative
identity/signature/expiry/length tests. Extend Lean transcript/epoch models and
linked label-size arithmetic; retain explicit crypto/compiler trust.

Ownership: coding agent owns key schedule and TLS-label code/tests; provider/PKI
agent owns streaming-hash/HMAC adapter additions and the PKI crate; proof agent
owns new Lean proofs/ledger; coordinator owns transcript, shared traits,
translation, model comparisons and integration. Full endpoint hello negotiation,
certificate-message codec, connection FSM, KeyUpdate and interoperability remain
subsequent integration work rather than implicit claims from these components.


This milestone supplies streaming hash/HMAC, bounded transcripts and single HRR
rewriting, typed no-PSK key derivation/Finished/update operations, and server PKI
with DNS/IP identity, CertificateVerify and strict X.509 KeyUsage. The latter
uses maintained x509-parser to supplement webpki's intentional Web PKI policy.
Native candidate-path callbacks preserve alternate-path retries and separate
trust anchors. Revocation is explicitly absent. The independent review found
and corrected acceptance of preloaded transcript hash state at construction;
initial reset, algorithm stability and failure retirement have regressions.

The checked corpus is 4,047 cases across nine operations. Lean checks 75 model
and 16 linked theorems; the fifth linked Rust helper is the exact HKDF-label size
guard, including safe arithmetic and minimum mandatory-format footprint.
Published RFC8448 composition covers transcript hashes, derived record keys,
server Finished and an exact application record. Historical certificate bytes
remain opaque in that trace; maintained PKI uses separate valid fixtures.
See current validation for final Rust/fuzz results and exact trust boundaries.

Next integration work: provider-backed fresh X25519/P256 key shares; bounded
hello/extension and Certificate codecs; distinct client/server FSMs that wire
PKI, CertificateVerify and Finished into a real application-release gate;
atomic key installation/KeyUpdate; CCS/alerts/shutdown; authenticated endpoint
interoperability. After equivalent workloads exist, follow the requested
benchmark-first rustls/webpki review and optimize both TLS libraries and webpki
from measured profiles. Full v1 remains open.

## Authenticated client milestone (implemented)

`tls-client` is a reusable std library with immutable shared configuration,
caller-owned scratch buffers and explicit input/output progress. It composes
fresh native X25519/P-256 key agreement, bounded hello/certificate codecs,
offered-selection checks, HRR, streaming transcripts, strict server PKI,
CertificateVerify and Finished. Client application access starts only after the
last ClientFinished record byte is handed to caller output. No socket or runtime
is required; `tls-core` remains no_std.

The engine installs directional application keys, sends automatic KeyUpdate
before its configured cap, handles peer requests, and blocks application writes
while authenticated update messages remain unprocessed. New key preparation
precedes sealing under the old key. Provider-failure tests verify that errors
preserve the expected wire sequence and immediately retire key owners. Pending
or partly handed-off ciphertext cannot be replaced by an alert after failure.
Compatibility CCS, ignored tickets without resumption, alerts, reciprocal
close_notify and truncation have real-record regressions.

The client interop matrix passes 18 suite/group/fragmentation cases plus HRR,
KeyUpdate, authentication negatives, partial-output and shutdown tests against
pinned rustls. Final local checks pass 102 Rust unit/integration tests, 14
ownership doctests and all 16 client integration tests in release. A fresh
28-seed Rust-ASan campaign passes 9,804 executions in 11 seconds. Native AWS-LC
C/assembly sanitizer coverage remains unestablished.

Lean checks 92 model and 21 linked theorems over six extracted production
helpers. The new scalar client phase guard has exact translated semantics;
whole-engine verification evidence, retry bookkeeping and release wiring remain
tested/model assumptions. All 113 theorem closures use standard foundations;
4,923 executable Rust/Lean comparisons pass across ten operations.

Next: server/mTLS and OpenSSL endpoint interoperability, transport examples and
the remaining v1 RFC checklist. Then establish equivalent workload/policy
benchmarks before source optimization of tlsed, rustls and webpki. The client
milestone is interoperability evidence, not a comparative performance result.

## First own-client comparison (measured)

The user requested immediate comparison after the client milestone. The harness
now runs tlsed and rustls0.23.45 clients against the same rustls server with
AWS-LC and shared strict tls-pki certificate validation. Six profiles, five
fresh-process paired repeats and100 samples per workload retain54000 TLS timing
observations; a separate native/strict PKI comparison retains3000 batches.
Client/server authentication and all plaintext bytes are checked. Compilation
and fuzzing stop before timing; repeated-order ratios and environment/source/
binary evidence are retained.

On the primary AES128/X25519 profile, median repeat ratios show tlsed slower
by16% for fresh-buffer handshake,34% for connection lifecycle,1.67x for16KiB
transmit and2.94x for16KiB receive.64-byte receive is36.5x slower; the small
transmit difference crosses parity and is not a robust win. A separate sampling
run plus assembly/source inspection identifies duplicate full-buffer/unused-tail
volatile clearing as the first inbound optimization target. Strong wiping and
failure/Drop guarantees must be preserved, with explicit buffer invariants,
regressions/proof scope and the same benchmark rerun. The valid direct-root PKI
adapter costs about3% over native policy; it is not the dominant observed gap.

See `docs/CLIENT_BENCHMARKS.md`, `docs/PKI_BENCHMARKS.md` and retained raw
results. This measures client+common-server API/transport costs, not isolated
client CPU, all platforms, complete v1 or a global optimality theorem. Source
review now follows measurements as requested; server/mTLS work remains open.

## Plaintext clearing optimization (implemented and measured)

Remove the final redundant whole-loan wipe after application reads, then lend
only the active ciphertext prefix to protected opening. Preserve all consumed
content, type/padding/tag, failure/abort/Drop and handshake/control wipes.
New byte-memory models prove completed-read redundancy and clean-tail
recombination across bounded prefix writes and completed/control cycles.
They remain conditional model proofs with actual Rust/provider orchestration
tested and reviewed; the six linked helpers are unchanged.

Final gates pass109 Rust regressions,14 ownership doctests,21 client release
tests, strict formatting/Clippy, source/translation checks and138 Lean audits
(117 model+21 linked). Fresh-seed ASan passes11759 executions in16 seconds;
native C/assembly coverage remains unestablished. Paired old/new binaries,
alternating order, six repeats and three profiles retain64800 final observations.
AES128/X25519 receive improves36.54x at64B,9.17x at1KiB and1.34x at16KiB;
64-byte receive is now1.03x the native strict-policy pair time. Larger records,
constructor/Drop and broader roles/platforms remain targets. See
`docs/READ_OPTIMIZATION.md` for raw evidence, noise and exact assumptions.

## Public wire clearing follow-up — 2026-10-14

Profiled successful network-prefix and consumed output-prefix zeroize loops;
replaced only already public wire clearing with observable ordinary fill.
Retained all plaintext/key/failure/abort/Drop zeroize. Three live-buffer tests and
ten standalone Lean byte-state/footprint proofs pass; total148 audit closures
(127model+21linked),112 Rust tests,14 compile-fail docs,24 release client tests.
Six paired repeats/three profiles retain64,800 observations:16KiB AES128 TX/RX
improve1.640x/1.475x against the prior optimized engine; after/native1.018x/1.538x.
Fresh Rust-ASan runs14,546 cases; native C/assembly coverage remains unestablished.
See [measured scope](WIRE_CLEARING.md) and [source candidates](SOURCE_COMPARISON.md).
Next experiments: secret-preserving receive/copy changes, connection lifecycle,
bounded native deframer-capacity retention, and strict alternative-issuer PKI.
These do not replace open server/mTLS/OpenSSL/full-v1/platform gates.

## Aligned volatile secret erasure — 2026-10-14

Implemented safe maintained head/u128-middle/tail zeroize for client byte-slice
cleanup. Removed the dominant byte-store loop while retaining compiler-resistant
erasure, exact ranges, secret lifecycle and authentication/nonce/PKI policy.
Twenty new standalone Lean theorems bring audits to168 (147model+21linked);
114 Rust tests,14 docs and26 release client tests pass. Two guarded-range/unaligned
peer tests and exact copied helper Miri on three targets pass. Fresh Rust-ASan
runs23,054 cases; native C/assembly coverage remains unestablished.
Six paired repeats/three profiles retain64,800 observations: AES12816KiB receive
improves1.853x, after/native0.835x; lifecycle1.227x faster but still1.119x native.
See [implementation/proof/timing scope](SECRET_WIPING.md). Remaining lifecycle
core-handshake erasure, native deframer capacity, alternative-issuer PKI and
server/mTLS/OpenSSL/full-v1/platform gates remain separate work.
