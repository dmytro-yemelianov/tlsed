# Compare with rustls: measurements first, code second

Requested by the user on 2026-10-14. This extends the original competitive
baseline requirement without replacing the active protocol implementation work.
Reference repository: [rustls/rustls](https://github.com/rustls/rustls).
The user also explicitly included correctness review and optimization of webpki.

The [first own-client benchmark](CLIENT_BENCHMARKS.md) and
[standalone PKI results](PKI_BENCHMARKS.md) are now measured and retained.
Source review follows those observations; no production performance patch has
yet been applied in that original baseline. The subsequent
[buffer optimization](READ_OPTIMIZATION.md) has paired measurements and explicit
Lean invariant models. The [public wire follow-up](WIRE_CLEARING.md) adds a
second paired optimization and [source review](SOURCE_COMPARISON.md) scopes
rustls capacity retention and alternative-path PKI experiments. Server/full-v1
and wider platform/profiling gates remain open.

## Order and gates

1. Establish the authenticated endpoint functionality needed for each chosen
   workload. The experimental client now interoperates with rustls; the server
   and complete v1 remain open. Identify the exact
   functionality both implementations can actually execute.
2. Run controlled, repeatable benchmarks first, beginning with equivalent
   overlapping components and then complete authenticated handshakes/records.
   Label client-only comparisons separately from unimplemented server/full-v1 workloads.
3. Use measured profiles to guide a code comparison at pinned commits. Explain
   the implementation choices responsible for observed CPU, allocation, memory,
   copy, buffering and latency differences.
4. Propose improvements for **both** tlsed and rustls. Validate local changes with
   their respective regression/security checks and rerun the same benchmarks.
   Keep unsuccessful hypotheses and overhead tradeoffs in the report.

## Controlled benchmark design

Pin rustls release and source commit, our source snapshot, compiler, AWS-LC,
webpki, platform and build flags. The existing reference uses rustls 0.23.45;
recheck that choice when starting the experiment. Follow
[rustls benchmark guidance](https://github.com/rustls/rustls/blob/main/BENCHMARKING.md).

Use the same crypto provider, TLS 1.3 suites/groups, certificates/roots, identity
verification, ALPN, payload sizes, padding and session policy. Measure both
directions and roles. Separate record crypto, transcript/HKDF, framing and PKI
microbenchmarks from end-to-end transport/API costs. Full handshake tests include
validating the peer; they never turn verification off to improve a number.

Record raw repeated samples, confidence/variance and warmup. Alternate runs and
document core/frequency/power/scheduler controls. Measure throughput, handshake
p50/p95/p99, allocations, connection/record memory, copies and CPU profiles.
Include tiny buffers, fragmentation/coalescing, invalid input and connection churn.
Test ARM64 and x86-64 when machines are available; missing-platform measurements
remain explicit gaps. Resumption is compared only when actually implemented.

## webpki validation and profiling

Review pinned webpki and our adapter's validation contracts independently before
proposing changes. Exercise path constraints, BasicConstraints, KeyUsage/EKU,
DNS/IP SAN identity, name constraints, validity, algorithm/key compatibility,
malformed or duplicate extensions, ambiguous/cross-signed chains and bounded
failure paths. Preserve native validation errors and distinguish intentional
backend policy from defects. Revocation capabilities and trust-anchor treatment
must be explicit in every compared profile.

Benchmark PKI separately with identical roots, chains, identity, time and policy.
Measure successful and rejected paths, many irrelevant intermediates/roots,
cross-signing, RSA/ECDSA/Ed25519, allocations and peak memory. Separate chain
construction, signature verification, name matching and our extra strict
KeyUsage parser checks. A rustls default-policy run and our stricter KeyUsage
profile are labeled separately unless equivalent checks are applied to both.

Use CPU/allocation profiles to justify source review and optimization candidates
in webpki as well as both TLS libraries. Any caching proposal must identify the
trust-store/policy/time/identity/revocation invalidation rules before implementation.
Retain negative regressions and rerun the same workload for every local patch.
Upstream reports or submissions require a separate request.

## Review and improvement artifacts

After benchmark evidence exists, produce a table mapping each measured hotspot
to both implementations, source locations, an explanation, a change hypothesis,
security/proof obligations and isolated before/after measurements. Look at buffer
ownership, per-record allocations, batching, state storage, transcript snapshots,
HKDF info storage, certificate validation and error paths according to the profiles.

Keep protocol compliance and maintained-provider trust explicit. A smaller/faster
path with missing functionality is not equivalent functionality. Improvements must
preserve authentication, key/nonce limits and resource bounds. Our affected pure
components require their Lean checks; rustls changes require its test/benchmark
workflow and review. Upstream findings/local patch candidates are reviewable
deliverables; publication or messages to maintainers are separate actions.

The subsequent [aligned volatile secret-wipe implementation](SECRET_WIPING.md)
resolves the former large receive deficit in a new paired local experiment.
Cipher/provider/PKI policy remains, and lifecycle/native-capacity/alternative-path
PKI plus broader platform/server/full-v1 gates remain distinct follow-ups.
