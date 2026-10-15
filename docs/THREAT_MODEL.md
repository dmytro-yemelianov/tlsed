# Threat model

Status: **experimental authenticated TLS1.3 client, incomplete v1, not externally
audited**. Security objectives derive from [RFC9846 §1 and Appendix F](https://www.rfc-editor.org/info/rfc9846/)
and [RFC9325](https://www.rfc-editor.org/rfc/rfc9325.html).

An attacker controls transport bytes, fragmentation, timing, server messages,
certificates, selections and connection churn. They may impersonate servers,
replay traffic, force errors and exhaust CPU/memory. This implemented profile
authenticates the configured server through a fresh no-PSK handshake; it has no
server endpoint or client authentication. Post-handshake confidentiality/integrity
assumes maintained primitives, fresh secure randomness and trusted verification
configuration. TLS does not hide packet sizes, SNI, addresses or all timing.
Compromised endpoints, roots, private keys, RNG, clocks, OS and hardware are
outside the protocol-model guarantees.

| Threat | Implemented control | Evidence / remaining limit |
|---|---|---|
| Malformed/oversized/fragmented input | Caller-buffer record/handshake caps, checked arithmetic, per-drive work and cumulative message/byte caps | Component/endpoint tests and bounded fuzz campaigns; adversarial stress and external review pending |
| Authentication bypass/order confusion | Private client phase; actual chain+SAN+usage, CV and Finished gates; application blocked through final ClientFinished-byte handoff | Native rustls suite/group matrix, independent vectors, CV/Finished mutations, handoff interleaving; no full endpoint refinement proof |
| Modified records | AEAD header/payload authentication before release, whole output wiping on errors | Three-suite vectors, tamper tests and native endpoint rejection; backend trusted |
| Nonce reuse/epoch confusion | Separate serialized directions, fresh keys, nonwrap counters, reserve before crypto; prepare replacement keys before sealing control records | Native provider-fault tests authenticate correct old-key alerts; pending/partial output discarded on abort, never replaced or rewound |
| Key-limit exhaustion/KeyUpdate storm | Conservative suite sending caps, proactive automatic updates, reciprocal response, epoch/post-handshake message limits | Three-suite update interoperability and exact NeedWork/InputPending race regression; wider sustained stress pending |
| Downgrade/selection confusion | TLS1.3-only offered suites/groups/schemes, exact ALPN, duplicate/placement checks, one HRR | Native HRR and duplicate-HRR rejection with expected alert; broader negative negotiation corpus pending |
| PKI impersonation | Explicit anchors/name/time; native chain/SAN/EKU/constraints plus strict maintained-parser KeyUsage checks | Positive/negative name/path/time/usage/CV tests; explicit no CRL/OCSP validation, broader PKIX profiles pending |
| Secret leakage | Nonclone/non-Debug key owners, redacted test secret capture, zeroization, terminal retirement | Counting-provider keys all Drop while failed connection remains alive; native erasure, compiler copies, dumps and constant-time behavior not proved |
| Replay | Fresh consuming X25519/P256 exchange; HRR replacement share; authenticated record sequences | Provider vectors/fresh agreement and endpoint tests; resumption and 0-RTT disabled |
| Truncation/cancellation/partial output | close_notify differs from unclean EOF; ignore user_canceled; fatal peer alerts receive no response; queued/partial wire discarded on abort | Native closure and authenticated mid-fragment alert cases, EOF with queued/partial Finished/app record; caller must honor handoff and shutdown semantics |
| Resource exhaustion | Configured body/work, cumulative handshake, certificate, cookie, post-handshake and key limits; no ticket cache | Bounded native PKI preflight and framed NST discard; CPU bounds include trusted native path-building budgets, not global timing guarantees |
| Side channels | Maintained native crypto and authentication APIs | No end-to-end constant-time or erasure claim; profiling/security review pending |

Root anchors and reference identities come from trusted application
configuration, never unauthenticated peer certificates or SNI alone.
[RFC9525](https://www.rfc-editor.org/rfc/rfc9525.html) identity validation is
separate from [RFC5280 §6](https://www.rfc-editor.org/rfc/rfc5280.html) chain
validation. Caller-supplied UnixTime is a verification input, not proof that a
trusted clock is available. Root updates, revocation policy and clock failures
require explicit deployment policy. The implemented `NoRevocationData` profile
makes no revocation assertion.

Applications supply `Arc<ClientConfig>` and borrowed scratch buffers, serialize
connection mutation, process consumed/produced counts and distinguish recoverable
backpressure from fatal failure. Local ClientFinished handoff is not delivery
acknowledgment. No sockets/runtime live in the engine. Neither tests nor abstract
Lean theorem passage establish Internet deployment readiness. See
[client evidence](CLIENT_INTEROP.md), [provider](CRYPTO_PROVIDER.md),
[key agreement](KEY_AGREEMENT.md), [PKI](PKI.md) and the
[proof ledger](../verification/PROOF_LEDGER.md).

Remaining gates include server/mTLS implementation, OpenSSL endpoint
interoperability, transport adapters, negotiated record_size_limit, resumption
policy, full endpoint refinement, resource stress, provider/dependency and
independent security reviews, and controlled equivalent-policy benchmarks.
There is no performance win, all-RFC conformance or full-v1 readiness claim.

Aligned client secret erasure trusts pinned bytemuck1.25.2 for a safe disjoint
u8-head/u128-middle/u8-tail view and zeroize1.9.1 for volatile writes of the zero
representations. The view performs no allocation/secret-value copy. Own unsafe
is still forbidden. Exact loan effects are tested and modeled; source-hashed
helper Miri on ARM64/32-bit/big-endian targets does not prove native erasure,
compiler correctness or full engine safety. See [current scope](SECRET_WIPING.md).
