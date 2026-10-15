# Streaming handshake transcript

`tls_core::transcript::Transcript<H>` hashes exactly one complete encoded
handshake message per append through a maintained `HashContext`. It retains
provider state and fixed metadata, without keeping transcript byte history.
Construction resets the supplied context, including previously updated contexts,
and rejects reset failure or a changed algorithm before creating an owner.
SHA-256 and SHA-384 are selected by the negotiated suite outside this component.
The endpoint must retain or concurrently hash ClientHello until that selection.

[RFC9846 §4.1](https://datatracker.ietf.org/doc/html/rfc9846#section-4.1)
includes the four-byte handshake type/u24 header and excludes record headers.
The input guard rejects truncation, coalesced extra bytes, oversized bodies,
post-handshake messages, early data and externally supplied synthetic type254.
Caller-selected message and cumulative hashing-byte budgets use checked arithmetic.

The component guards initial ClientHello/ServerHello order. After ServerHello,
the role-specific endpoint must enforce exact message order, semantic body checks,
extension placement and authentication. `snapshot` does not advance the hash;
its algorithm-tagged owner has no Clone/Debug and erases its bytes on Drop.
Any invalid active operation or provider error retires the context and makes the
transcript terminal. Failure-injection regressions check Drop and failed snapshots.

## HelloRetryRequest

`apply_hello_retry_request` is permitted once, directly after ClientHello1. It
requires exactly one complete type2 message with the
specified HRR random sentinel. The endpoint must first validate all remaining
hello fields, selected cipher, supported versions/group, extensions and the
required ClientHello2 changes. Ordinary `append` rejects the HRR sentinel.
With a selected supported_versions0304, the endpoint ignores ServerHello's
legacy_version as RFC9846 §4.3.1 requires; transcript hashing still includes
those exact received legacy bytes. Writers emit0303.

The method snapshots Hash(ClientHello1), resets the provider context, and hashes:

```text
fe 00 00 Hash.length || Hash(ClientHello1) || encoded HelloRetryRequest
```

Then only ClientHello2 and a final ServerHello advance its hello phases.
The byte budget counts both the original ClientHello work and the synthetic
rewrite/HRR work. Preflight occurs before the reset. Failed snapshot/reset/update
returns no usable digest and retires the context; provider-internal erasure is
governed by the maintained backend.

`freeze` snapshots and retires an active post-ServerHello context. It asserts
neither Finished success nor certificate authentication. The endpoint chooses
the correct final boundary and must not freeze merely because ServerHello arrived.

## Evidence and limits

SHA-256/384 regressions check ordered encoded bytes, repeatable snapshots,
synthetic HRR rewriting, duplicate/wrong-stage HRR, bounds, malformed input,
freezing and provider failures. A separate RFC8448 composition test checks the
published CH..SH and server-Finished transcript hashes, derives handshake keys,
opens the published server flight, verifies its Finished, derives application
keys and matches the published application record. Historical certificate bytes
are opaque in that test; PKI is tested separately with valid deterministic fixtures.
The independent published RFC8448 §5 HRR transcript hash also matches after
the exact CH1/HRR/CH2/SH rewrite, including a preloaded-context reset regression.

Standalone Lean proofs describe message history, ordered append, guarded HRR
rewriting and conditional Finished binding under an explicit provider-verification
soundness premise. They do not prove hash collision resistance, the Rust streaming
context's refinement, complete handshake ordering, PKIX or endpoint authentication.

```sh
cargo test --locked -p tls-core --test transcript --test rfc8448_composition
```
