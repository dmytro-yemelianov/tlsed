# Architecture and provider decision

**Experimental authenticated TLS 1.3 client; not a server or complete v1.**
`tls-client` now composes the bounded `tls-core` codecs, protected records,
streaming transcripts, typed no-PSK key schedule, fresh maintained key exchange
and `tls-pki` verification into an actual transport-independent client endpoint.
Real rustls interoperability and provider-failure tests support this restricted
profile; they do not establish every RFC requirement, an endpoint refinement
proof, external audit or performance superiority. `tls-bench` still contains
reference baselines plus a [measured client comparison](CLIENT_BENCHMARKS.md)
against the same native server with shared strict PKI policy.

```text
application / caller-owned transport and scheduling
    -> ClientConnection::drive / drain_output / plaintext / EOF APIs
        -> private client phase and bounded handshake reassembly
        -> hello codecs / transcript / key schedule / server identity gates
        -> independent protected inbound/outbound epochs
            -> AWS-LC crypto and fresh X25519/P-256 key exchange
            -> maintained webpki + strict KeyUsage policy
```

The application supplies immutable `Arc<ClientConfig>`, explicit trust roots,
DNS/IP reference identity and `UnixTime`. It supplies four buffers borrowed for
the connection lifetime: record/outbound at least16645 bytes, plaintext at
least16640 bytes, and handshake at least configured body limit+4. The engine
owns mutable connection state and provider key owners; the caller owns sockets,
output handoff, scheduling and backpressure. `drive` reports consumed/produced
counts and bounded work/input/output statuses. Default body/work limits are
65536/4096 bytes; accumulated handshake bytes/messages, certificate count,
per-certificate/aggregate DER, cookie bytes, post-handshake messages and sending
records per key also have configured caps. Bounded configuration, owned verified
leaf and maintained crypto/PKI operations may allocate; this is not a
heap-free handshake or allocation-free native key-agreement claim.

The private phase admits ServerHello, EncryptedExtensions, Certificate,
CertificateVerify and server Finished in order. Actual chain/name/usage,
signature and Finished checks precede their phase transitions. A private owned
verified-leaf token carries the authenticated leaf to CertificateVerify without
repeating path validation. Client application reads/writes remain blocked until
the last queued ClientFinished byte is handed to the caller's transport buffer.
This establishes local handoff, not network delivery or acknowledgment. A
single HRR uses the transcript message_hash rewrite, consistent selections,
bounded cookie and fresh replacement share; duplicate HRR is rejected.

The client advertises only its implemented TLS1.3 suites, groups and signature
schemes. Hello codecs enforce vector bounds, duplicate/placement/unsupported
extension rules and offered selections. SNI comes from the configured DNS
reference; IP reference identities do not imply DNS SNI. ALPN is one configured
protocol with exact server-selection validation. Supported-groups in EE is a
capability hint rather than a selected group. CertificateRequest/client
authentication and arbitrary extension profiles remain outside this client.

Protected directions reserve nonces before crypto and never rewind them.
Application-key preparation and transcript freezing finish before sealing
ClientFinished; prepared keys are then installed without further fallible
provider work. Automatic sending-limit and requested reciprocal KeyUpdates
prepare their next secret/key before sealing the update under the old key,
then install the next epoch. Pending output preserves old/new wire ordering.
`InputPending` prevents application writes while a retained/fragmented control
handshake could require a response. Epoch and post-handshake limits bound
updates. A bounded complete NewSessionTicket frame is silently ignored because
resumption is disabled; no ticket/PSK cache or ticket semantic parsing is exposed.

The connection dispatcher drops valid plaintext compatibility CCS before AEAD
only in its allowed handshake window; protected/wrong-body/late CCS is rejected.
AEAD failure releases no plaintext. Clean close_notify differs from unclean
EOF; user_canceled is ignored while awaiting closure. A fatal peer alert
terminates without a reciprocal error alert, including mid-fragment. Other
failures may queue a best-effort mapped fatal alert. If output was already
queued or partly handed off, abort discards it and sends no replacement record:
a consumed nonce or partial wire cannot be rolled back. Terminal failures
retire key owners and wipe retained plaintext/scratch storage; a permitted
fatal wire alert remains available only until drain or Drop. A failed connection
cannot resume by receiving more input. See [client evidence](CLIENT_INTEROP.md).

## Maintained provider and identity boundary

Pins are **aws-lc-rs1.18.2**, **rustls-webpki0.103.15**, and reference
**rustls0.23.45**; Cargo.lock fixes their transitive native/provider types.
This is not a FIPS build or certification claim. The implemented provider
supports AES128GCM/SHA256, AES256GCM/SHA384, ChaCha20Poly1305/SHA256,
streaming SHA256/384, HKDF, native HMAC verification, secure native randomness
and consuming X25519/P256 ephemeral owners. Native RNG, point validation,
C/assembly execution and erasure remain trusted. See [key agreement](KEY_AGREEMENT.md),
[provider](CRYPTO_PROVIDER.md), [transcript](TRANSCRIPT.md),
[key schedule](KEY_SCHEDULE.md) and [record](PROTECTED_RECORDS.md).

[rustls-webpki](https://github.com/rustls/webpki/tree/v/0.103.15) validates the
server chain, EKU, constraints, validity and DNS/IP SAN identity against explicit
anchors/time. The maintained-parser supplement enforces leaf digitalSignature
and selected-issuer keyCertSign when KeyUsage exists; trust anchors remain
separate. No CN fallback, custom X.509 verifier or accept-invalid option exists.
Server CertificateVerify permits ECDSA P256/SHA256, Ed25519 and RSA-PSS rsae;
legacy RSA PKCS#1 handshake schemes remain disabled. The declared
`NoRevocationData` profile does not validate CRL/OCSP. Root updates, trusted clock
availability, system root loading and broader identity profiles are application
or future adapter responsibilities. See [PKI](PKI.md).

## Verification boundary and remaining work

Lean and translated Rust evidence covers only named pure guards/models in the
[proof ledger](../verification/PROOF_LEDGER.md). The actual private phase invokes
maintained checks before guarded transitions, with native endpoint tests, but
there is no full refinement proof of parsers, buffers, crypto/PKI, provider
failure paths or the entire client. Counter uniqueness also assumes fresh keys
and serialized mutation. Crypto/PKI, C FFI, compiler, extraction tools, Lean
kernel, RNG, time, OS and hardware remain trusted. Functional proofs do not
establish constant-time execution, erasure, protocol secrecy or global speed.

Remaining work includes a server endpoint, mTLS, OpenSSL endpoint
interoperability, transport/runtime adapters, negotiated record_size_limit,
resumption, independent security review, resource stress and controlled fair
broader benchmarks/profiling. The first local client and PKI comparison is
measured; no performance patch or global optimum follows from it. QUIC consumes
handshake bytes and secret exports rather than these
TLS records ([RFC9001 §4–§5](https://www.rfc-editor.org/rfc/rfc9001.html)); its
adapter remains deferred. Reference implementation capabilities are described
by [pinned rustls AWS-LC source](https://github.com/rustls/rustls/tree/v/0.23.45/rustls/src/crypto/aws_lc_rs).
