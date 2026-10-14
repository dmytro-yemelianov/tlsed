# Experimental client interoperability

`crates/tls-client/tests/interop.rs` drives the real client and a maintained rustls
0.23.45 AWS-LC TLS 1.3 server through an in-memory transport. This is protocol
interoperability evidence, not a benchmark or a proof of the whole endpoint.
The client uses its actual maintained certificate, hostname, CertificateVerify,
Finished, AEAD and fresh key agreement paths. There is no permissive verifier.

The server permits exactly one tested suite and one tested group. The matrix
covers AES-128-GCM/SHA-256, AES-256-GCM/SHA-384 and ChaCha20-Poly1305/SHA-256,
each with X25519 and P-256. Each combination uses one-byte, seven-byte and
coalesced network buffers. Both peers exchange and check application bytes.
ALPN is `bench/1`; only TLS 1.3 is enabled. Session tickets are disabled.
Fresh native random and ephemeral keys are generated each run. The fixed public
CA, P-256 leaf and private key are the existing `tls-bench/fixtures` inputs;
validation time is explicitly 2026-10-15 00:00:00 UTC, within their validity.
These local public credentials must never be deployed.

Additional cases force HelloRetryRequest by offering the client's initial
X25519 share to a P-256-only server, exercise a configured three-record client
sending cap and peer-requested KeyUpdate, and check both-direction application
bytes after updates. The retained encrypted client wire is counted after the
handshake: eight application writes must emit more than eight records under
the cap, and a peer request must emit an additional client response record.
The maintained rustls peer accepts these records and subsequent application
bytes under the updated keys. Wrong hostname, unrelated root, expiration and not-yet-valid
time must fail closed. Application reads and writes cannot release data before
establishment. Clean bidirectional close_notify and unclean EOF are distinct.

Negative cryptographic cases mutate the first real rustls server flight. A
ciphertext bit flip must fail record authentication. For CertificateVerify and
Finished, a test-only rustls KeyLog object retains the server handshake traffic
secret in memory, derives its record key through the existing provider-backed
TLS key schedule, decrypts, mutates a signature or verify_data byte, and reseals
with the same record sequence. This separates handshake verification failures
from AEAD failure. Secrets are never written as NSS logs, included in output or
persisted as fixtures. The helper is confined to integration tests. It requires
whole handshake messages in the current server flight's record layout and
asserts that condition rather than silently skipping a target. It is not a
production handshake parser or a verifier bypass.

On 2026-10-14, all thirteen integration tests passed in debug and release builds;
the success matrix contains 18 suite/group/fragmentation cases, and the HRR/
KeyUpdate test exercises all three suites. Strict all-target client Clippy and
formatting pass. Reproduce with:

```sh
cargo test -p tls-client --test interop --locked
cargo test -p tls-client --release --test interop --locked
cargo clippy -p tls-client --all-targets --locked -- -D warnings
cargo fmt -p tls-client --check
```

These are assertions of successful negotiation and byte exchange or the specified
rejection, not throughput measurements. Passing this bounded
matrix does not establish general Internet compatibility, all malformed-input
behavior, revocation validation, resumption, 0-RTT, client authentication,
post-handshake authentication, endpoint refinement proof or performance superiority.
The primitive/backend and native PKI trust boundaries remain as documented in
`KEY_AGREEMENT.md`, `CRYPTO_PROVIDER.md` and `PKI.md`.

Primary references: [TLS 1.3 RFC 9846](https://datatracker.ietf.org/doc/html/rfc9846),
[rustls 0.23.45 ServerConfig](https://docs.rs/rustls/0.23.45/rustls/struct.ServerConfig.html)
and [pinned rustls source](https://github.com/rustls/rustls/tree/v/0.23.45/rustls/src).

The no-resumption regression additionally injects a well-formed authenticated
NewSessionTicket under the actual server application traffic key at sequence
zero. RFC 9846 §4.7.1 requires a client without resumption support to silently
ignore it. The ticket includes a nonempty nonce/ticket and an unknown,
structurally valid extension; one-byte, seven-byte and coalesced inputs must
leave the connection established without application output. The next record
contains actual rustls-produced application plaintext, reauthenticated at
sequence one after the injected ticket, and must be accepted unchanged. Because
this client omits PSK modes, rustls would not naturally emit the ticket; this
is explicit test-only session-key injection rather than evidence that rustls
issued a ticket. The native server's internal counter does not account for the
injected record, so this one-way test ends after the following application read.
Its application-secret capture has the same redacted Debug, in-memory-only and
zeroization restrictions as the handshake mutation helper.

A separate real-wire negative case sends compatibility ChangeCipherSpec after
Finished and requires rejection with no application release; ordinary rustls
compatibility CCS during the handshake remains covered by successful pairs.

An interleaving regression feeds a complete authenticated native rustls
KeyUpdate into exactly one `drive` call, observes `NeedWork`, and attempts an
application write before processing that pending handshake. It requires the
recoverable `InputPending` refusal, preserves establishment, and checks that
one requested-update response record is emitted before subsequent application
data. Both-direction native interoperability then succeeds for each suite.
This checks a caller-visible race between record authentication and bounded
handshake processing, rather than only a straight-line handshake.

Authenticated alert injections use the same private test-only server application
key: warning `user_canceled` is ignored without a reciprocal alert, followed by
sequence-one `close_notify` with clean EOF and one reciprocal close. A fatal
peer `handshake_failure` must terminate application access and leave no outgoing
response, including via `drain_output`. These are one-way synthetic input cases
at real established sessions, not claims that rustls generated those alerts.


Three additional ordering regressions cover reviewed fail-closed boundaries.
An authenticated partial NewSessionTicket at application sequence zero,
`04 00 00 04 00`, followed by fatal alert `02 28` at sequence one must retain
`PeerAlert(40)` and send no response despite incomplete handshake reassembly.
A real native server flight is processed while caller output has zero capacity:
reads/writes remain `NotEstablished` with ClientFinished queued, after the first
ciphertext byte is handed off, and until the final record byte is handed off.
Only then is the client established; native rustls verifies the complete
Finished and subsequent bidirectional application bytes. Finally the test
replays the actual first HRR from a P-256-only rustls server after locally
retaining CH2. It requires `UnexpectedMessage`, no application release, and
exact plaintext fatal alert bytes `15 03 03 00 02 02 0a`.

## Provider failures and transaction boundaries

`tests/faults.rs` adds three integration tests containing eight injected failure
or EOF cases. A test-only provider delegates cryptography, entropy, hashing and
ECDHE to AWS-LC, wraps native AEAD keys with creation/Drop counters, and injects
one Finished HMAC verification failure or one selected AEAD import failure.
The exact third and fourth imports fail during application-key preparation
after a valid server Finished. No ClientFinished is delivered, application
access remains blocked, and native rustls must authenticate the fatal alert at
handshake sequence zero (`decrypt_error` for failed Finished authentication,
`internal_error` for failed import). Exact import/creation counters confirm the
intended injection point, and all created key owners must Drop before the
failed connection itself is destroyed.

The fifth import fails during automatic KeyUpdate under a three-record cap,
after two application records accepted by rustls. The native peer must decrypt
`internal_error` at the old application-key sequence; no premature KeyUpdate
or rejected application payload is delivered. Four additional cases inject EOF
with ClientFinished or application output queued, either wholly unsent or after
six wire bytes (header plus first ciphertext byte) were handed off. They require
pending output discard, no substitute alert, immediate key-owner retirement,
failed state, and refusal to recover through subsequent input or EOF calls.
This checks transactional preparation before sealing and the inability to rewind
a consumed nonce or replace a partially handed-off record. Drop counters observe
Rust owner lifetimes; they do not prove native key erasure or allocator behavior.

All three fault tests pass in debug and release, with strict all-target Clippy
and formatting. Run:

```sh
cargo test -p tls-client --test faults --locked
cargo test -p tls-client --release --test faults --locked
```
