# Experimental authenticated client engine

`tls-client` is a reusable TLS 1.3 client library driven through caller buffers.
It performs a full no-PSK server-authenticated handshake using maintained
AWS-LC and webpki, then exchanges protected application records. It supports
AES-128-GCM/SHA-256, AES-256-GCM/SHA-384, ChaCha20-Poly1305/SHA-256, fresh X25519
and P-256 shares, one HRR, automatic/reciprocal KeyUpdate, alerts and shutdown.
Its source is safe Rust. This std crate uses `Arc` configuration and bounded
handshake allocations; the underlying `tls-core` remains no_std.

## Configuration and buffers

`ClientConfig::new(roots, alpn, suites, initial_group, limits)` validates explicit
roots and resource policy. Share it through `Arc<ClientConfig>`. Each connection
also requires a trusted `ServerName<'static>`, explicit `UnixTime`, a
`KeyExchangeProvider` (normally `AwsLcProvider`) and four mutable buffer loans.
The caller provides trustworthy time at construction; the engine does not load
system roots, read a clock, own sockets or choose a runtime.

DNS/IP SAN identities are supported, with no CN fallback. DNS references send
SNI; IP references omit it. ALPN is one exact protocol or empty to disable it;
when enabled, the server must select that protocol. Server-chain validation
uses the documented strict KeyUsage supplement and explicit
`RevocationPolicy::NoRevocationData`. Revocation is absent.

| `ClientBuffers` field | Required size |
|---|---|
| `record` | `RECORD_BUFFER_SIZE = 16645` |
| `handshake` | `limits.handshake_body + 4` |
| `plaintext` | `PLAINTEXT_BUFFER_SIZE = 16640` |
| `outbound` | `RECORD_BUFFER_SIZE = 16645` |

The connection borrows these buffers for its lifetime, reuses them and wipes
accepted loans on abort/Drop. Constructor preflight errors do not promise to
wipe rejected caller storage. Native providers may allocate and copy; there is
no measured zero-allocation or complete native-erasure claim.

| Limit | Default |
|---|---|
| Handshake body | 65,536 bytes |
| Transcript bytes / messages | 1,048,576 / 32 |
| Handshake reassembly copy per step | 4,096 bytes |
| Certificates / each DER / chain DER | 8 / 65,536 / 262,144 bytes |
| HRR cookie | 4,096 bytes |
| Sending records per key | 2^24 |
| Post-handshake messages | 1,024 |

The handshake-message cap also bounds the entire Certificate encoding, so the
effective chain size can be tighter than the separate DER-chain limit. Config
rejects impossible/unsupported policy, duplicate suites, zero work and a send
cap below two or above an offered suite's maintained bound. A drive step handles
at most one wire record or one bounded handshake-copy step/message. Record
decryption and a maintained certificate verification are indivisible operations;
`work_bytes` is a copy budget, not a wall-clock or cryptographic instruction cap.

## Driving and backpressure

Construction queues ClientHello. Call `drive(input, network_output)` and retain
any input beyond `Progress.consumed`. Transmit exactly `Progress.produced`
output bytes in order. The connection hands bytes to a caller buffer; it cannot
confirm that a socket transmitted them. The caller must preserve that ordering.

| Status | Caller action |
|---|---|
| `NeedInput` | Supply more network bytes. |
| `NeedOutput` | Supply output space and deliver queued bytes before later records. |
| `NeedWork` | Call again, even with empty input, to process retained handshake bytes. |
| `HandshakeProgress` | Continue using consumed/produced counts. |
| `HandshakeComplete` | ClientFinished handoff completed; application APIs are available. |
| `ApplicationData` | Drain `read_plaintext` before supplying additional records. |
| `Closed` | Peer close_notify was processed; drain any queued reciprocal close. |
| `Failed` | Terminal; only already-queued alert output may remain. |

Queued output takes priority and consumes no new input. Zero output capacity is
supported and preserves pending bytes. Application reads/writes require private
Established state, reached only after chain plus reference identity,
CertificateVerify, server Finished and the final ClientFinished wire byte
handoff. A queued or partly copied Finished does not establish the client.

`write_plaintext(input)` queues at most 16,384 plaintext bytes. A zero return for
nonempty input can mean an automatic KeyUpdate was queued: drain it, then retry
the same application input. `OutputPending` and `InputPending` are recoverable;
the latter blocks writes while authenticated handshake bytes or a partial
post-handshake message still need processing. `read_plaintext(output)` drains
retained authenticated application bytes and wipes consumed storage.

The plaintext backing starts zero and admits a new record only after previous
application bytes are consumed or retained handshake bytes are processed.
Protected opening uses only the active ciphertext-length prefix; untouched
backing stays zero. Core opening clears type/padding/tag inside that prefix,
and reads clear consumed content ranges. At completion the whole loan is
already zero, so no repeated full-loan wipe runs. Handshake/control/failure/Drop
full wipes remain. A debug assertion checks clean backing before protected
opening. See [models, regressions and paired timings](READ_OPTIMIZATION.md).

`is_established`, `negotiated_suite`, `retried` and `alpn` expose negotiated
state; they do not expose traffic secrets. `drain_output` copies pending bytes
without accepting input, including an already-queued fatal alert after error.
Successful receive clears only the immutable peer-wire prefix; drain clears
only wire bytes already copied to the transport. These public ranges use ordinary
`fill(0)`, preserving the observable clean state. Secret plaintext, failed seals,
abort and Drop retain compiler-resistant `zeroize`. No compiler-resistant erasure
claim applies to the public-wire fills. See [wire clearing](WIRE_CLEARING.md).

`drive` errors are terminal; inspect the original typed error, drain any alert,
and retire the connection. Do not retry a failed connection with new input.

## Key changes, control messages and closure

Key transitions require complete handshake messages at the physical record
boundary. ClientFinished and KeyUpdate are sealed under their old write key.
The new material/key owner is prepared before sealing consumes the old nonce;
installation follows without another fallible preparation step. Output
backpressure prevents newer-key application records from overtaking these
messages. Every update derives fresh directional traffic material and resets
its own sequence counter; epochs cannot wrap. Per-key send limits reserve space
for an update, and a bounded post-handshake count also limits update traffic.

Compatibility CCS is accepted only with body `01` after ClientHello handoff and
before server Finished; dispatch discards it before protected-record opening.
Protected/late/malformed CCS fails. Without resumption, bounded authenticated
NewSessionTicket messages are ignored without interpreting or caching tickets.
`user_canceled` is advisory; fatal peer alerts terminate without a response.

`close_notify()` queues a protected close and retires the sending key after
sealing. Continue draining output and receiving the peer close. `finish_input()`
reports clean EOF only after peer close_notify with no incomplete record/message;
otherwise it fails as truncation. An error discards pending/partly handed-off
output instead of substituting a different record at a consumed nonce. Key,
ephemeral, traffic-secret, transcript and verified-leaf owners retire immediately.
Rust Drop/zeroization evidence does not prove native erasure or absence of
compiler copies.

## Evidence and remaining scope

[Native rustls interoperability](CLIENT_INTEROP.md) covers negotiation, verified
duplex data, HRR/KeyUpdate, ordering, alerts, EOF and injected provider failures.
[The validation report](../verification/results/VALIDATION.md) records tests,
fuzzing and Lean. The extracted phase guard is proved; the whole engine's
verification evidence, retry bookkeeping, I/O and release composition are tested.
Record-count/label-footprint optimality applies only to the stated mathematical
costs, with no global TLS speed claim.

Server/mTLS, CertificateRequest/post-handshake authentication, resumption/0-RTT,
record_size_limit, multiple ALPN offers, transport adapters/examples and OpenSSL
endpoint interoperability remain open. Controlled rustls/webpki benchmarks and
independent security review remain gates before deployment claims.

## Aligned secret erasure

Client byte-slice constructor/read/control/failure/abort/Drop erasure delegates
to maintained zeroize over a safe bytemuck byte-head/aligned-u128-middle/byte-tail
view. Exact live clearing and compiler-resistant stores are preserved, with
no own unsafe, allocation, secret-value copy or API alignment requirement.
Core/provider/typed-secret wipes remain unchanged. [Measured implementation and
verification scope](SECRET_WIPING.md) documents the new trusted view boundary,
unaligned real-peer tests, three-target isolated Miri and standalone Lean model.
