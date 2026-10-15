# Bounded hello and server-authentication codec

The `tls_core::hello` module supplies allocation-free syntactic components for
an experimental TLS 1.3 client. It does not authenticate a peer, negotiate an
endpoint, validate public keys/certificates, verify signatures/Finished, or release
application data. All parsers borrow complete handshake bodies already bounded
by the caller's reassembly/resource policy. Truncated input is an error at this
layer; incremental network fragmentation belongs to the existing framers.

## ClientHello encoding

`encode_client_hello(&ClientHelloParams, output)` writes the complete handshake
message, including the type-1/u24 header. It emits legacy version 0x0303,
caller-supplied 32-byte random, session ID, suites and zero compression, then
supported_versions (TLS 1.3 only), supported_groups, signature_algorithms and
one key_share. Optional extensions are one DNS SNI, one opaque ALPN protocol,
and an echoed HRR cookie. No PSK, early_data, tickets, status_request/SCT,
legacy TLS negotiation, or insecure verification option is emitted.

Parameters use borrowed bytes/code slices. Session IDs are at most 32 bytes;
ALPN is empty to omit or 1..255 bytes for one protocol. Each suites/groups/
signatures list has 1..64 unique code points, a local resource bound that keeps
configuration duplicate checking bounded. The share group must be in the groups
list. Share/cookie and total extension lengths fit their enclosing wire vectors;
the overall ClientHello is preflighted before output is touched. Invalid parameters
and insufficient output return errors with output unchanged; success leaves its
unused tail unchanged. The encoder neither allocates nor generates randomness.

SNI accepts ASCII DNS LDH labels, 1..63 bytes each, total at most 253, with no
empty labels, wildcard, underscore, leading/trailing hyphen or trailing dot.
Literal IPv4/IPv6 are not encoded as DNS SNI; IP identity verification is an
endpoint/PKI operation. Internationalized names require caller-provided A-labels.
Algorithm support, suite policy, signature/group capabilities, negotiated-group
share length/point validity, secure random generation and ephemeral share
freshness remain caller/provider responsibilities. This codec is not their validator.

## Borrowed server messages

`parse_server_hello(body)` returns `ServerHello` with random/session/suite,
`is_retry`, and either `key_share` or the HRR `selected_group`/cookie views.
Normal ServerHello supports only supported_versions and key_share for this
no-PSK profile. HRR additionally permits cookie, including a cookie-only retry.
TLS 1.3 selected_version 0x0304 is required; compression must be zero and session
ID is bounded. All supported extension duplicates, unsupported extensions,
wrong placement, empty shares/cookies, bad vector lengths and trailing bytes fail.
Version selection ignores legacy_version as RFC 9846 §4.3.1 directs when the
required supported_versions extension is present; generated ClientHello still
uses 0x0303. Exact raw share/cookie bytes remain borrowed, never copied/allocated.

The endpoint must check selected suite/group against offers and provider policy,
exact session-ID echo, retry cipher consistency, one-retry limit, cookie cap,
requested group change and whether the second hello changes anything. The codec
performs no asymmetric agreement or second-hello/session validation. Cookie-only
HRR must not spuriously require a new group selection.

`parse_encrypted_extensions(body)` returns `EncryptedExtensions { alpn,
server_name_ack, supported_groups }`. The SNI acknowledgment has an empty body;
ALPN contains exactly one nonempty protocol; supported_groups is a nonempty
even-length big-endian u16 vector without its inner length prefix. It is a server
capability/preference hint. The endpoint checks extension offer/ALPN selection;
server hints need not all be in the client's group list. Duplicates and every
other extension, including early_data and misplaced versions/key shares,
are rejected for this intentionally narrow offered-extension profile.

`parse_certificate(body, &mut certificate_slots)` parses the initial server
Certificate body into borrowed DER slices and returns a count. Slots are
`&mut [&[u8]]`; callers configure the certificate-count cap through their slot
count and the total-byte cap through reassembly. Empty server chains, nonempty
request context, empty entries, inconsistent u24/vector lengths, trailing bytes
and certificate-entry extensions fail. This ClientHello offers no status_request
or SCT, so accepting their unsolicited entry extensions would be inappropriate.
The first pass fully validates before populating references; all slots are cleared
on error and unused slots remain empty. Work is linear in the bounded body and
stops at the configured count cap; the parser does not allocate or parse ASN.1.
The maintained PKI adapter must validate the chain, algorithms, reference identity,
time and CertificateVerify proof. This server-only parser does not implement
client-certificate/post-handshake request-context semantics.

`parse_certificate_verify(body)` returns `{ scheme, signature }`, requiring one
nonempty exact signature vector with no trailing bytes. Offered scheme, key
compatibility, TLS 1.3 signature input construction and verification remain
endpoint/maintained-verifier responsibilities. Codec success confers no
certificate, identity or signature authentication.

## Standards, checks and limits

References: [RFC 9846 §§4.2–4.5](https://www.rfc-editor.org/rfc/rfc9846.txt),
[RFC 6066 SNI](https://www.rfc-editor.org/rfc/rfc6066.txt), and
[RFC 7301 ALPN](https://www.rfc-editor.org/rfc/rfc7301.txt).

Regressions use published RFC 8448 ServerHello/HRR and the server's first protected
flight, borrowing the exact Certificate/CertificateVerify bodies. Its full
EncryptedExtensions contains a historically offered record_size_limit; this
profile rejects that unoffered extension and separately tests its supported
groups/SNI subset. Additional cases verify ClientHello fields and every extension byte,
cookie-only HRR, arbitrary receive legacy versions, every truncated prefix,
duplicate/unsupported/wrong-placement extensions, vector/chain storage limits,
atomic caller output/slot handling, and DNS/ALPN/configuration negatives.

```sh
cargo test -p tls-core --test hello --locked
cargo clippy -p tls-core --all-targets --locked -- -D warnings
cargo fmt -p tls-core --check
```

No linked parser/encoder refinement proof, full endpoint interoperability, or
external security review is claimed by this module. A real client must connect
these views to its guarded protocol state, exact transcript hashing, provider
operations, identity verification and authenticated data-release policy.
