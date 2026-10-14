# RFC traceability matrix

Reviewed 2026-10-14. **Experimental authenticated TLS1.3 client; no server or complete v1.**
Normative source: [RFC 9846](https://datatracker.ietf.org/doc/html/rfc9846), July 2026,
obsoleting RFC 8446. Implemented statuses describe the restricted client or
named component, not all-RFC compliance. Foundation denotes a local model.
Native client/provider-failure evidence is in [CLIENT_INTEROP](CLIENT_INTEROP.md);
maintained crypto, PKI and whole-endpoint refinement boundaries remain explicit.
See [proof ledger](../verification/PROOF_LEDGER.md) for exact theorem evidence.

| Requirement / acceptance evidence needed | Reference | Component | Status |
|---|---|---|---|
| Ordered client/server handshake; illegal messages abort | 9846 §4, §2 | distinct FSMs | Private actual client phase and body validation implemented; cert/name/CV/Finished checks precede transitions; native positive/negative tests; server FSM pending |
| Transcript includes handshake headers, excludes record headers; HRR message_hash | 9846 §4.1 | transcript | Streaming SHA256/384, single guarded HRR rewrite and actual client transcript wiring implemented; published vectors/native HRR; whole refinement pending |
| ClientHello/ServerHello syntax, offered selections, downgrade refusal | 9846 §4.2.1–4.2.3 | codec/policy | Bounded codecs and offered suite/group/version checks implemented in client; TLS1.2/earlier never accepted; native negotiation coverage, wider negative corpus pending |
| At most one HRR; changes CH; consistent cipher/group | 9846 §4.2.4 | handshake | Client hello/HRR selection checks, bounded cookie and group-change fresh share implemented; all-suite native HRR and replayed duplicate-HRR alert10 regression |
| Allowed extension placement; reject duplicates/unsolicited responses | 9846 §4.3 | codec/policy | Implemented duplicate, placement and unsupported/unsolicited response rules in bounded hello/certificate codecs; restricted extension profile |
| TLS1.3 supported_versions; TLS1.2 and earlier excluded by project | 9846 §4.3.1; 9325 §3.1 | config | Client advertises/accepts TLS1.3 only; lower-version/invalid selections rejected; native server also restricted to TLS1.3 |
| Signature schemes and certificate algorithm consistency | 9846 §4.3.3 | provider/policy | Client offered-scheme whitelist and maintained verified-token key/signature compatibility implemented; legacy PKCS1 handshake schemes disabled |
| X25519/P256; validate shares; fresh KeyShare each connection | 9846 §4.3.7–4.3.8, §7.4 | provider | Maintained consuming AWS-LC ephemeral owner, native point/low-order checks and new connection/group-retry shares; RFC7748/native pair tests; native erasure/RNG trusted |
| EE immediately follows SH; explicit client-cert policy | 9846 §4.4.1–4.4.2 | handshake | Private client phase enforces EE after SH; CertificateRequest/client authentication unsupported and rejected; server/mTLS pending |
| Chain, SAN identity, validity, usage and trust policy | 9846 §4.5.1; 5280 §6; 9525 §4–§6 | PKI | Bounded maintained chain/SAN/path/time/EKU/strict KeyUsage validation wired into client; alternative-path tests; explicit NoRevocationData, no CRL/OCSP assertion |
| CertificateVerify context and signature | 9846 §4.5.2 | transcript/provider | Private owned verified-leaf token and actual client transcript/order gate implemented; maintained ECDSA/Ed25519/RSA-PSS signatures and native CV mutation rejection |
| Finished MAC and transcript; authentication before client data release | 9846 §4.5.3 | handshake | Native HMAC verification and RFC8448 composition; client data blocked until final ClientFinished byte handoff; native Finished mutation/handoff/provider-failure tests |
| NewSessionTicket ignored without resumption | 9846 §4.7.1 | engine | Bounded complete frame silently ignored, body semantics not interpreted and no ticket cache; authenticated NST then application regression; resumption deferred |
| KeyUpdate ordering, reciprocal response, update-count limit | 9846 §4.7.3 | key schedule/FSM | Automatic/reciprocal updates and bounded epochs/post-handshake messages implemented; next-key preparation before old-key seal, nonfallible installation and InputPending gate; native/fault tests |
| Compatibility CCS valid body0x01 only between first CH and peer Finished; dispatch/drop before deprotection | 9846 §5, Appendix E.4 | engine record dispatch | Client dispatch drops valid plaintext compatibility CCS before AEAD in allowed window; rejects wrong/protected/late CCS; ciphertext-only component validator remains distinct |
| Bounded plaintext <=2^14; header/legacy version rules | 9846 §5.1 | framer | Record/reassembly framing and actual client dispatch implemented with caller buffers and configured cumulative/per-drive limits |
| Ciphertext <=2^14+256; authenticated header; reject AEAD failure | 9846 §5.2 | record/provider | Three-suite protected component and actual client record wiring implemented; RFC8448 vectors, tamper/wipe and native AEAD rejection pass |
| Independent directional sequence numbers, reset with fresh key, no wrap | 9846 §5.3 | counter/provider | Independent owned counters/XOR nonces and fresh actual client epoch installation implemented; no rollback; key-preparation fault alerts authenticate at correct old sequence |
| Inner content type, padding and limits | 9846 §5.4 | protected record | Strict decode/zero padding/inner cap implemented; numeric guards linked/proved |
| MUST update before algorithm-specific key limits | 9846 §5.5; 9325 §4.4 | record/provider | Conservative suite send caps trigger automatic KeyUpdate before exhaustion; native cap-3 emitted-record tests and next-key-import failure lifecycle evidence |
| close_notify, truncation, fatal alerts, user_canceled/general_error | 9846 §6 | engine/adapters | Client clean close/unclean EOF, ignored user_canceled and fatal peer alert/no reply implemented; pending/partial output discarded on abort; native/fragment/fault tests; adapters pending |
| HKDF labels, hash binding, epoch-specific traffic secrets/IVs | 9846 §7.1–7.3 | provider/key schedule | Typed no-PSK schedule and actual client key installation implemented; RFC8448/SHA384 fixtures, linked label guard and native transition-failure tests; whole refinement pending |
| Mandatory algorithms/extensions and project defaults | 9846 §9; 9325 §4.3 | config/provider | Client implements three TLS1.3 suites, X25519/P256 and configured signature/extension profile; no complete mandatory-feature/v1 conformance claim |
| SNI bound to intended peer/application protocol | 6066 §3; 9325 §3.7 | handshake | Client DNS SNI derived from explicit reference identity and checked EE acknowledgment; IP references omit DNS SNI; no caller/peer identity inference |
| ALPN offered-selection validation, fatal no-overlap behavior | 7301 §3.1–3.2; 9325 §3.8 | handshake | Single configured ALPN requires exact EE selection; native bench/1 interoperability; broader application/server policy pending |
| record_size_limit 64..2^14+1 and directional negotiated caps | 8449 §4 | config/record | Pending; global cap is not this extension |
| 0-RTT anti-replay and application policy | 9846 §2.3, §8; 9325 §3.10 | policy | Disabled; deferred |
| PSK+ephemeral resumption, tickets/cache bounds | 9846 §4.3.9–4.3.11, §4.7.1 | session | Deferred v1.1 |
| QUIC CRYPTO handshake separate from TLS records | 9001 §4–§5 | future adapter | Deferred, architecture input only |
| Hybrid KEX | 9954, 10024 | future provider | Deferred; not enabled by baseline |
| Legacy RSA PKCS#1 handshake signatures | 9963 | policy | Disabled; optional reference not implemented |

## Revision traps

RFC9846 §1.2 lists changes; never transplant 8446 section numbers. Transcript
moves from 8446 §4.4.1 to 9846 §4.1, HRR from §4.1.4 to §4.2.4,
authentication from §4.4 to §4.5, and KeyUpdate from §4.6.3 to §4.7.3.
The implemented client covers fresh key shares, HRR transcript/selection checks,
mandatory key-limit updates, bounded post-handshake messages and alert cases.
Continue reviewing PSK/HRR hash clarification and deferred features; track
KeyUpdate count bounds, corrected vector bounds, generic KEM language, revised
RSA wording, and alert semantics against this restricted profile and future extensions.

Supporting sources: [RFC9325](https://www.rfc-editor.org/rfc/rfc9325.html),
[RFC5280](https://www.rfc-editor.org/rfc/rfc5280.html),
[RFC9525](https://www.rfc-editor.org/rfc/rfc9525.html),
[RFC8449](https://www.rfc-editor.org/rfc/rfc8449.html),
[RFC7301](https://www.rfc-editor.org/rfc/rfc7301.html),
[RFC9001](https://www.rfc-editor.org/rfc/rfc9001.html).
This matrix is a review checklist covering v1 scope, not a claim that every
normative sentence has already been implemented or tested.


Remaining acceptance gates are server/mTLS, OpenSSL endpoint interoperability,
transport/runtime adapters, record_size_limit, resumption, whole endpoint
refinement, resource stress, independent security review and controlled fair
benchmarks. Thirteen interop tests plus three provider-fault tests support the
experimental client; they are not a performance comparison, external audit or
proof of every requirement in this matrix.
