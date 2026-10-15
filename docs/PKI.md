# Maintained bounded server PKI

`tls-pki` supplies standalone chain, DNS/IP identity and server CertificateVerify
components. **Experimental, no full endpoint or external audit.** It uses
rustls-webpki0.103.15 with AWS-LC, rustls-pki-types1.15.1, and the workspace's
pinned aws-lc-rs1.18.2/aws-lc-sys0.46.0. Native crypto, DER/path code, FFI,
compiler, allocator and supplied trust/time remain outside Lean linked proofs.

## Public contract

```text
ServerVerifier::new(&roots, ChainLimits, RevocationPolicy::NoRevocationData)
verify_server_certificate(&leaf_first_chain, &ServerName, UnixTime)
    -> VerifiedServerCert
VerifiedServerCert::verify_certificate_verify(scheme, transcript_hash, signature)
```

Roots are explicitly trusted DER inputs, never obtained from the peer. They
are converted to owned native trust anchors during configuration. Anchor
extraction does not authenticate the root's self-signature, perform root-store
maintenance or make the root a currently valid end-entity certificate. The
application decides which anchors to trust and must manage root updates.

Before external parse/path verification, `ChainLimits` checks certificate count,
each DER length and checked aggregate bytes. Default limits are8 certificates,
64KiB per certificate and256KiB aggregate. The same checks bound root imports;
applications using larger explicit root stores must configure larger limits.
Limits can be independently stricter and zero caps are rejected. This adapter
borrows already-extracted certificate slices; it does not retroactively bound
TLS certificate-message allocation, entry extensions or previous network
buffering. The engine's message/resource caps remain necessary.

The maintained leaf parser/path verifier checks the chain to supplied anchors
at the supplied UnixTime for `KeyUsage::server_auth`. Native serverAuth policy
requires that purpose if EKU is present; absence of EKU is allowed as described
by [RFC5280 §4.2.1.12](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12).
A clientAuth-only EKU and a CA used as the leaf are rejected in regressions.
Strict X.509 KeyUsage checks supplement this deliberate Web PKI scope:
leaf digitalSignature is required if KeyUsage exists, as
[RFC9846 §4.5.1.2](https://datatracker.ietf.org/doc/html/rfc9846#section-4.5.1.2)
specifies. Each issuing intermediate selected by native path building must
have keyCertSign if its KeyUsage exists, per
[RFC5280 §6.1.4(n)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4).
Absent KeyUsage imposes no additional restriction here; native BasicConstraints,
EKU, validity, signatures and name constraints still apply. Trust anchors are
separate inputs and do not acquire inappropriate leaf or intermediate KU rules.

The extension parser is maintained x509-parser0.18.1 with default features
disabled: no second signature/path verifier or crypto backend. Its unique-OID
lookup rejects duplicate KU extensions; public maintained ASN.1 BitString::from_der parses the
bit string. The certificate parser uses shallow extension decoding, avoiding
the generic KeyUsage helper’s arbitrary-length u16 flag folding. Complete certificate and extension-consumption guards reject
trailing data. Explicit extension parsing matters because its generic deep
extension parser can discard extension remainders. Field-policy guards require
unused count0..7, at least one asserted bit, no unknown positions beyond the
profile’s named bits0..8, and canonical DER removal of trailing zero bits
([ITU-T X.690 §11.2.2](https://www.itu.int/rec/T-REC-X.690-202102-I/en)). These are maintained-parser
APIs plus policy/consumption checks, not homemade DER parsing. Malformed/duplicate
parser errors preserve `X509Error` with the certificate's role.

The native verify_path callback checks only actual candidate-path intermediates,
never unused peer certificates or roots. It rejects a KU-invalid candidate and
allows maintained path building to try alternatives. If all otherwise-valid
candidates fail KU, the typed policy/parser cause is returned; native fatal
signature/path/name-comparison budget errors retain their original type. The
leaf is checked after native path validation and before the token is issued.

Pinned webpki's intentional omission of KeyUsage in its Web PKI profile is a
backend scope/policy difference, **not an established vulnerability in rustls**.
This adapter chooses the project's stricter certificate-use policy. See
[pinned validation source](https://raw.githubusercontent.com/rustls/webpki/v/0.103.15/src/verify_cert.rs)
and [maintained parser documentation](https://docs.rs/x509-parser/0.18.1/x509_parser/).

Reference identity is an explicit trusted DNS/IP `ServerName`. Maintained SAN
matching has no CN fallback. DNS wildcards follow webpki's profile; SRV/URI
identities, custom application-service restrictions and arbitrary RFC5280 policy
processing are unsupported. Name/path validation are separate operations,
consistent with [RFC9525](https://www.rfc-editor.org/rfc/rfc9525.html).

No clock is fetched here. The caller must acquire an appropriate time and
handle unavailable/untrusted clocks before invocation. Success at a supplied
timestamp cannot prove time-source availability, current wallclock validity,
future certificate validity or fresh revocation information. The token records
successful validation at that call's policy/time; it is not reusable evidence
of every future policy or clock state.

## Revocation and algorithm profile

The constructor requires explicit `RevocationPolicy::NoRevocationData`.
CRL/OCSP validation, stapled-status processing, certificate transparency,
system root loading and network fetching are not implemented. No API accepts
invalid certificates or silently pretends revocation checks occurred. A future
require-CRL policy needs native RevocationOptions plus availability, expiration,
unknown-status and depth decisions, fixtures and tests before being exposed.

Certificate issuer signatures permit a conservative modern list: ECDSA
P256/SHA256, P384/SHA384, P521/SHA512, Ed25519, RSA PKCS#1 SHA256/384/512
(with native accepted present/absent parameters), and RSA-PSS SHA256/384/512
for rsaEncryption keys. SHA1 and other curve/hash combinations are unsupported
by this configured profile even if the backend offers them. Modern RSA PKCS#1
*certificate* signatures are separate from legacy TLS handshake signature
schemes, which remain disabled.

The server CertificateVerify whitelist is:

| TLS code | Scheme | Native public-key constraint |
|---|---|---|
|0x0403 |ecdsa_secp256r1_sha256 |ECDSA P256 |
|0x0804 |rsa_pss_rsae_sha256 |rsaEncryption RSA2048..8192 |
|0x0805 |rsa_pss_rsae_sha384 |rsaEncryption RSA2048..8192 |
|0x0806 |rsa_pss_rsae_sha512 |rsaEncryption RSA2048..8192 |
|0x0807 |ed25519 |Ed25519 |

Pinned webpki exposes its RSA-PSS algorithms as `*_LEGACY_KEY`, meaning the
RSA **key OID** rsaEncryption, not a legacy PKCS#1 signature. It does not offer
this adapter a verifier for id-RSASSA-PSS restricted keys; rsa_pss_pss codes
0x0809..0x080b are explicitly unsupported. Key/algorithm incompatibility retains
the native contextual error. See the
[pinned AWS-LC webpki algorithm definitions](https://raw.githubusercontent.com/rustls/webpki/v/0.103.15/src/aws_lc_rs_algs.rs).

## CertificateVerify domain and residual obligations

The private-construction verified-leaf token builds a bounded stack message
from64 space octets, the exact server context, zero separator and caller-supplied
32/48-byte transcript hash, per
[RFC9846 §4.5.2](https://datatracker.ietf.org/doc/html/rfc9846#section-4.5.2).
It calls maintained `EndEntityCert::verify_signature`; no custom signature
primitive or byte-comparison authentication is implemented. Signatures over
1024 bytes are rejected before native verification, covering the supported
maximum8192-bit RSA signature. Invalid hash lengths and unlisted schemes fail.

The caller must ensure the scheme was offered, that the transcript hash belongs
to the negotiated hash and exact ordered handshake through Certificate, HRR
handling is correct, and the received CertificateVerify is legal in its FSM.
The helper validates hash length but cannot infer whether those bytes represent
the right transcript. Chain+identity+CertificateVerify success still does not
verify Finished or authorize application data by itself. There is no mTLS,
certificate selection, protocol alert mapping or asynchronous cancellation here.

Native parsing/path verification entry points are documented in the
[pinned EndEntityCert source](https://raw.githubusercontent.com/rustls/webpki/v/0.103.15/src/end_entity.rs).
`PkiError::WebPki` retains exact native errors, including contextual expiry/name/
algorithm errors; adapter caps/empty-input/scheme errors are separate variants.
Root initialization allocates bounded owned anchors; native parsing, path search
and signature operations may allocate. There is no allocation-free or measured
CPU-bound PKI claim. Caller caps complement maintained path-building budgets.

## Tested evidence

```sh
cargo test -p tls-pki --locked
cargo clippy -p tls-pki --all-targets --locked -- -D warnings
```

Sixteen integration regressions use the committed benchmark CA-signed P256 leaf
and fixed test fixtures (provenance/hashes in
[fixture README](../crates/tls-pki/tests/fixtures/README.md)). Tests supply
2026-10-15 UTC; they do not depend on the machine's wallclock.

Evidence includes valid DNS and IP SAN, wrong DNS/IP, CN-only refusal, wrong
root, expired/not-yet-valid timestamps, invalid DER with its exact native
TrailingData(SignedData) cause, modified chain signature, CA leaf and client-only
EKU refusal. Malformed oversize DER confirms count/per-certificate/aggregate
caps run before native parsing. Server CertificateVerify succeeds for P256,
Ed25519 and all3 RSA-PSS rsae hash schemes; changed signature/hash and client
context signatures fail. Legacy/unknown schemes, restricted-PSS-key schemes,
incompatible key algorithms, wrong hash length and excess signature length fail.
Strict KU regressions reject a leaf without digitalSignature, an issuing CA
without keyCertSign and trailing KU extension bytes. Signed negative fixtures
also reject noncanonical named-bit padding, unknown bit9 and a high bit16 that
the generic u16 helper would discard. Absence semantics and a
separate explicitly trusted root with no keyCertSign are covered. Alternative
same-key/subject issuers demonstrate retry of a KU-invalid first path and
ignore unused bad-KU certificates.

These tests are maintained-provider integration evidence. They do not constitute
complete RFC5280/9525 conformance, a PKI audit, proof of cryptographic security,
revocation coverage, or live Internet endpoint interoperability.


## Future webpki profiling and verification work

No webpki optimization or performance claim is made here. Source observations
for the exact0.103.15 pin identify measurements to perform before changing it:

- `build_chain_inner` scans candidate anchors by issuer/subject equality, then
  peer intermediates and recurses with loop prevention. An intermediate can be
  parsed again across candidate paths. Measure direct-root, multi-intermediate,
  cross-signed/ambiguous-issuer and adversarial bounded-path profiles separately.
- When an anchor candidate matches, `check_signed_chain` checks signatures along
  the complete candidate and then name constraints. Alternative candidate paths
  can repeat shared signature checks; no performance impact is established yet.
  `signed_data::verify_signed_data` linearly filters algorithm identifiers before
  maintained signature verification. The AWS-LC adapter uses UnparsedPublicKey,
  so native key parsing/call costs are another profiling target.
- Path storage is a fixed six-intermediate `PartialPath` array; it is incorrect
  to assume every path node heap-allocates. Our owned anchor construction does
  allocate, and x509-parser allocates parsed certificate/extension structures;
  native public-key/error construction may allocate. Measure Rust and native
  allocation domains independently, excluding reusable verifier setup where the
  workload calls for steady validation.
- Default native budgets cap100 signature checks,200000 path-building calls,
 250000 name-constraint comparisons, and six intermediates. These fail closed
  with distinct native errors and complement our smaller DER/count caps. They
  are source constants, not throughput or wallclock guarantees. Capture budget
  use, selected paths and rejection causes in benchmark/proof workloads.

Primary sources: [path building/storage/budgets](https://raw.githubusercontent.com/rustls/webpki/v/0.103.15/src/verify_cert.rs),
[algorithm selection/signature work](https://raw.githubusercontent.com/rustls/webpki/v/0.103.15/src/signed_data.rs),
[AWS-LC signature adapter](https://raw.githubusercontent.com/rustls/webpki/v/0.103.15/src/aws_lc_rs_algs.rs).
Potential caches or indexes must preserve exact trust/time/identity/algorithm/
revocation/name-constraint/KU semantics, bounded memory, error behavior and
provider assumptions. Any later optimization needs equivalent checked behavior,
source-linked proof scope where feasible, and controlled repeated benchmarks
before an efficiency conclusion.

`VerifiedServerCert::to_owned()` creates `OwnedVerifiedServerCert` by copying
only the bounded, already verified leaf DER. Its fields are private and it has
no untrusted constructor, Clone or Debug. The client can retain it across
handshake parser steps and discard its original chain storage. CertificateVerify
reparses that private leaf with maintained webpki and uses the same shared
signature/domain helper; it does not repeat path, hostname or time validation.
The token refers to the original supplied verification context, and is not an
assertion that identity remains valid forever or that Finished was verified.
A regression test drops original chain, roots and verifier, then verifies a
valid signature and rejects a changed signature and disabled scheme. A
compile-fail doctest prevents constructing the token from untrusted DER.
