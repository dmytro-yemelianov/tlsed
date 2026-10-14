# Bounded server PKI adapter

Experimental standalone component using rustls-webpki0.103.15 AWS-LC and
rustls-pki-types1.15.1. No TLS endpoint, socket, system trust-store loading,
clock, custom X.509 primitive or certificate-acceptance bypass.

```rust
use tls_pki::{ServerVerifier, ChainLimits, RevocationPolicy};
// roots, chain, reference and now come from trusted caller policy/input handling.
let verifier = ServerVerifier::new(&roots, ChainLimits::default(),
    RevocationPolicy::NoRevocationData)?;
let verified = verifier.verify_server_certificate(&chain, &reference, now)?;
verified.verify_certificate_verify(signature_scheme, &transcript_hash, &signature)?;
```

`chain` is leaf first and then candidate intermediate DER certificates.
`reference` is an explicit `ServerName` DNS/IP identity, not inferred from a
peer certificate. `now` is an explicit `UnixTime`, with clock validity and
availability left to the caller. Limits bound count/per-certificate/aggregate
DER bytes before external parsing and path verification. Default caps are
8 certificates,64KiB each,256KiB total. Root imports use the same caps; larger
trusted root stores require an explicit larger configuration.

The returned private-construction `VerifiedServerCert` token means chain and
SAN identity were checked at that supplied time. It does not verify Finished,
message order or the caller's authentic transcript. Its CertificateVerify
method constructs the exact server TLS1.3 signature domain and invokes native
signature verification. It accepts P256/SHA256, RSA-PSS rsaEncryption keys
(SHA256/384/512), and Ed25519. Restricted id-RSASSA-PSS keys and all legacy
RSA PKCS#1 handshake schemes are unsupported. The caller must enforce offered
scheme negotiation and the negotiated transcript hash.

Maintained x509-parser0.18.1 supplements webpki's deliberate Web PKI scope with
strict KeyUsage: digitalSignature on leaf and keyCertSign on actual issuing
intermediates when the extension exists. No KU extension adds no restriction.
Trust anchors remain separate; unused peer certificates are not checked as
issuers. Native path callbacks can retry another valid candidate when KU fails.
Duplicate/malformed KU and trailing extension DER fail. No custom DER parser or
second cryptographic/path verifier is introduced; parser verification features
are disabled. This stricter policy does not establish a rustls vulnerability.

The only revocation policy is explicit `NoRevocationData`: no CRL/OCSP check
or assertion. No CN fallback, SRV/URI identity profile or full arbitrary PKIX
policy processing is provided. `PkiError::WebPki` retains the maintained
library's exact typed cause. See [PKI research](../../docs/PKI.md) for scope,
algorithm profile, native guarantees and limitations.

```sh
cargo test -p tls-pki --locked
cargo clippy -p tls-pki --all-targets --locked -- -D warnings
```
