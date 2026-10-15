# Fresh maintained key exchange

Experimental provider-backed component, not an authenticated TLS endpoint or a
linked cryptographic proof. Existing pins remain aws-lc-rs1.18.2 and
aws-lc-sys0.46.0. No dependencies or lockfiles were added for this component.

```text
NamedGroup::{X25519, Secp256r1}
    wire_code / public_key_len / shared_secret_len
KeyExchangeProvider::start_key_exchange(group) -> Ephemeral
EphemeralKeyExchange::group / public_key
EphemeralKeyExchange::complete(self, peer_share, &mut output)
```

`AwsLcProvider` implements KeyExchangeProvider with `AwsLcEphemeral`.
Start generates a new native EphemeralPrivateKey and computes its public share;
there is no cache or production deterministic-private-key import API. The
private field is inaccessible and the wrapper has neither Clone nor Debug.
Completion consumes the owner on every attempt, including preflight failure.
Three compile-fail tests prevent reuse, cloning and Debug logging.

| Group | TLS code | Required peer/public encoding | Shared output |
|---|---|---|---|
|X25519 |0x001d |32 octets per RFC7748 |exact32 octets |
|secp256r1 |0x0017 |65-octet uncompressed SEC1 point, first byte0x04 |exact32 octets |

P256 compressed/hybrid encodings and infinity forms fail preflight. Maintained
native agreement validates the point on the specified curve; an uncompressed
encoding alone is insufficient. X25519 peer length is exact and native
agreement rejects all-zero results, including tested low-order inputs. The
adapter does not reimplement scalar multiplication, point validation, clamping
or shared-secret comparisons. Requirements derive from
[RFC9846 §4.3.8.2](https://datatracker.ietf.org/doc/html/rfc9846#section-4.3.8.2)
and [RFC7748](https://www.rfc-editor.org/rfc/rfc7748.html).

Output must have exactly32 bytes. Any returned error wipes the entire supplied
mutable output, even when its length is invalid. Wrong peer shape returns
InvalidKey; bad output size returns InvalidLength; an unexpected native public
or secret size returns BackendFailure. Native agreement's Unspecified peer/
internal failures are mapped to InvalidKey; its public API does not distinguish
all invalid-peer causes from internal faults. Generation/public computation
failures map to BackendFailure. No failure falls back to weak or fixed material.

## Trusted lifecycle and allocation boundaries

[The pinned native ephemeral API](https://raw.githubusercontent.com/aws/aws-lc-rs/v1.18.2/aws-lc-rs/src/agreement/ephemeral.rs)
accepts SystemRandom for ring API compatibility but explicitly ignores that
argument: PrivateKey::generate uses AWS-LC's native key generation and entropy,
not caller-controlled random bytes. Secure native entropy and fresh generated
keys remain trusted assumptions. Tests observe distinct generated shares;
that is not a formal guarantee or statistical audit of global freshness.

[`agree_ephemeral`](https://raw.githubusercontent.com/aws/aws-lc-rs/v1.18.2/aws-lc-rs/src/agreement.rs)
consumes the native ephemeral key and calls a closure with the maintained raw
shared secret. The adapter copies that fixed-size secret to caller storage.
The [pinned native EVP wrapper](https://raw.githubusercontent.com/aws/aws-lc-rs/v1.18.2/aws-lc-rs/src/evp_pkey.rs)
uses native EVP contexts and a Zeroizing<Vec<u8>> temporary for agreement,
scrubbing its retained capacity on drop. Native private-key EVP destruction,
allocator behavior, registers/compiler copies, RNG, FFI, OS and hardware remain
trusted; there is no independently verified key-erasure or constant-time claim.
No allocation-free handshake claim is made. Agreement allocation is separate
from the steady-state record path.

Returned-error wiping does not promise cleanup after a provider panic, process
abort or compiler/ABI copies. Caller-owned successful shared secrets must be
retired/zeroized after HKDF. The adapter does not keep a successful secret in
its wrapper and does not log private keys or fresh secrets.

## Validation and remaining protocol obligations

```sh
cargo test -p tls-crypto-awslc --test agreement --locked
cargo test -p tls-crypto-awslc --doc --locked
cargo clippy -p tls-crypto-awslc --all-targets --locked -- -D warnings
```

Five integration tests cover both-group fresh pair agreement and wire sizes,
wrong peer/output sizes, all-byte error wiping, X25519 low-order zero-result
refusal, and P256 compressed/hybrid/infinity/off-curve refusal. Secure native
entropy failure and unexpected provider-internal length faults were not
injected. Functional success/rejection and ownership evidence are not a crypto
audit, side-channel measurement, formal primitive proof or endpoint interop.

An independent native known-answer test imports the published Alice/Bob private
inputs from [RFC7748 §6.1](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1),
checks both public shares and verifies their published shared value
`4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742`.
Native PrivateKey offers a maintained deterministic import; EphemeralPrivateKey
has no public import constructor. Therefore this deterministic test checks the
underlying maintained primitive, while wrapper tests use fresh native generation.
No deterministic private import is exposed through the production provider.

The endpoint must match the selected group to offered groups/shares, enforce
HRR rules and fresh shares across connections, associate this one owner with
one handshake, retire it on cancellation/rejection and bind the derived secret
to the authenticated transcript/key schedule. A successful ECDHE operation does
not establish server identity, certificate validity, Finished correctness or
permission to release application data. Hybrid KEX and other groups remain
separate future scope.
