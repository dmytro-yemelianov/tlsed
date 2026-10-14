# AWS-LC adapter

Experimental maintained-provider boundary for `tls-crypto`. This crate contains
no cryptographic primitive implementation and has no socket, transcript, nonce
counter, key schedule, identity verifier or endpoint handshake.

```rust
use tls_crypto::{AeadKey, CipherSuite, CryptoProvider};
use tls_crypto_awslc::AwsLcProvider;

let provider = AwsLcProvider;
let mut key_bytes = [0; 16];
provider.fill_random(&mut key_bytes).unwrap();
let key = provider.aead_key(CipherSuite::Aes128GcmSha256, &key_bytes).unwrap();
// In production, derive a direction-specific traffic key through TLS HKDF,
// wipe raw key material, and obtain nonces from the record engine's counter.
let nonce = [0; 12]; // First use only; never repeat under this key.
let mut buffer = [0; 19];
buffer[..3].copy_from_slice(b"abc");
let n = key.seal_in_place(&nonce, b"authenticated header", &mut buffer, 3).unwrap();
let plaintext_len = key.open_in_place(&nonce, b"authenticated header", &mut buffer[..n]).unwrap();
assert_eq!(&buffer[..plaintext_len], b"abc");
```

`AwsLcProvider` is a unit struct; `AwsLcKey` is private-context, nonclone and has
no Debug implementation. Supports AES128GCM/SHA256, AES256GCM/SHA384, and
ChaCha20Poly1305/SHA256 with exact key lengths16/32/32, 12-byte nonces and
16-byte tags. `seal_in_place` appends the separate tag without extending or
allocating a buffer. `open_in_place` receives exactly ciphertext+tag and returns
only the authenticated plaintext length. Every returned open error zeroizes
the entire supplied slice, including malformed lengths and potential partial
native plaintext. Seal errors also wipe the supplied buffer.

Hash and HKDF-Extract outputs must equal digest length32/48. HKDF-Expand accepts
only exact32/48-byte extracted PRKs at this TLS boundary (stricter than generic
RFC5869's minimum-length input), and output0..255*digest bytes. All returned
hash/HKDF errors wipe output. Secure RNG errors return EntropyUnavailable and
wipe output; there is no fallback. See [provider research](../../docs/CRYPTO_PROVIDER.md)
for sources, native allocation/lifecycle caveats and assurance limits.

```sh
cargo test -p tls-crypto-awslc
cargo clippy -p tls-crypto-awslc --all-targets -- -D warnings
```

Tests cover NIST published GCM examples, AES128/256 zero-key empty/one-block
answers, RFC8439 AEAD, RFC5869 SHA256 cases1–3, SHA256/384 abc, native SHA384
extract/expand cross-check, all-suite ciphertext/tag/AAD/nonce corruption and
whole-buffer wiping, key/length/overflow/maximum-HKDF bounds, RNG success smoke,
and compile-fail ownership/logging checks. These are adapter tests, not a
cryptographic audit, entropy-quality assessment or formally linked proof.

## Streaming hashes and HMAC

`AwsLcProvider` also implements `HandshakeCryptoProvider`, with associated
`AwsLcHashContext` implementing `HashContext`. The context holds native SHA256
or SHA384 state and a checked total-byte counter, never retained transcript
bytes. `snapshot` writes an exact32/48-byte digest without consuming the live
context; later updates remain valid. `reset` replaces it with a fresh empty
state. This boundary conservatively caps total input at `u64::MAX / 8` bytes
for both algorithms before native updates. Invalid snapshot output is wiped.

`hmac_sign` requires exact digest output and wipes it on returned errors.
`hmac_verify` rejects truncated/oversized tags and invokes AWS-LC's maintained
HMAC authentication API; protocol code performs no raw tag comparison.
RFC4231 SHA256/384 case1 and corrupted input/key/tag are tested. Streaming
snapshot/update/reset and invalid-output regressions are also tested. Current
provider integration-test count is12, plus two compile-fail doctests.
Native hash construction/copy/update/finalization and HMAC context failure
panics remain trusted boundaries, as documented in CRYPTO_PROVIDER.md.
