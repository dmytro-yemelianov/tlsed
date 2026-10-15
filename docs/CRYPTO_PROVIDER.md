# Maintained cryptographic provider

Status: implemented experimental adapter; cryptographic code remains external
and trusted. It does not establish a peer identity or implement a handshake.
Pins: aws-lc-rs1.18.2, aws-lc-sys0.46.0 (Cargo.lock), zeroize1.9.1. Ordinary
non-FIPS provider build; no FIPS certification claim. AWS-LC's Rust/C/assembly,
FFI, RNG sources, allocator, compiler and hardware are outside current Lean
functional proofs.

## Operations and source choices

| Shared operation | Maintained API | Adapter guard / behavior |
|---|---|---|
| AES128GCM / AES256GCM / ChaCha20Poly1305 | aead::UnboundKey + LessSafeKey | exact16/32/32-byte key; nonce12, tag16 |
| In-place seal | seal_in_place_separate_tag | checked plaintext+tag capacity; append tag in caller slice; wipe on returned error |
| In-place open | open_in_place | input>=16; authenticate exact bytes; return plaintext length; wipe entire supplied slice on every returned error |
| Secure randomness | rand::fill (AWS-LC RAND_bytes) | return EntropyUnavailable and wipe on failure; no fallback |
| SHA256 / SHA384 | digest::digest | exact32/48 output; invalid output wiped |
| HKDF-Extract | hmac::Key + sign_to_buffer | RFC5869 HMAC(salt,IKM); missing salt uses HashLen zeros; exact digest output |
| HKDF-Expand | hkdf::Prk::new_less_safe + expand/fill | exact digest PRK; output<=255*HashLen; zero-length output allowed; errors wipe output |

[aws-lc-rs1.18.2 source](https://github.com/aws/aws-lc-rs/tree/v1.18.2/aws-lc-rs/src)
and [AWS user guide](https://aws.github.io/aws-lc-rs/) describe the maintained
backend. The adapter's explicit nonce API is appropriate for TLS's deterministic
nonce construction. It is not a nonce manager: the record engine must reserve
nonces before encryption, never roll them back on cancellation/errors, enforce
per-algorithm usage limits and install fresh direction-specific keys atomically
with epoch changes. Reconstructing a key with the same bytes can violate these
assumptions; the adapter cannot globally prevent it.

[RFC5869 §2.2–§2.3](https://www.rfc-editor.org/rfc/rfc5869.html) defines extract
as maintained HMAC and limits expand to255*digest bytes. AWS-LC Salt::extract
returns an opaque PRK with no public byte-export API; using its HMAC primitive
permits the TLS key schedule to own the extracted bytes without implementing
HMAC or HKDF expansion ourselves. `new_less_safe` imports those already-extracted
bytes; it does not log/export keys. Its fixed-storage panic precondition is
excluded by our exact digest-length guard. The exact PRK-length policy is
intentionally narrower than general-purpose RFC5869.

The caller encodes TLS HKDF labels/info and maintains transcript/domain binding;
this generic adapter does not validate a TLS label. Do not treat raw successful
AEAD decryption as proof of server authentication.

## Allocation and secret lifecycle

The adapter AEAD methods have no Vec, Box, extension, hidden transport, or
per-record Rust heap allocation. One native AEAD context is allocated when a
key is created: pinned `aead/aead_ctx.rs` uses OPENSSL_malloc/init. The private
context is freed through `EVP_AEAD_CTX_free` via the provider pointer wrapper.
Native cleanup/erasure, temporary registers/compiler copies, crash dumps and
swapping are trusted/residual concerns. We do not claim independently verified
native erasure or universally zero native allocations; allocator instrumentation
has not yet measured provider/C/error-path behavior.

The caller owns raw key/PRK/IKM/output buffers and must wipe them when retired;
constructing AwsLcKey does not wipe its immutable source slice. Adapter-returned
errors zeroize mutable outputs with zeroize, which does not prove erasure of
all copied state. Keys cannot be Debug-formatted or cloned through this wrapper.

Pinned HKDF Prk copies imported bytes into fixed secret storage and zeroizes
that storage on drop. HKDF info concatenation uses an80-byte stack buffer and
allocates a Vec for larger info. HKDF is key-schedule work, not the steady-state
record operation; no blanket allocation-free key-schedule claim is made. HMAC
contexts delegate cleanup to native HMAC_CTX_cleanup. Hash/HMAC public APIs may
panic on native context construction/copy/update failures; they expose no fully
fallible equivalent constructor. Such provider/runtime panics/aborts are trusted
boundary failures and are not disguised as CryptoError. Returned-error wiping
claims do not claim panic/abort cleanup. AEAD and rand expose checked results.

## Validation evidence

`cargo test -p tls-crypto-awslc` checks10 integration tests plus two compile-fail
doctests. `cargo clippy -p tls-crypto-awslc --all-targets -- -D warnings` passes.
Tests exercise algorithms, wire bytes and meaningful authentication failure,
not just local round trips:

- AES128/256GCM zero-key empty and one-block known answers. Original GCM
  submission cases are retained by
  [BoringSSL's primary vector source](https://boringssl.googlesource.com/boringssl/+/517073cd4b/crypto/cipher/cipher_test.txt)
  with the historic NIST GCM submission URL.
- [NIST AES_GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf),
  GCM-AES128 examples1/2, including empty and64-byte plaintext. The downloaded
  primary PDF SHA256 is `55e822592257799a4f895d6f3cb4c15515a065c008087105fc2063d2e757b5ef`.
  GCM standard: [NIST SP800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).
- [RFC8439 §2.8.2](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8.2)
  ChaCha20Poly1305 ciphertext/tag including nonempty AAD.
- [RFC5869 Appendix A.1–A.3](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A)
  SHA256 extract/expand vectors, long inputs/output and absent salt/info.
- SHA256/384 abc known answers from the
  [RFC6234 test driver §8.5](https://www.rfc-editor.org/rfc/rfc6234.html#section-8.5).
  SHA384 HKDF additionally cross-checks AWS-LC's opaque extract/expand path;
  this same-backend comparison is not independent cryptographic validation.
- All3 suites reject changed ciphertext/tag/AAD/nonce and wipe every passed
  byte; short ciphertext0..15, invalid key/length and overflow are covered.
  HKDF validates exact digest outputs/PRKs and both sides of the255*digest bound.

RNG success smoke performs no probabilistic assertion and cannot establish
entropy quality. Native RNG failure and allocation/context failures were not
injected; failure handling is implemented from maintained Result contracts.
No constant-time benchmark, side-channel proof, primitive formal verification,
provider audit or complete TLS interoperability follows from these tests.

## Streaming transcript and Finished primitive milestone

The provider now implements `HandshakeCryptoProvider` with bounded-state
`AwsLcHashContext` for SHA256/384. It stores native `digest::Context` plus a
checked byte counter, not a growing transcript Vec. Snapshot clones the native
context and finalizes the clone; update continues from unchanged live state.
Reset constructs empty state. Snapshot outputs must equal digest length and
are wiped on returned errors. A conservative `u64::MAX / 8` total-byte cap for
both algorithms prevents unbounded counters and native update overflow; it is
not a protocol-level handshake resource budget.

Native digest context initialization/clone/finalization may allocate bounded
provider state and panic on native failures; update APIs are similarly
infallible Rust wrappers over fallible native operations. There is no claim
that snapshots or HMAC/context construction are allocation-free, or that these
Result-returning trait methods eliminate provider panics. Input storage is not
retained by the adapter and transcript replay is unnecessary for snapshot.

HMAC signing writes into exact digest-size caller output and wipes on returned
errors. Verification requires a full32/48-byte tag and uses the maintained
`aws_lc_rs::hmac::verify` API, which delegates to the provider's constant-time
comparison implementation. There is no byte-comparison implementation in the
protocol layer; full-system side-channel behavior still remains unproved.
[RFC4231 §4.2](https://www.rfc-editor.org/rfc/rfc4231.html#section-4.2) supplies
independent SHA256/384 HMAC case1 expectations. Added tests cover changed key,
input and tag, invalid output/tag lengths and streaming update/snapshot/reset.
The complete current provider suite has12 integration tests and two ownership
compile-fail tests, superseding the earlier milestone count above.
