# Experimental protected-record components

The `tls_core::protected` module now composes maintained-provider AEAD with TLS
record syntax. It is a component for a future endpoint, not a completed secure
channel. Successful AEAD verifies a record under the caller's installed traffic
key; it does not establish server identity, validate certificates, authenticate
Finished, or authorize application release before the handshake policy permits it.
The complete sealing/decryption path has no linked Rust refinement proof or
external security audit. Any separately linked pure helper must be listed with
its exact scope in the proof ledger.

## Caller-buffer API

- `ProtectedWriter<K: AeadKey>::new(key, iv, inner_limit, record_limit)` takes one
  direction's owned key and 12-byte static IV. `record_limit` must be positive and
  no greater than the suite's conservative sending budget. A caller may use a
  stricter cap. The inner limit is `1..=16385`, including content, type and padding.
- `seal(content_type, content, padding, output)` protects one record and returns
  its wire size. It stages borrowed content into caller storage, appends the type
  and zero padding, and passes only the record body/tag slice to the provider.
- `ProtectedReader<K>::new(key, iv, inner_limit)` owns a separate receiving
  direction. It applies no GCM sending budget to receiving; its sequence budget
  stops conservatively before `u64::MAX` could be reserved.
- `open(input, output)` authenticates the first complete record and returns
  `Parse::Complete { value: OpenedRecord { content_type, content }, consumed }`.
  Coalesced trailing input is untouched. Short input returns `Parse::Incomplete`
  with the missing header/body length. Output must hold ciphertext plus its tag;
  decryption occurs in that caller-owned staging buffer. `content` borrows output.

Both directions provide read-only `next_sequence()` and `is_failed()`. No reset,
rotation, key replacement, or public access to their internal counters exists.
They neither allocate per record nor perform I/O. Keys, IV owners, and opened
plaintext deliberately omit Debug, and the directions are not Clone. Exclusive
mutable access serializes reservations. Once `open`/`seal` starts crypto there is
no async suspension or retry point inside the component.

## Enforced record rules

[RFC 9846 §§5.2–5.5](https://www.rfc-editor.org/info/rfc9846/) supplies the wire,
nonce, padding and use-limit requirements. For the currently supported suites:

- The outer header is exactly `23 || 0x0303 || uint16(ciphertext_length)`; these
  exact five wire bytes are the provider's authenticated additional data.
- Nonce = the static 12-byte IV XOR the sequence encoded as a left-zero-padded
  64-bit big-endian value. Each attempted crypto operation reserves a distinct
  sequence before calling the provider. No failed operation rolls it back.
- Inner content and type and zero padding together are at most 16385 bytes. A
  fixed 16-byte provider tag makes this implementation's maximum ciphertext
  16401 bytes, which is below the protocol's general 16640-byte bound.
- Protected Handshake content is nonempty; Alert content is exactly two bytes;
  ApplicationData content may be empty. Protected CCS and unknown types fail.
  This component does not parse handshake/alert bodies or validate endpoint state.
- Receiving scans only the authenticated plaintext, from its end, for the final
  nonzero byte. That byte is the inner type. An all-zero body, unsupported type,
  invalid content length, or invalid plaintext size is a terminal failure.
- Configured inner limits include type and padding; a ciphertext exceeding that
  limit plus the fixed tag is rejected before provider invocation. Negotiation of
  RFC 8449 `record_size_limit` remains an endpoint responsibility.

An integrating endpoint must recognize and drop permitted unencrypted CCS before
ciphertext deprotection (RFC 9846 §5), checking its exact `0x01` body and permitted
handshake window. Passing CCS to this fixed ciphertext reader is a terminal wire
error, not compatibility dispatch. It must separately handle record/key alignment,
handshake boundaries, and authenticated application-data release policy.

## Failure and ownership contract

Output shortages and incomplete input reserve no sequence and leave caller output
untouched. The writer's invalid local content/size arguments are also preflight
errors: they leave the output and sequence unchanged and can be corrected.
Malformed receiving headers, invalid inner content, AEAD failures, provider return
length violations, and sequence exhaustion permanently fail their direction.
Every terminal failure erases the entire supplied output buffer with `zeroize`,
including unused tail storage. Calls on a failed direction erase output and fail
without calling the provider again. Success erases the reader's unused output,
inner type, padding and residual tag; only validated content remains.

A provider may modify its supplied buffer before reporting failure. The reader
independently erases caller output even if that provider violates its own wipe
contract. Unexpected returned lengths are checked before slicing, so they cannot
cause a bounds panic. Providers must still authenticate correctly, preserve the
fixed tag contract, protect their native key state, and avoid secret logging;
these trusted properties cannot be reconstructed by generic caller code.

`zeroize` erases the owned static IV on drop and temporary nonce after provider
use. It cannot erase original caller IV copies, compiler/ABI copies, retained
provider-internal key copies, swapped memory, or previously copied application
plaintext. Key destruction/erasure remains the maintained provider's documented
responsibility. The caller owns successful plaintext and must erase it when done.

The caller must install distinct direction traffic keys derived by the authentic
handshake, never recreate a writer with the same traffic key/IV after progress,
and reserve room for a KeyUpdate under old sending keys before reaching a budget.
Automatic KeyUpdate and atomic fresh-key installation are not implemented here.
Exhaustion terminates the component. Creating a new owner does not prove traffic
key freshness; that remains an explicit handshake/provider obligation.

## Regressions and limits of the evidence

`cargo test -p tls-core --test protected --locked` exercises all three AWS-LC
suites, exact header AAD/sequence-nonce assembly against direct provider calls,
empty/full records, zero padding, every input prefix, coalesced tails, small output
retry, stricter limits, mutation of every wire byte, replay/reordering, all-zero
and malformed authenticated inner bodies, and malicious provider lengths.
The RFC 8448 §3 client application-data and following alert records are also
checked in both directions against published key/IV/wire bytes, including the
sequence-0 to sequence-1 transition:
[RFC 8448 known-answer trace](https://www.rfc-editor.org/rfc/rfc8448.txt).
Failure-injecting test providers simulate partial plaintext on error and verify
that the wrapper erases output, retires its nonce and cannot retry. They implement
no cryptography and are not production providers. Existing counter regressions
cover wrap/exhaustion separately. Provider known-answer tests remain in its crate.

This evidence verifies a maintained provider integration and structural record
behavior. It does not demonstrate endpoint interoperability, certificate/Finished
authentication, complete RFC compliance, constant-time behavior, absence of all
side channels, or Internet-facing deployment readiness. Sustained record fuzzing,
full key schedule/handshake integration, independent wire interoperability, and
external security review remain open gates.

The separate `protected_probe` example supplies `inner-check TYPE CONTENT_LEN
PADDING_LEN LIMIT` to compare deterministic size/type guards with the executable
Lean model. It returns `true`/`false`, or `error` for malformed native integer
arguments/type outside u8. These comparisons do not prove the provider/AEAD path.
