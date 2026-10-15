# Experimental TLS labels and no-PSK key schedule

`tls_core::key_schedule` composes maintained provider HKDF/hash/HMAC operations;
it implements no cryptographic primitive and no endpoint handshake. The caller
must supply a valid fresh shared secret and hashes of the exact authenticated
transcript boundaries. A returned traffic secret or successful Finished check is
not certificate/identity authentication or permission to release application data.

## Exact labels and bounds

[RFC 9846 §7.1](https://www.rfc-editor.org/rfc/rfc9846.txt) defines the label
encoding and suite-specific transcript/HKDF hash. The encoding is:

```text
uint16(output_length) || uint8(6 + label_length) || "tls13 " || label
                     || uint8(context_length) || context
```

`hkdf_label_encoded_len(output_len, label_len, context_len)` returns
`Some(10 + label_len + context_len)` exactly when output length is at most 65535,
raw label length is 1..249, and context length is at most 255. Its accepted
result is 11..514 bytes; native additions cannot overflow. It returns `None`
for invalid fields, including native `usize::MAX` cases. `encode_hkdf_label`
writes that exact format into caller storage without allocation, checks output
capacity before slicing, and erases supplied output on every returned error.
Success leaves the unused tail unchanged.

`expand_label` requires a PRK of exactly the selected SHA-256/SHA-384 digest
length and calls maintained HKDF-Expand with the bounded label. It erases caller
secret output on any returned error, even if a faulty provider leaves partial
output. The encoder's uint16 length bound does not override HKDF's own
255-digest-block bound; the provider can reject a larger requested expansion.
Static schedule labels retain historical `master` spelling for wire/key
compatibility even though RFC 9846 calls those values main secrets.

## Owned stages and directions

`HandshakeSecrets::derive(provider, suite, shared_secret, hello_hash)` implements
only the full no-PSK path. The suite selects the hash; SHA-256 suites require
32-byte hashes and AES-256-GCM/SHA-384 requires 48. Shared-secret input is bounded
to 1..256 bytes as this component's resource policy. Negotiated-group length,
peer-share validity (including X25519's all-zero rejection), entropy, ephemeral
freshness and erasure of the original input remain caller/provider obligations.
The input must be a validated provider result, not raw peer-controlled bytes.

The sequence is no-PSK early Extract with digest-sized zero salt and zero input,
`derived` against Hash(empty), handshake Extract with the shared secret, then
`c hs traffic`/`s hs traffic` against the ClientHello-through-ServerHello hash.
Early/derived temporaries are retired after use.

`into_application(provider, server_finished_hash)` consumes the base handshake
secret, derives the next `derived` value against Hash(empty), Extracts the main
secret with digest-sized zero input, then derives `c ap traffic`, `s ap traffic`
and `exp master` against the transcript through the server Finished. The main
secret and derived temporary are retired on return. Resumption, PSKs, binders,
early traffic, and exporter invocation remain unimplemented.

The returned `ApplicationTransition` retains typed client/server handshake traffic
owners alongside `ApplicationSecrets`. A client may still need handshake keys to
send its own Finished after application secrets have been derived. The endpoint
must retire those retained owners as soon as their protocol use ends; this
component does not decide those state transitions.

`TrafficSecret<Client, Handshake>`, `TrafficSecret<Server, Handshake>`, and their
application-stage counterparts have private construction, no Clone/Debug, and
private immutable epochs. Traffic key/IV material retains those static direction
and stage types. `key_material` derives `key` and `iv` with empty context and
returns a bounded owner for provider import. Raw byte access is explicit and may
expose secrets; do not log or retain copies. Re-deriving/importing the same material
is deterministic and must never be used to reset counters under the same key/IV.
No record-key installation API or automatic counter reset is exposed.

Only handshake-stage traffic exposes `sign_finished` and `verify_finished`.
They derive `finished` with empty context and use the provider's maintained HMAC
sign/verify APIs on the caller's pre-Finished transcript hash. Protocol code never
compares tags byte-by-byte. Incorrect lengths are rejected; sign-output is erased
on every error. These borrowed methods do not mutate an authentication FSM. A real
endpoint must abort and retire all owners on failed verification, and combine
successful verification with certificate/service-identity and signature checks.

Application traffic is consumed into `SendingTraffic<D>` or `ReceivingTraffic<D>`.
A consuming update derives `traffic upd` with empty context, checks epoch+1,
and returns a new owner. The sending epoch cannot exceed `2^48-1`; receiving
must not impose that sender cap and stops only at u64 overflow. Failed updates
return no usable new owner and retire the consumed old secret. A caller must
select its correct local sending/receiving role, send/accept KeyUpdate under old
keys, and atomically install fresh record keys before restarting a sequence.
These requirements are not inferred from a derivation call.

All owned secrets use a fixed [u8;48] plus private active length and erase the
entire storage on Drop. Stack HKDF label staging is erased after provider use.
Explicit copies, input shared secrets/hashes, compiler/ABI copies, provider native
contexts, swapping and crash dumps remain outside this erasure guarantee. The
code's bounded ownership and consuming stages are not a linked proof of secret
memory erasure, constant-time behavior, or cryptographic security.

## Evidence and reproducibility

The key-schedule regressions observe actual provider Extract/Expand outputs for
the [RFC 8448 §3](https://www.rfc-editor.org/rfc/rfc8448.txt) full no-PSK chain:
early, both derived intermediates, handshake/main secrets, both handshake and
application traffic secrets, exporter secret, all four key/IV pairs, server/client
Finished keys and tags. Test-only observation logs contain published fixture
secrets; production providers must never implement that logging pattern. Server
Finished input is recomputed from the exact published CH/SH and the existing
server-flight fixture. The historically expired certificate is opaque transcript
data and is not trusted by these tests.

SHA-384 additionally uses static independent expected values generated with
Python cryptography 50.0.2 and its reported OpenSSL 4.0.3 backend. The fixture uses
shared bytes 0..31, hello hash 48 copies of 0x31, and server-Finished hash 48 copies
of 0x52. The generator uses maintained HKDF/HKDFExpand/HMAC, not an in-house
primitive. This is differential fixture evidence, not a published RFC SHA-384
trace or endpoint interoperability. Cargo tests need no Python dependency.
Reproduce the fixture with an environment containing cryptography 50.0.2:

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

def label(n, raw, ctx):
    full = b"tls13 " + raw
    return n.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx

alg = hashes.SHA384()
n = 48
zero = bytes(n)
shared = bytes(range(32))
hello_hash = bytes([0x31]) * n
server_hash = bytes([0x52]) * n
empty = hashes.Hash(alg).finalize()

def combined(salt, ikm, raw, ctx):
    return HKDF(algorithm=alg, length=n, salt=salt, info=label(n, raw, ctx)).derive(ikm)

def expand(prk, raw, ctx, length):
    return HKDFExpand(algorithm=alg, length=length, info=label(length, raw, ctx)).derive(prk)

early_derived = combined(zero, zero, b"derived", empty)
chs = combined(early_derived, shared, b"c hs traffic", hello_hash)
shs = combined(early_derived, shared, b"s hs traffic", hello_hash)
handshake_derived = combined(early_derived, shared, b"derived", empty)
cap = combined(handshake_derived, zero, b"c ap traffic", server_hash)
sap = combined(handshake_derived, zero, b"s ap traffic", server_hash)
exporter = combined(handshake_derived, zero, b"exp master", server_hash)
for name, secret in [("chs", chs), ("shs", shs), ("cap", cap), ("sap", sap)]:
    print(name + "_key", expand(secret, b"key", b"", 32).hex())
    print(name + "_iv", expand(secret, b"iv", b"", 12).hex())
mac = hmac.HMAC(expand(shs, b"finished", b"", 48), alg)
mac.update(server_hash)
print("server_finished", mac.finalize().hex())
print("exporter", exporter.hex())
print("updated_client_key", expand(expand(cap, b"traffic upd", b"", 48), b"key", b"", 32).hex())
```

Negative regressions cover label/context/output maxima and short buffers, invalid
PRK/hash/shared-secret lengths, unsupported suites, altered transcripts/tags and
wrong directions, all three suites, partial secret output from faulty providers,
consuming failure, updated keys, sending/receiving epoch caps and overflow.
Compile-fail tests reject secret Clone/Debug, direction/stage confusion and use of
an old sending owner after update. They demonstrate ownership/type constraints;
they do not inspect erased memory after Drop or prove a Rust compiler/backend.

```sh
cargo test -p tls-core --test key_schedule --locked
cargo test -p tls-core --lib --locked
cargo test -p tls-core --doc --locked
cargo clippy -p tls-core --all-targets --locked -- -D warnings
cargo build -p tls-core --example key_schedule_probe --locked
```

`key_schedule_probe label-size OUTPUT_LEN LABEL_LEN CONTEXT_LEN` prints decimal
encoded size or `error`. Inputs parse as native usize. The arithmetic helper is a
candidate for the root's retained Aeneas/Lean translation; consult the final proof
ledger for its exact linked status. The slice encoder, complete key schedule,
HMAC authentication, provider internals and endpoint security remain outside that
pure helper's proof scope.
