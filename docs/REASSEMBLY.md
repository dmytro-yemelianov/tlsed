# Bounded handshake reassembly

`tls_core::handshake::Reassembler` retains one syntactic handshake message in
caller-owned scratch. It performs no I/O or allocation. Constructor limits are
trusted configuration, independent of declared wire lengths: maximum body fits
u24, scratch holds that cap plus four bytes, and a positive work budget limits
bytes copied by each call. The encoded header remains available for transcript
hashing by the eventual endpoint.

```rust
let mut scratch = [0_u8; 4100];
let mut messages = Reassembler::new(&mut scratch, 4096, 1024)?;
let step = messages.push_fragment(handshake_record_tail, key_epoch, true)?;
// Retain input[step.consumed..]; handle MessageReady then consume_message().
```

`push_fragment(input, key_epoch, end_of_record)` receives bytes from one decoded
Handshake record. The final-byte flag refers to the actual TLS record boundary,
not a socket-read/chunk/work boundary. Each call returns NeedInput, NeedWork or
MessageReady and exact consumption. A ready message consumes no more input
until explicitly consumed. Coalesced messages are processed by resubmitting the
tail. Bodies may span records only under the same key epoch.

At four buffered header bytes, unsupported wire types and lengths above the
configured cap are rejected before any body is copied. The supported syntax
includes ClientHello, ServerHello, NewSessionTicket, EncryptedExtensions,
Certificate, CertificateRequest, CertificateVerify, Finished and KeyUpdate.
EndOfEarlyData is rejected because 0-RTT is disabled; message_hash is an internal
HRR transcript construction and cannot arrive as a handshake wire message.
Message-body validity and role/state ordering are separate future codec/FSM work.

Messages immediately preceding key changes (ClientHello, ServerHello, Finished,
KeyUpdate) must finish at the supplied record boundary. The component rejects
extra record bytes after such a complete message and premature boundary flags.
`check_key_change` rejects retained bytes; `note_other_record` rejects handshake
interleaving. Permitted compatibility CCS must be validated and dropped by the
endpoint before those calls. Actual boundary/epoch values and processing of all
unconsumed tails remain caller obligations; this API cannot infer them from TCP.

Malformed input, epoch/interleaving/alignment violations and truncated EOF
permanently fail reassembly and wipe retained bytes. Premature consume is a
recoverable caller error. Successful consume wipes that message; Drop wipes
the borrowed scratch. It cannot erase compiler copies or separately copied
messages. `finish_input` detects incomplete syntax, not orderly TLS closure.

The linked `checked_handshake_total` proof establishes exact guard/checked-add
correspondence and u24/usize headroom. Model theorems establish accumulation
bounds and maximal local min-copy progress under the supplied effective input
budget. Full Rust reassembly/refinement and record-boundary enforcement are
tested rather than formally linked. Regression and fuzz evidence includes
fragmentation/coalescing, work budgets, resource attacks, boundary errors and
[published server-flight bytes](RFC8448_VECTORS.md).
