# Lean model and optimization objective

The required model builds with **Lean 4 v4.34.1**, pinned in
`lean/lean-toolchain`. It imports only Lean's bundled `Init`; there is no
mathlib or other external dependency for this model. Warnings are errors.

```sh
cd lean
lake build
lake env lean AxiomAudit.lean
```

`AxiomAudit.lean` enumerates the required theorems. Its output contains only
Lean's standard foundational axioms `propext`, `Quot.sound`, and (for some
proofs) `Classical.choice`. No custom axioms, admitted proofs, native-decision
oracle, or `sorryAx` occur in these proofs. The kernel, bundled libraries, and
compiler/runtime remain trusted; executable comparisons additionally trust
both language toolchains and the comparison harness.

## What is optimized

For a payload of `n` bytes and fixed positive payload capacity `L`,
`recordCount n L = n / L + (if n % L = 0 then 0 else 1)`.
The result is feasible: `n ≤ recordCount n L * L`. A concrete partition
contains `n / L` full records and, only when nonzero, one remainder. Its sum
is `n`, its length is the returned count, and each chunk is positive and at
most `L`.

Every finite list of chunks bounded by `L` and summing to `n` has length at
least the returned count. This is a true minimum over all such partitions,
not just a comparison with another chosen algorithm. For a fixed nonnegative
per-record overhead `h`, the same choice minimizes `n + h * count`.
`recordCount_le_input` proves the final count is at most `n`; therefore the
addition in this quotient-and-remainder formula cannot overflow if `n` fits
in the target unsigned type. No overflowing `n + L - 1` intermediate is used.

The cost model excludes cryptographic CPU time, padding choices, varying
record capacities, latency/flush policy, batching, transport I/O, and memory
allocation. It does not prove global implementation optimality or a speed
advantage against other TLS implementations. Empty payload yields zero
records; explicitly requested empty/padded records require a different policy.

## Wire model

`Header` stores the numeric content type, legacy version, and length. The
header codec models five bytes using naturals constrained to byte ranges;
round-trip proofs assume kind < 256 and version/length < 65536. These are
mathematical byte values, not a formal semantics of Rust slices or `u8`.

The plaintext profile accepts ChangeCipherSpec of length 1, Alert of length 2,
and nonempty Handshake records; it ignores received plaintext legacy version.
Ciphertext requires type 23, version 0x0303, and nonzero length. The configured
cap must not exceed 16384 (plaintext) or 16640 (ciphertext). These checks are
record-header preconditions; payload validity, compatibility CCS placement,
AEAD tag size, and handshake reassembly require further layers.

`readRange` checks both the initial cursor and remaining size before returning
an end position. Successful ranges are in bounds; truncated ranges fail. This
is a cursor arithmetic model, not a proof of the full incremental Rust framer.

## Counters and key assumptions

Reservation succeeds only when `next < limit` and `next < u64::MAX`, returning
`next + 1`; the consumed sequence number is the previous `next`. The explicit
max guard conservatively refuses to reserve the terminal integer so that
state never wraps. Epoch rotation has the same shape with an independent cap.
Rust uses direction-specific epoch caps: outbound 2^48-1, inbound u64::MAX.

`Reservations` models sequential atomic consumption of returned states.
`reservations_unique` proves no sequence repeats in a finite trace within one
epoch. `rotated_coordinates_distinct` separates `(epoch, sequence)` coordinates
across a successful rotation. Fresh, direction-specific traffic keys, nonce
encoding/injectivity, no cloning or rollback of live state, provider behavior,
and atomic installation remain implementation assumptions. These theorems
alone do not establish cryptographic nonce uniqueness across all connections.

## Authentication evidence model

Numeric states are Start=0, HelloAccepted=1, IdentityVerified=2,
SignatureVerified=3, Established=4, and Failed=5. Events 0 through 3 advance
only the matching stage; Abort=4 and AeadFailed=5 move to Failed. Failed cannot
return to an active phase. Invalid or unexpected events return failure without
a successful next state.

Events are **already verified evidence**: event 1 represents successful
certificate-chain and reference-identity validation together, event 2 a valid
CertificateVerify, and event 3 a valid Finished. `AuthTrace` starts at Start
and applies only successful transitions. Its establishment theorem requires
all three evidence events. Release additionally requires successful AEAD.
Calling a model function with an arbitrary integer state does not establish
reachability. Actual PKIX, signatures, Finished/transcript binding, HRR,
server/mTLS behavior, and provider integration are outside this initial model.

## Executable interface

`lean/.lake/build/bin/tls13_model` accepts one command per process:

| Command | Output |
|---|---|
| `count N LIMIT` | count or `error` (zero limit) |
| `header MODE TYPE VERSION LENGTH CAP` | `true` / `false` |
| `reserve NEXT LIMIT` | incremented state or `error` |
| `rotate EPOCH CAP` | incremented epoch or `error` |
| `auth STATE EVENT` | next state or `error` |
| `release STATE AEAD_OK` | `true` / `false` |

Mode 0 is plaintext and 1 ciphertext; AEAD_OK is 0 or 1. Inputs are decimal.
Malformed commands and arguments return `error`. Arguments must fit unsigned
64-bit integers (the current differential platform's `usize` width); header
fields additionally fit u8/u16 and state/event codes fit 0..5. The mathematical
theorems use unbounded naturals and positive capacity where required.

The coordinator's correspondence artifacts record actual Rust comparison
runs and any separately checked translation proofs. Executable agreement is
not a refinement proof. The standalone model does not by itself prove Rust.

## Separate checked Rust translation

The standalone model is complemented by `verification/aeneas/Proof.lean`,
checked using a separate pinned Lean 4 v4.31.0 / Aeneas / mathlib project. It
imports the unchanged segmentation model source. The actual translated
production `schedule::record_count` is proved to return the model's value
without checked-arithmetic failure when capacity is positive, to return
`InvalidLimit` for zero capacity, and to satisfy the minimum-count and
fixed-overhead theorems. All four theorem axiom sets are exactly
`[propext, Classical.choice, Quot.sound]`.

This initially upgraded the record-count function to linked/proved under the
documented Charon/Aeneas/compiler trust boundary. The proof ledger and coordinator's
translation provenance specify scope and reproduction. Other functions retain
their separately stated modeled or tested-against-model status.

```sh
(cd verification/aeneas && lake build)
```

## Protected-record and handshake-reassembly models

`Tls13/Reassembly.lean` checks the u24 handshake body length against the
configured cap before adding the four-byte handshake header. A successful total
is at most 16,777,219, hence fits even a 32-bit unsigned integer. The abstract
body-copy operation starts after a validated header, retains at most the target
message, and consumes `min inputRemaining (target - buffered)` bytes. Its result
is within both the source and destination bounds; an excessive declared length
returns failure before copying a body byte. These are arithmetic/model proofs,
not a proof of the complete Rust reassembler's lifetime or slice semantics.

`copyProgress_maximal` proves an additional precise optimization property:
for a fixed retained-message interface, any copy count that fits both the input
and the remaining target is at most the greedy count. This maximizes local
progress, without claiming optimal CPU time, copying architecture, or throughput.

`Tls13/Protected.lean` models TLSInnerPlaintext and its release conditions.
The configured limit is 1..16385 and includes content, one type byte, and zero
padding. ApplicationData (23) permits empty content, Handshake (22) requires
nonempty content, and Alert (21) requires exactly two content bytes. Other types
are rejected. A 16-byte tag yields at most 16,401 bytes of ciphertext for this
provider profile, within the protocol outer-record maximum 16,640.

The decoder scans reversed already-decrypted bytes for the first nonzero type.
Its proof reconstructs the original bytes exactly as content, one type byte,
and zero padding, and proves a content bound of 16,384. All-zero input fails.
Successful `openInner` requires AEAD evidence, valid type/content conditions,
and the configured full inner size. Failed AEAD releases an empty mathematical
buffer. Provider implementations, actual wiping of caller storage, Rust byte
slice handling, authenticated header binding, and nonce construction are outside
these model proofs. Decrypting a valid record does not establish a peer identity:
connection authentication must separately gate application delivery.

New executable commands:

| Command | Output |
|---|---|
| `handshake-total BODY CAP` | body + 4 or `error` |
| `inner-check TYPE CONTENT_LENGTH PADDING_LENGTH LIMIT` | `true` / `false` |

The existing unsigned-64-bit argument domain applies; TYPE additionally fits
u8. Mathematical length calculations cannot overflow, and accepted values are
proved small enough to represent. Translation proofs must discharge the actual
Rust checked arithmetic separately. Decoder/padding proofs are not upgraded to
linked status by comparing only the numeric `inner-check` command.

The `openProtected` wrapper additionally rejects provider length discrepancies:
decrypted bytes plus the fixed 16-byte tag must equal the ciphertext length.
Success proves an outer length in 17..16401 and AEAD evidence; failed AEAD cannot
open any input. This models validation of a provider result, without proving
the provider's cryptographic implementation or actual zeroization.

## Linked guards for the second milestone

The translation project also checks exact correspondence for production
`handshake::checked_handshake_total`, `protected::inner_length`, and
`protected::valid_content_type`. `ReassemblyProof.lean` establishes u24 header
headroom using the backend's proved 32-or-64-bit usize bound, then proves exact
Option agreement, acceptance without overflow, and oversized-body rejection.
`ProtectedProof.lean` proves both checked-add paths, invalid-limit rejection,
the 16385 constant calculation, and exact type-policy agreement. These are
unconditional on representable inputs: failure paths are part of the proofs.

Across the original and new proof files, all 21 audited linked theorem closures use
only standard Lean foundations. The backend's width/headroom lemma does not
introduce a custom platform axiom. Explicit Option branching in the Rust helper
avoids the pinned translator's unsupported Try-trait expansion while preserving
checked arithmetic. The retained generated artifact contains no custom axiom.

The standalone project now audits 92 model theorems. The protected padding
scanner, actual buffer wiping, full Rust reassembler and protected-record engine
retain their distinct modeled/tested status; these linked numeric proofs do
not establish whole-component or endpoint verification. The local progress
optimum assumes effective input availability after an external work budget.

## Transcript and typed key-schedule models

`Tls13/Transcript.lean` keeps an ordered **ghost history** of complete parsed
handshake messages. The Rust implementation streams their bytes and need not
store this list. Appending preserves order exactly. A HelloRetryRequest rewrite
is permitted only for a healthy, not-yet-rewritten history containing exactly
one ClientHello; its result is exactly the synthetic message_hash of the encoded
ClientHello followed by the supplied HRR ServerHello. A rejected rewrite
preserves history and poisons the state, and a poisoned state cannot append.

The caller supplies an already-recognized HRR; the model checks its ServerHello
type but does not validate the HRR random, negotiation fields, extensions, or
encoded-message parser. Synthetic message_hash has type 254 and contains the
hash of the entire encoded ClientHello. Hash output size (32 or 48 bytes),
streaming-provider equivalence, and hash security remain external obligations.
The arbitrary hash function is a parameter, not a custom Lean axiom.

Finished verification explicitly consumes the current ordered transcript
snapshot. The endpoint must choose the correct transcript boundary (before
appending the received Finished being verified). `finished_binds_current_snapshot` is conditional on a stated provider
soundness premise: acceptance implies the supplied tag equals HMAC of that
snapshot. It assumes neither hash nor HMAC injectivity and does not establish
peer identity or exclude collisions. The modeled endpoint's failed-Finished
policy prevents application release. The Rust low-level verification helper
returns an error; its caller must terminate/drop the affected handshake. That
future endpoint behavior is not proved merely by this model.

`Tls13/KeySchedule.lean` selects secret coordinates by client/server direction,
handshake/application stage, and epoch together. Wrong coordinates fail.
Traffic update is application-only, preserves direction/stage, and strictly
increments the epoch within its configured and u64 bounds. These are coordinate
and state-policy proofs, not cryptographic secrecy, key erasure, or proof of the
Rust generic ownership implementation.

The HKDF-label numeric guard accepts output length≤65535, user label length in
1..249, and context length≤255. The literal six-byte ASCII `tls13 ` prefix and
mandatory two-byte output length, one-byte label length, and one-byte context
length yield exactly `10 + labelLength + contextLength` bytes, at most 514.
The numeric-byte encoder achieves that length. `hkdfLabel_footprint_minimal`
proves that every layout retaining all required fields and bytes has at least
that many bytes. This is a fixed-format serialization lower bound; it makes no
CPU-time, compression, or alternative-protocol optimality claim.

The new command `label-size OUT LABEL CONTEXT` returns the decimal encoded size
or `error`, with the same native unsigned-64-bit CLI domain. The model's fields
use mathematical naturals; linked translation proofs separately check actual
machine operations. PKIX and CertificateVerify through the maintained adapter
are tested components, not covered by these Lean models.

## Linked HKDF-label guard

`verification/aeneas/KeyScheduleProof.lean` proves the actual extracted
`hkdf_label_encoded_len` agrees exactly with `hkdfLabelSize` for every
representable input, succeeds without overflow for accepted lengths, rejects
invalid lengths, and returns the minimum mandatory-format footprint described
above. Both machine additions are checked through the backend's integer
specifications; arithmetic success is not an assumption. The model encoder
attains this footprint, while actual Rust encoder byte writes retain their
separate regression-test status.

All four new theorem closures are exactly `[propext, Classical.choice,
Quot.sound]`. The complete automated audit passes for 113 theorems (92 standalone
models plus 21 linked theorems across six production helpers). The current
executable comparison passes 4,923 cases across ten commands, including 553
label-size and 876 client-phase cases. These comparison results do not broaden the formal refinement
scope to whole key-schedule, transcript, PKI, or TLS implementations.


## Client flight policy

`Tls13/Client.lean` models the no-PSK client flight gate with phases
0 AwaitServerHello, 1 AwaitEncryptedExtensions, 2 AwaitCertificate,
3 AwaitCertificateVerify, 4 AwaitServerFinished, 5 AuthenticatedPendingClientFinished,
6 Established, and 7 Failed. Matching verified events 2,8,11,15,20,252 advance
phases zero through five. Internal event252 is successful client Finished handoff;
253 is a previously validated HRR and 255 is fatal failure. Fatal failure reaches
Failed from every phase, even without verification evidence. All other events
require verification, and unexpected events are rejected.

The pair-state wrapper atomically records an accepted HRR in `retried`. Accepted
HRR requires phase zero and no earlier retry, so every reachable trace has at
most one HRR. The pure Rust guard only reads this flag; it cannot itself establish
that callers update it correctly. The modeled endpoint wrapper turns rejection
into terminal Failed. Accepted traces beginning at the initial state require
verified Certificate, CertificateVerify, server Finished, and successful client
Finished handoff before reaching Established. Release additionally needs AEAD
success. Certificate evidence includes both chain and reference-identity checks.

These are policy implications under supplied verification evidence. They do not
prove the actual cryptographic checks, wire parsing, body semantics, transcript
boundaries, network handoff, or the entire Rust endpoint. The implementation's
exhaustive 262,144-case relation test is separate from a translation proof.

`client-phase PHASE MESSAGE VERIFIED RETRIED` returns decimal next phase or
`error`. Phase and message fit u8; Boolean arguments are decimal 0 or 1.


`verification/aeneas/ClientProof.lean` now checks the actual extracted pure Rust
phase guard. It proves total ordinary Option execution, exact correspondence
with `clientPhaseNext`, a necessary-and-sufficient legal-transition relation,
unverified rejection, terminal Failed and duplicate-HRR rejection. The final
linked build and combined audit pass for 113 theorems, using only standard Lean
foundations. All five new linked closures are exactly
`[propext, Classical.choice, Quot.sound]`.

The atomic retry bookkeeping, reachable-history evidence, and release wrapper
remain model-level results. Linked proof of a phase decision does not prove that
the full endpoint supplies truthful verification evidence or executes each
modeled state mutation. The established record-count/fixed-overhead and label
footprint optimality results are preserved; no new global performance claim is
made for this policy guard.


## Plaintext loan after partial reads

`Tls13/Zeroization.lean` models bytes with `Nat → UInt8`, restricted to a loan
length. Opening preserves arbitrary content and zeroes its complete remaining
tail. The invariant divides the loan into a zero consumed prefix, arbitrary
unread content, and a zero tail. A read takes `min(requested, content-offset)`,
clears precisely that range, and advances the offset. The bounds proof also
shows the addition fits a machine maximum whenever the loan length does.

Fourteen checked theorems establish exact range mutation, zero-read behavior,
preservation through an arbitrary finite read sequence, and zero contents of
the whole loan when the read offset reaches content length. The final full-loan
wipe then changes no byte (`readPlaintext_final_wipe_redundant`). This is a
semantic redundancy result, not a predicted speedup or global CPU optimum.

The correspondence obligations are full-loan tail clearing after a successful
open, correct initial bounds, copy-before-clear behavior, exact interval
clearing, and no intervening writes or alias mutation. The model does not prove
Rust slice semantics or compiler-level erasure. It deliberately does not justify
shortening a provider's plaintext slice: that later change needs a distinct
cross-record invariant for the backing bytes omitted from the slice. Failure
and Drop wipes are retained outside this normal-read proof.

Main Lake build (27 jobs), source guard, and combined axiom audit pass. Current
total: **127 theorem closures = 106 model + 21 linked**, standard foundations
only. The six extracted helpers and 4,923 differential cases are unchanged;
new zeroization claims are **modeled**, not linked/proved Rust. Earlier counts
in this document describe prior milestones.


## Restricting opening to the active ciphertext prefix

`Tls13/PlainBacking.lean` builds on the unchanged stage-one zeroization model.
The whole plaintext backing loan starts clean. An operation can replace only
`[0, active)`; its footprint hypothesis preserves every byte outside that
prefix. On success, content fits the prefix and opening clears its own tail
`[content, active)`. The proof combines this tail with the untouched clean
`[active, loan)` backing to recover the original full-loan read invariant.

Completing any finite partial/zero-read trace restores a wholly clean backing
loan. A coarse transition model permits only complete record/read cycles,
whole-loan clears (the net effect of handshake/alert handling), and identity
controls (CCS). Induction proves any finite mixture preserves cleanliness at
new-record boundaries. An unconsumed application record cannot start the next
cycle. This is the stronger cross-record invariant needed to justify restricting
the buffer given to opening; stage-one `Zeroization.lean` itself is unchanged.

The eleven new theorems are model implications under explicit active-slice
bounds, footprint/tail-clearing, initial cleanliness, no-alias/no-concurrent-write,
and orchestration hypotheses. They do not translate the engine/provider or
prove cryptographic or compiler-level erasure properties. Actual debug
assertions and regression tests can check selected executions of these
obligations but do not upgrade the model to a linked Rust proof. The six linked
helpers and 4,923 numeric differential cases remain unchanged.

Main Lake build (29 jobs), source guard, and combined axiom audit pass. Current
total: **138 theorem closures = 117 model + 21 linked**, with only standard Lean
foundations. No audit/source scripts or retained translations changed.


## Public-wire fill versus sequential clearing

`Tls13/WireClearing.lean` proves a recursive byte-clear loop equals a bulk range
fill as a function from byte indices to observable byte values. It then models
partial drains using the bounded `min(requested, length-offset)` count. Drained
bytes become zero, the remaining suffix is unchanged, zero-length drains are
identities, and the consumed-prefix invariant yields an entirely zero valid
wire region at completion. The model assumes bytes were copied to the recipient
before this source mutation; it does not model that destination copy.

The range fill changes exactly initially nonzero consumed bytes. Every result
satisfying the same live consumed-bytes-zero contract must change those bytes,
so its changed support cannot be smaller. If all consumed bytes initially are
nonzero, each belongs to any valid write footprint. This worst-case condition
matters: the contract alone cannot require another store to an already-zero
byte. These are memory-state/footprint results, not CPU or store-count optima.

The application scope is ordinary consumed **public wire** storage only. Public
classification is an external security judgment, not a Lean theorem. Volatile
writes, compiler dead-store elimination, physical erasure, Rust/LLVM semantics,
and alias/concurrency effects are not modeled. Consequently observable equality
does not authorize replacing secret plaintext/key/error/Drop zeroization. No
new Rust function is translated and no endpoint-refinement claim is made.

Main Lake build (31 jobs), source guard, and combined axiom audit passed for
**148 closures = 127 model + 21 linked**, with only standard Lean foundations.
Earlier milestone totals remain historical; the six translated helpers and
4,923 differential comparisons are unchanged.


## Chunked secret zeroization

`Tls13/ChunkedZeroization.lean` gives separate byte-state proofs for fixed-width
blocks plus remainder and for arbitrary byte-head/word-middle/byte-tail
partitions. A generic adjacent-clear composition theorem proves that clearing
all partition chunks equals one range clear. Exact-range effects, empty input,
partial reads, and arbitrary completed read traces reuse the earlier clean
prefix/tail invariant. Any cumulative endpoint and the block-count product are
bounded by the original representable range, avoiding overflow-prone ceiling
addition.

For positive width, the full-width-block/remainder partition has minimum chunk
count among all width-bounded partitions of the same input. This does not
choose an optimal width or describe compiler/CPU performance. An aligned
partition need only cover exactly the requested range; the model does not
assume its middle is maximal. A separate optional tail<width hypothesis proves
minimum remaining chunk count after a **fixed head**. That model counts chunks,
not byte-tail stores or barriers, and is inapplicable without that hypothesis.

These are twenty model theorems, with no new extracted Rust helper. Actual
address alignment, disjoint safe views, absence of secret copies, trusted
zeroize semantics (including volatile word stores and barriers), and Rust/LLVM
lowering remain external obligations. The equivalence is observable byte state,
not a proof of physical erasure or compiler optimization resistance. Secret
head/middle/tail clearing must retain the trusted secret-erasure primitive;
the earlier ordinary-public-wire fill result does not establish that property.

Main Lake build (33 jobs), source guard, and combined axiom audit passed for
**168 closures = 147 model + 21 linked**, using only standard Lean foundations.
The prior totals describe earlier milestones; retained translations are unchanged.
