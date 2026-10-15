# Implementation correspondence

The project uses two independently executable implementations: the
Rust `tls-core` functions and a Lean reference built by Lake. A deterministic
cross-language corpus exercises common inputs, boundary values and rejection
paths. `python3 verification/check_models.py` builds both sides and compares
their outputs.

The cross-language comparison is **tested against model** assurance, not a proof that arbitrary Rust
executions refine the Lean model. Rust compilation, arithmetic widths, slice
operations and execution remain outside the Lean proof. Counter and wire
correspondence are recorded separately in `PROOF_LEDGER.md`; passing one
operation's comparison cannot promote the entire library to a higher level.

The optimality theorem concerns a specific objective: the smallest number of
capacity-bounded records for a fixed payload. The capacity is positive, every
record holds at most that many payload bytes, and fixed per-record overhead is
nonnegative. Greedy full-capacity segmentation meets the lower bound. Extra
constraints such as padding, epochs, application flush deadlines and record
type boundaries require a new model; processor cycles and end-to-end latency
are evaluated through benchmarks.

## Linked production arithmetic and type guards

`aeneas/generated/TlsCore.lean` was generated directly from
six production helpers, starting with rustc MIR through Charon, then translated
by Aeneas. Twenty-one audited theorems in `Proof.lean`, `ReassemblyProof.lean`,
`ProtectedProof.lean`, `KeyScheduleProof.lean` and `ClientProof.lean` cover this scope:

- `schedule::record_count`: zero-capacity rejection, successful checked
  arithmetic, equality to the model, minimum bounded-partition count and fixed
  framing-overhead cost.
- `handshake::checked_handshake_total`: exact Option/model agreement, u24/usize
  headroom, cap rejection and successful total length.
- `protected::inner_length`: exact Option/model agreement for all representable
  inputs, including both checked-add overflow paths and configured/protocol caps.
- `protected::valid_content_type`: exact Boolean/model agreement for type and
  content-length restrictions.
- `key_schedule::hkdf_label_encoded_len`: exact Option/model agreement, field
  bounds, overflow-safe additions, rejection and minimum mandatory-format byte
  footprint. Actual encoder slice writes are tested, not translated/refined.
- `client_policy::client_phase_next`: exact Option/model agreement for all
  u8/Boolean inputs, legal verified transitions, rejection of unverified
  nonfatal events, terminal failure and duplicate-HRR rejection. Whole-connection
  verification evidence and retry-flag writes are outside this scalar proof.

`cd verification/aeneas && lake build` checks this result on Lean 4.31.0 with
the pinned Aeneas backend and mathlib. All twenty-one theorem dependency audits are
subsets of `propext`, `Classical.choice`, and `Quot.sound`. No custom backend assumption
or proof admission enters these theorem proofs. Translation correctness,
Charon's MIR extraction and compiler/provider semantics remain trusted;
this is not compiler or whole-library verification. The initial extraction
was run natively on aarch64-apple-darwin with nightly-2026-09-17.

`python3 verification/check_translation.py` checks source/artifact hashes against
the retained extraction manifest. CI checks those hashes and rebuilds the linked
proof. CI does not rebuild the translator binaries or rerun extraction; changed
source/artifact hashes require an explicit regeneration and proof check. Hash
agreement catches stale evidence but does not prove translator correctness.

To regenerate with the exact pinned tools:

```sh
CHARON_BIN=/path/to/pinned/charon AENEAS_BIN=/path/to/pinned/aeneas \
  python3 verification/check_translation.py --regenerate
cd verification/aeneas
lake build
```

`aeneas/README.md` gives the tool pins and dependency bootstrap commands. The
[toolchain investigation](../docs/TOOLCHAIN_FEASIBILITY.md) records initial
discovery. The linked status applies only to the six named pure helpers; full
Rust chunk iteration, parsing/reassembly, counter ownership, authentication,
sealing/decryption, erasure and cryptography are not promoted by these proofs.

The corpus now compares 4,923 cases across ten operations, including 553
HKDF-label length cases and 876 client-phase cases. Streaming transcript/HRR,
typed secret and accepted client-flight trace models have
standalone proofs. Their production hash/provider orchestration is tested with
RFC8448 published hashes, intermediate secrets, Finished and record composition;
no full transcript refinement, cryptographic security or PKIX proof is claimed.

The actual `tls-client` connection invokes the translated phase guard after
maintained chain/identity, CertificateVerify and Finished checks; its final
event occurs after the last ClientFinished wire byte is handed to caller output.
Native rustls integration and provider-fault regressions test this composition.
The model's single-HRR trace and release implications require truthful evidence,
private serialized state and atomic retry bookkeeping. Those engine operations,
I/O progress and application release are not themselves translated/refined.

The `Zeroization` and `PlainBacking` byte-memory models add25 checked theorems
for precise consumed-range clears, zero/partial read progress, whole-loan zero
at completion, redundant final-wipe equality, and active-prefix/backing-tail
recombination across completed records/full-clear/identity controls. Actual Rust
slice writes, admission gates, byte-copy/wipe effects, provider footprint and
absence of aliasing remain explicit correspondence obligations. Real-rustls
private-buffer inspection, public partial-read/failure/Drop regressions and
fuzzing test those obligations; the full client is not translated/refined.
The linked six helpers/21 theorems remain unchanged. See
[optimization evidence](../docs/READ_OPTIMIZATION.md).

The `WireClearing` model adds ten standalone theorems for byte-loop/fill
observable equality, bounded partial drains, preserved queued suffixes, completed
clearing, and minimal changed-byte support. The mandatory footprint lower bound
requires initially nonzero consumed bytes; already-zero bytes need no store to
meet a final-state contract. Public-wire classification, real Rust/provider
writes and compiler semantics remain outside the model. This does not prove
volatile erasure, constant time or CPU optimality. Secret-bearing paths still
use `zeroize`; see [the measured scope](../docs/WIRE_CLEARING.md).

The original `?`-based inner-length helper translated to unsupported standard
Option/Try definitions represented as custom axioms. That artifact was rejected.
The production helper now uses equivalent explicit Some/None branches with a
scoped Clippy exception documenting the translator constraint. Regeneration
rejects admissions/custom axioms before retaining output; no stand-in definition
or admitted theorem is used to hide this tool limitation.

The `ChunkedZeroization` model adds20 standalone partition/byte-state theorems.
Arbitrary exact head/word-middle/tail coverage yields the same range clear and
read invariant without assuming maximal middle; conditional minimum chunk count
requires positive width, fixed head and tail<width. Runtime bytemuck views,
u128 representation, volatile granularity, compiler lowering and alias/provenance
remain trusted. An exact body-hashed copied helper passes isolated Miri on ARM64,
32-bit and big-endian targets, while actual peer tests inspect unaligned loans.
Neither evidence links the full helper/engine to Lean or proves CPU/erasure
optimality. See [the current measured boundary](../docs/SECRET_WIPING.md).

## Reassembler Drop aligned wiping

The core now uses pinned bytemuck 1.25.2 (`default-features = false`) for safe
head/u128-middle/tail views in `Reassembler::drop`, retaining `zeroize` on every
part of the entire caller loan. The constructor still does not clear storage;
therefore arbitrary unused caller bytes remain part of the required Drop wipe.
The existing `Tls13.alignedClear_equals_range` model in `ChunkedZeroization.lean` supports exact
byte-state equivalence under its footprint and trusted primitive assumptions.
The new guarded Drop test exercises the actual implementation separately.

Pinned extraction was regenerated because `handshake.rs` is whole-file hashed.
Generated Lean is byte-identical; LLBC changes only its embedded source text and
temporary destination path. This refresh preserves the same six-helper linked
scope. `ReassemblyProof.lean` proves the length helper, not `Reassembler::drop`.
Safe slice construction, volatile erasure, library/compiler semantics and the
complete engine remain outside the translated proof. Minimum fixed-width
chunk count does not establish global CPU or erasure-instruction optimality.
