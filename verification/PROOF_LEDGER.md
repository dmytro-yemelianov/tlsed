# Proof ledger

Status: experimental foundation, not a verified or complete TLS endpoint.
Standalone model checked 2026-10-14 using pinned Lean 4 v4.34.1.

## Reproduce

From the repository root:

```sh
(cd lean && lake build && lake env lean AxiomAudit.lean)
cargo test -p tls-core
(cd verification/aeneas && lake build)
python3 verification/check_axioms.py
```

`lake build` builds all thirteen model modules and `tls13_model`, with warnings as
errors. `AxiomAudit.lean` prints dependencies for all 147 required model theorems. Every
proof below is kernel checked; none uses an admission or custom axiom. Axiom
sets are subsets of the standard Lean foundations `{propext, Quot.sound,
Classical.choice}`; `encodeHeader_size` uses none. The exact per-theorem sets
are reproducible from the audit command.

**Modeled** means a checked model, **tested against model** additionally needs
recorded executable agreement, and **linked/proved** requires a checked theorem
about an actual verified translation. The coordinator's
`verification/CORRESPONDENCE.md` records executable comparison evidence and
translation scope. The standalone proofs in this table are kernel-checked models. The recorded
`verification/results/model-comparison.json` run passed **4,923 cases** on a
64-bit target: count 306, header 948, reserve 292, rotate 292, auth 49, release
21, handshake-total 320, inner-check 1266, label-size 553, and client-phase 876. These ten numeric
commands are **tested against model**. Six pure Rust functions have
the separately checked **linked/proved** results described below. Cursor arithmetic,
byte-codec round trips, concrete partition construction, and trace properties
remain **modeled**: the comparison did not exercise those entire implementations.
No successful comparison changes other functions' status.

All theorem names below have namespace prefix `Tls13.`.

| Checked theorem(s) | Requirement / objective | Rust correspondence target | Assumptions and exact claim |
|---|---|---|---|
| `recordCount_feasible` | Optimization objective; RFC 9846 §5 payload caps | `schedule::record_count` | `0 < limit`; `n ≤ count * limit`. |
| `recordCount_minimal` | Minimum record count | `schedule::record_count` | `0 < limit`, `n ≤ k * limit`; returned count ≤ k. |
| `recordCount_le_input` | Nonoverflowing optimization arithmetic | `schedule::record_count` | `0 < limit`; count ≤ n, so result fits wherever n fits. Machine operations need separate correspondence. |
| `recordPartition_sum` | Feasible partition | `schedule::ChunkSchedule` | Sum of constructed full records and optional remainder is n. |
| `recordPartition_length` | Feasible partition | `schedule::ChunkSchedule` | Constructed partition length equals recordCount. |
| `recordPartition_bounded` | RFC 9846 §5 / feasible partition | `schedule::ChunkSchedule` | Positive capacity; each constructed chunk is positive and ≤ capacity. |
| `partition_capacity` | Partition lower bound | `schedule::ChunkSchedule` | Each finite-list chunk ≤ capacity; sum ≤ length * capacity. |
| `recordCount_partition_optimal` | True minimum across all valid partitions | `schedule::record_count` | Positive fixed capacity and arbitrary finite partition summing to n; count ≤ partition length. |
| `fixed_overhead_optimal` | Declared optimization cost | `schedule::record_count` | Fixed nonnegative overhead, same n and capacity; minimizes n + overhead * record count. No CPU/latency/crypto optimum. |
| `accepted_length_bounded` | RFC 9846 §§5.1–5.2 | `wire::Header::validate` | Successful numeric header check bounds length by configured cap and cap by protocol cap. |
| `oversized_rejected` | RFC 9846 §§5.1–5.2 | `wire::Header::validate` | A declared length above cap cannot be accepted. |
| `invalid_cap_rejected` | RFC 9846 §§5.1–5.2 | `wire::Header::validate` | A configured cap above the protocol maximum cannot be accepted. |
| `ciphertext_header_guard` | RFC 9846 §5.2 | `wire::Header::validate` | Success requires outer type23, version0x0303, positive length. Does not validate AEAD/payload. |
| `readRange_safe` | Bounded parsing | `wire` cursor/slice arithmetic | Successful checked cursor advance is monotone, exact, and within supplied input length. Abstract arithmetic only. |
| `readRange_rejects_truncation` | Bounded parsing | `wire` cursor/slice arithmetic | End beyond input cannot succeed. Abstract arithmetic only. |
| `encodeHeader_size` | RFC 9846 §§5.1–5.2 | `wire::Header::encode` | Header model always encodes five numeric bytes. |
| `decode_encode_header` | Header codec round trip | `wire::parse_header` / `wire::Header::encode` | kind fits u8, version/length fit u16; numeric byte encode/decode round trips. |
| `reserveNext_safe` | RFC 9846 §5.3 | `counter::reserve_next` | Success increments exactly one, strictly increases, stays ≤ supplied use limit and u64 maximum. |
| `exhausted_sequence_rejected` | RFC 9846 §§5.3,5.5 | `counter::reserve_next` | At/above limit or maximum, reservation fails. |
| `rotateEpoch_safe` | RFC 9846 §4.7.3 | `counter::rotate_epoch` | Success increments exactly one, strictly increases, stays within cap and u64 maximum. |
| `exhausted_epoch_rejected` | RFC 9846 §4.7.3 | `counter::rotate_epoch` | At/above cap or maximum, rotation fails. |
| `reservations_monotone` | RFC 9846 §5.3 | owned traffic counter | Sequential successful reservations never decrease state. |
| `reservation_in_range` | RFC 9846 §5.3 | owned traffic counter | Every consumed sequence lies in the trace's start/end half-open interval. |
| `reservations_unique` | RFC 9846 §5.3 | owned traffic counter | All consumed sequences in a finite same-epoch trace are distinct, assuming atomic state consumption/no rollback. |
| `rotated_coordinates_distinct` | RFC 9846 §§5.3,4.7.3 | owned traffic counter | Successful rotation separates old/new (epoch,sequence) pairs for arbitrary sequence values. Fresh keys/nonce injectivity remain assumptions. |
| `authStep_characterization` | Guarded client authentication stages | `auth::transition` | Successful step is abort/failure to Failed or one matching stage advance; symbolic evidence events only. |
| `unexpected_event_rejected` | No illegal advance | `auth::transition` | Valid state and ordinary event differing from current stage return no successful next state. |
| `failure_is_terminal` | Fail closed | `auth::transition` | Any successful transition from Failed remains Failed. |
| `authTrace_evidence` | Ordered authentication evidence | `auth::transition` | Reachable trace; every completed stage has its earlier evidence event in the trace. |
| `established_requires_authentication` | RFC 9846 §§4.5.1–4.5.3; RFC 5280/9525 | `auth` guarded client model | Reachable Established requires combined chain+identity event, CertificateVerify event, and Finished event. Events assume actual external verification. |
| `aead_failure_blocks_release` | RFC 9846 §5.2 | `auth::may_release` | False AEAD result always prevents release. |
| `release_requires_established` | Authenticated data release | `auth::may_release` | Release implies Established and successful AEAD. |
| `release_requires_authentication` | Authenticated data release | `auth` guarded client model | Reachable state plus release implies all three verification events and successful AEAD. |

## Protected records and bounded handshake reassembly

The following 21 additional model theorems passed `lake build` and the axiom
audit on 2026-10-14. Their dependency sets are subsets of the same standard
Lean foundations; no custom axiom or admission is used. These rows are
**modeled** unless a separate comparison or translated proof below explicitly
upgrades the particular numeric operation. The full provider, record reader,
and Rust reassembler are not formally refined by these models.

| Theorem (prefix `Tls13.`) | Requirement / Rust target | Checked assumptions and result |
|---|---|---|
| `handshakeTotal_bounds` | RFC 9846 §4, u24 handshake framing / `handshake::checked_handshake_total` | Successful total is body+4, ≤ cap+4, ≤ 16777219, and < 2^32. |
| `handshakeTotal_accepts` | Handshake length guard | Any body within u24 and configured bounds returns body+4. |
| `handshakeTotal_rejects` | Resource limits | Body over either u24 or configured cap returns failure. |
| `copyProgress_bounds` | Bounded reassembly | Initial buffered≤target; greedy count≤input and buffered+count≤target. |
| `copyProgress_maximal` | Local progress optimum | Any count fitting both available input and retained-message target is ≤ greedy min count. No CPU/throughput claim. |
| `reassembly_rejects_before_copy` | Reject resource amplification | Excessive declared body makes the modeled body-copy operation fail before any successful copy. |
| `reassemblyStep_bounded` | Bounded retained handshake message | Success consumes≤available input and retains≤body+4, ≤cap+4, and ≤16777219. Header was already validated/retained. |
| `checkedInnerLength_matches` | Numeric protected guard correspondence | Numeric length helper success combined with valid type is exactly innerAccepted. |
| `innerAccepted_bounds` | RFC 9846 §§5.2,5.4 / protected inner length guards | Successful check bounds content≤16384, full inner≤configured limit and 16385, and inner+16-byte-tag≤16640. |
| `innerAccepted_type` | Valid protected content type | Successful check has type23, nonempty type22, or exactly-two-byte type21. |
| `innerAccepted_rejects_overflow` | Inner-record resource bounds | Full inner length >16385 always fails, regardless of configured limit. |
| `stripInnerPadding_shape` | RFC 9846 §5.4 padding decode | Successful reverse scan identifies a nonzero type and exactly zero bytes after it. Natural-byte model. |
| `stripInnerPadding_length` | Bounded decode | Content length+1≤input length on successful reverse scan. |
| `all_zero_inner_rejected` | Missing inner content type | Any finite all-zero input fails the scan. |
| `openInner_requires_authentication` | Protected data release conditions | Success requires provider AEAD evidence, valid type/content, full input≤configured/protocol caps, and successful padding decode. |
| `openInner_content_bound` | RFC 9846 §5.2 | Successful decoded content≤16384. |
| `openInner_padding_shape` | RFC 9846 §5.4 | Accepted original bytes are exactly content ++ [type] ++ zero-padding. |
| `failed_aead_releases_empty` | No unauthenticated plaintext release | False AEAD evidence returns an empty mathematical release buffer; actual provider wiping remains a separate implementation obligation. |

The provider-output wrapper also has these modeled checks:

| Theorem (prefix `Tls13.`) | Checked result |
|---|---|
| `provider_length_mismatch_rejected` | If decrypted length plus 16 differs from ciphertext length, opening fails. |
| `openProtected_bounds` | Successful modeled opening requires AEAD evidence and ciphertext length in 17..16401 (hence ≤16640), with exact 16-byte tag accounting. |
| `failed_aead_cannot_open` | False AEAD evidence cannot produce a successful opening, even when lengths agree. |

## Linked proof: actual translated Rust record count

`verification/aeneas/Proof.lean` successfully built on 2026-10-14 with the
pinned Aeneas-compatible **Lean 4 v4.31.0**, Aeneas revision
`557eff83ecef5083b98a52a94ca7fae63d6c1dab`, and mathlib revision
`fabf563a7c95a166b8d7b6efca11c8b4dc9d911f`. This separate project imports the
same `lean/Tls13/Segmentation.lean` source; the standalone model remains on
v4.34.1. All project proof files use warnings-as-errors. The external Aeneas
cache replays three duplicate-namespace style warnings; none is in our proofs.

The target is `tls_core.schedule.record_count` in the generated
`verification/aeneas/generated/TlsCore.lean`, extracted from the production
`crates/tls-core/src/schedule.rs::record_count`. This is not a second handwritten
implementation used in place of the Rust translation. The coordinator's
translation provenance records the extractor, source hashes, and reproduction
commands.

| Theorem (prefix `Tls13.Linked.`) | Checked result | Status |
|---|---|---|
| `record_count_zero` | Zero capacity returns the domain error `InvalidLimit`, not a panic in the translated semantics. | Linked/proved, subject to translation trust |
| `record_count_refines` | Every representable input with positive capacity returns `Ok result` in the Aeneas semantics; `result.val = Tls13.recordCount bytes.val capacity.val`. Division/remainder zero guards and checked-add overflow obligations are discharged. | Linked/proved, subject to translation trust |
| `record_count_optimal` | The actual translated result has enough aggregate capacity and is no larger than the length of any finite capacity-respecting partition carrying the same bytes. | Linked/proved, subject to translation trust |
| `record_count_cost_optimal` | That result minimizes payload plus a fixed nonnegative overhead per record over those partitions. | Linked/proved, subject to translation trust |

`#print axioms` for **each of these four theorems** reports exactly
`[propext, Classical.choice, Quot.sound]`. No custom backend axiom or `sorryAx`
is in their dependency closures. The proofs use the backend's checked integer
operation specifications and prove the addition's upper bound from
`recordCount_le_input`; they do not assume arithmetic success.

Trusted boundaries include Rust MIR extraction by Charon, Aeneas translation,
the stated backend semantics, the Rust compiler/toolchain and source-selection
pipeline, and Lean's kernel. Neither source-to-MIR nor translator correctness
is proved by this project. The optimization proof in this section covers **only the pure
`record_count` function**. It does not cover `ChunkSchedule` iteration, buffer
handling, other Rust functions, external cryptography, or complete TLS. The
optimality objective remains only the explicitly stated fixed-capacity,
fixed-overhead cost model.

## Linked proof: handshake and protected-record guards

The same pinned translation project now checks `ReassemblyProof.lean` and
`ProtectedProof.lean`, importing the unchanged standalone `Reassembly.lean`
and `Protected.lean` model sources. `lake build` successfully checked all
five proof modules (21 linked theorem audits in total, including the label-size
and client-policy proofs below) on 2026-10-14. The retained `TlsCore.lean` artifact includes six
actual production functions: `record_count`, `checked_handshake_total`,
`inner_length`, `valid_content_type`, `hkdf_label_encoded_len`, and
`client_phase_next`. Source/artifact freshness remains enforced by the
coordinator's translation pipeline.

The additional checked theorems have prefix `Tls13.Linked.`:

| Theorem | Checked result / scope |
|---|---|
| `usize_has_u24_headroom` | Backend usize max is at least 16777219, derived from the bundled 32-or-64-bit platform theorem. No user-supplied width axiom. |
| `checked_add_refines` | Backend checked addition maps exactly to the mathematical sum when representable, and otherwise None. |
| `handshake_total_refines` | Actual translated handshake guard returns an `ok` Option whose mapped numeric result exactly equals checkedHandshakeTotal, for every representable input. |
| `handshake_total_success` | Valid u24/configured body returns Some(body+4), bounded by cap+4 and 16777219; checked addition cannot fail. |
| `handshake_total_rejects` | Body above u24 or configured cap returns `ok none`, not an arithmetic failure. |
| `max_inner_plaintext_evaluates` | The translated constant calculation 16384+1 succeeds and equals 16385. |
| `inner_length_refines` | Actual translated protected length helper exactly matches checkedInnerLength on every representable input, including zero/excessive limits and both checked-add overflow paths. |
| `valid_content_type_refines` | Actual translated type/content check returns exactly the modeled Boolean policy for every u8 type and usize length. |

All are **linked/proved under the documented translation trust boundary**.
`usize_has_u24_headroom` depends on `[propext, Quot.sound]`. Each of the other
seven new theorem closures is exactly `[propext, Classical.choice, Quot.sound]`.
There are no custom backend axioms or admissions in these dependency closures.

The production inner-length helper uses explicit Option branches because the
pinned translator cannot resolve Rust Option `?` through its Try-trait methods.
The explicit branches preserve the checked-add semantics and allow translation
without opaque custom axioms. Both success and failure cases are proved;
there is no premise assuming successful addition.

These results upgrade **only these pure numeric guards**. Full Rust reassembly,
work-budget handling, protected reader/writer state, padding scanning, actual
buffer wiping, crypto calls, nonce generation, and authenticated peer identity
remain outside linked verification. The model's greedy-copy maximum theorem
applies to effective available input after any external work-budget restriction;
it is not a refinement proof of the complete loop.

## Transcript and key-schedule models

All 21 new model theorems below passed the standalone Lean 4.34.1 build and
axiom audit, bringing the model total to **75**. Their axiom dependencies are
subsets of the same standard Lean foundations; `synthetic_message_hash_contents`
uses no axioms. They are **modeled**, with numeric guard correspondence upgraded
only by the separately recorded translated proof. No PKIX proof is claimed.

| Theorem (prefix `Tls13.`) | Requirement / target | Checked statement and assumptions |
|---|---|---|
| `hkdfLabelSize_bounds` | TLS HKDF label lengths | Accepted output fits u16, prefixed label/context fit u8, and exact encoded size≤514. |
| `hkdfLabelSize_rejects` | Reject invalid label lengths | Rejects output>65535, empty user label, label>249, or context>255. |
| `encodeHkdfLabel_length` | Exact fixed-format encoding | Numeric-byte encoding occupies 10+label.length+context.length. Input byte validity is a separate obligation. |
| `encodeHkdfLabel_fits` | Bounded label serialization | Accepted guard equals actual model encoding length and is≤514. |
| `hkdfLabel_footprint_minimal` | Minimum required serialization footprint | Any concatenated layout with all mandatory field widths, six prefix bytes, and complete label/context has at least the computed length. Fixed TLS format only; no CPU/compression optimum. |
| `selectedSecret_matches` | Direction/stage/epoch separation | Successful coordinate selection matches all requested dimensions. Secret bytes and Rust ownership are not refined here. |
| `wrong_secret_coordinate_rejected` | Reject key confusion | Any differing direction, stage, or epoch causes selection failure. |
| `traffic_update_monotone` | Application traffic update | Successful modeled update preserves direction, remains application-stage, increments epoch exactly, and respects cap/u64 bounds. |
| `handshake_key_cannot_update` | KeyUpdate stage guard | Handshake coordinates cannot be updated as application traffic. |
| `failed_finished_blocks_release` | Fail-closed endpoint policy | Failed Finished evidence moves the modeled auth policy to Failed and prohibits release. Rust's low-level verifier only returns Err; future endpoint integration must enforce this policy. |
| `finished_establishment_requires_stage` | Authentication ordering | Modeled Finished establishment requires the prior signature-verified stage and successful verification. |
| `transcript_append_order` | Ordered transcript bytes | Healthy append extends encoded history exactly in order. Complete parsed messages are assumed. |
| `failed_transcript_cannot_advance` | Poisoned transcript state | Appending to a failed transcript preserves state. |
| `hrr_rewrite_exact` | HRR synthetic transcript | Valid single-ClientHello state rewrites to [message_hash(Hash(encodedCH)), HRR]. |
| `hrr_rewrite_guarded` | HRR ordering/single rewrite | Successful rewrite requires healthy/unretried state, exactly one ClientHello, and supplied ServerHello type; produces rewritten flag and exact history. Caller has recognized the HRR random/format. |
| `hrr_duplicate_rejected` | Single HRR | Previously rewritten state cannot rewrite again. |
| `hrr_failure_preserves_and_poisons` | Transcript failure safety | Rejected rewrite preserves prior history and poisons state. |
| `hrr_success_binds_rewritten_order` | Ordered synthetic transcript | Successful byte history contains encoded synthetic message_hash followed by encoded HRR, in that order. |
| `synthetic_message_hash_contents` | HRR hash binding | Synthetic message has type254 and hash of the entire encoded ClientHello as body. Hash is a function parameter. |
| `finished_verification_uses_current_snapshot` | Finished transcript binding | Accepted modeled verification uses exactly the current ordered transcript hash and a healthy state. |
| `finished_binds_current_snapshot` | Conditional HMAC binding | Under explicit verifier-soundness premise, accepted tag equals HMAC(current snapshot). No collision-freedom, injectivity, identity, or cryptographic implementation proof. |

## Linked proof: HKDF label size and mandatory footprint

`KeyScheduleProof.lean` successfully checks four additional theorems against the
actual extracted `key_schedule::hkdf_label_encoded_len` function. The same
pinned Lean 4.31.0 / Aeneas / mathlib project imports the standalone
`Tls13/KeySchedule.lean` source. Exact source/artifact provenance is retained by
the coordinator. Status: **linked/proved under the translation trust boundary**.

| Theorem (prefix `Tls13.Linked.`) | Checked result |
|---|---|
| `hkdf_label_size_refines` | For every representable output/label/context length, the actual translated helper returns an `ok` Option whose numeric result exactly equals hkdfLabelSize. Both native additions' overflow obligations are discharged. |
| `hkdf_label_size_success` | Valid lengths return Some(10+label+context), bounded by 514, without arithmetic failure. |
| `hkdf_label_size_rejects` | Oversized output, empty/excessive label, or excessive context returns `ok none`. |
| `hkdf_label_size_minimal` | The actual returned count is at most the length of any layout retaining every mandatory field and complete label/context. The model encoder attains that size. This is a fixed-format byte-footprint result, not CPU or cryptographic optimality. |

Each new theorem's axiom dependency set is exactly
`[propext, Classical.choice, Quot.sound]`. The full executable audit
`python3 verification/check_axioms.py` passed for **113 theorems: 92 model and
21 linked**, recording only standard foundations in
`verification/results/axiom-audit.json`. No custom cryptographic axiom or
admission is used. The existing linked record-count optimality remains checked.

This proof upgrades only the numeric size helper. Actual `encode_hkdf_label`
byte/slice writes, streaming hash state, HRR classification, HKDF/HMAC operations,
Finished verification implementation, typed secret ownership/zeroization, and
PKIX remain separately tested or modeled. The conditional Finished model theorem
is not a proof of provider HMAC security or the complete authentication endpoint.

## Client flight policy model

`Tls13/Client.lean` adds 17 kernel-checked model theorems. The main Lean build
and all 92 model axiom audits pass with standard foundations only. The production
`client_policy::client_phase_next` pure guard has an exhaustive Rust regression
covering all 262,144 combinations of two u8 inputs and two Boolean inputs, plus
a complete retry/flight regression. These Rust tests do not establish refinement.

| Theorem (prefix `Tls13.`) | Checked result and assumptions |
|---|---|
| `clientFlightMessage_bounded` | The six ordinary expected flight event codes are at most 252. |
| `clientPhaseNext_exact` | Success is exactly fatal255→Failed7, a verified matching flight0..5→next phase, or verified first HRR253 at phase0 with retried=false. |
| `client_unverified_rejected` | Every nonfatal event without verification evidence is rejected. |
| `client_failed_terminal` | Any successful phase transition from Failed remains Failed. |
| `client_successor_bounded` | Every successful successor is in 0..7. |
| `client_established_no_handshake` | Established rejects all ordinary handshake events. |
| `client_step_projects` | Accepted pair transition projects to the pure phase guard and atomically sets the retry flag for HRR. |
| `client_illegal_enters_failed` | The modeled endpoint wrapper maps a rejected transition to Failed. |
| `client_apply_failure_terminal` | Failed remains Failed under the wrapper, including rejected events. |
| `client_hrr_bookkeeping` | Successful HRR requires phase0/retried=false and yields phase0/retried=true. |
| `client_duplicate_hrr_rejected` | HRR with retried=true is rejected in every phase. |
| `client_trace_evidence` | Every completed flight in a reachable accepted trace has its matching verified event in history. |
| `client_established_requires_verified_flights` | Reachable Established requires verified Certificate11, CertificateVerify15, server Finished20 and client Finished handoff252. |
| `client_trace_retry_count` | In an accepted trace with atomic pair bookkeeping, HRR count equals zero/one according to the retry flag. |
| `client_trace_at_most_one_hrr` | Such a trace contains at most one accepted HRR. |
| `client_release_requires_established` | Modeled release requires phase6 and successful record AEAD. |
| `client_release_requires_verified_flights` | Reachable release implies all four verified authentication/handoff events. |

The verification bit is external evidence, not a proof that parsing, chain and
reference-identity validation, CertificateVerify, or Finished succeeded. The
Certificate event requires chain and identity evidence together. Internal event252
means client Finished was handed off successfully. The pure guard does not write
the retry flag; single-HRR trace results require the separately modeled atomic
pair update. Full Rust endpoint composition, state ownership, alert/I/O behavior,
and release/secret retirement remain outside the scalar guard's proof scope.

### Linked client phase guard

`verification/aeneas/ClientProof.lean` checks the actual extracted production
`client_policy::client_phase_next` on all representable u8/Boolean inputs.
The final linked `lake build` and `python3 verification/check_axioms.py` pass:
**113 audited theorems = 92 model + 21 linked across six production helpers**.
Every new linked theorem has exactly `[propext, Classical.choice, Quot.sound]`.
There are no custom axioms or admissions. Existing linked record-count and
mandatory-label-footprint optimality remain checked under their original costs.

| Theorem (prefix `Tls13.Linked.`) | Checked translated result |
|---|---|
| `client_phase_refines` | Every input returns an ordinary Option result without backend failure; mapping its byte value agrees exactly with the natural policy. |
| `client_phase_accepts_exact` | Accepted production executions satisfy exactly the fatal, matching verified flight, or first verified HRR cases. The implication holds in both directions. |
| `client_phase_unverified_rejects` | Every unverified nonfatal production event returns None. |
| `client_phase_failed_terminal` | A successful production transition from Failed returns Failed. |
| `client_phase_duplicate_hrr_rejects` | Production rejects HRR whenever retried=true, in every phase. |

This upgrades the scalar guard to **linked/proved** under the retained
Charon/Aeneas/backend/compiler trust boundary. It does not upgrade the actual
Rust connection, the retry-flag write, or the source of verification evidence.
The accepted-history/HRR-count/release theorems remain model implications under
that wiring. The current ten-command comparison report includes 876 client-phase cases;
its 4,923 cases remain separate regression evidence, not a refinement argument.

## Plaintext read zeroization invariant

`Tls13/Zeroization.lean` adds **14 modeled theorems**. Main `lake build`
passed (27 jobs); `check_proof_sources.py` passed; the combined axiom audit
passed for **127 theorems = 106 model + 21 linked**. All closures use only
standard Lean foundations. These are new model results, not additional
translated Rust proofs or executable differential cases.

`PlainMemory` maps indices to actual `UInt8` values. Only indices below `loan`
belong to the caller buffer. `openedPlaintext` leaves content arbitrary and
clears `[content, loan)`. `CleanPlaintext` asserts
`offset ≤ content ≤ loan`, zero bytes in `[0, offset)`, and zero bytes in
`[content, loan)`. A read consumes `min(requested, content - offset)`, copies
those old bytes to its destination, wipes exactly the consumed interval, and
advances its offset. Copying to the destination is an implementation obligation;
this memory model specifies the source mutation, not destination semantics.

| Theorem (prefix `Tls13.`) | Checked result |
|---|---|
| `openedPlaintext_content`, `openedPlaintext_tail`, `openedPlaintext_clean` | Modeled successful opening preserves arbitrary content, clears the entire loan tail, and establishes the invariant at offset zero. |
| `readAmount_bounds`, `readAmount_machine_bound` | Consumption fits the request; the offset advances monotonically within content; its addition fits any machine maximum that represents the loan length. |
| `consumedPlaintext_inside`, `consumedPlaintext_outside` | Exactly the consumed interval is cleared; every other byte remains unchanged. |
| `consumedPlaintext_zero`, `readPlaintext_zero_request` | Zero consumption or a zero-length request leaves memory unchanged. |
| `readPlaintext_preserves_clean` | Each read preserves the zero prefix and entire zero tail, including partial reads. |
| `readPlaintext_complete_zero` | At offset=content, every byte of the loan is zero. |
| `readPlaintext_final_wipe_redundant` | A final full-loan wipe is extensionally identical to doing nothing when the invariant holds and content is exhausted. |
| `plainReads_preserves_clean`, `plainReads_complete_zero` | The same invariant and completion result hold after any finite sequence of partial or zero-length reads. |

The optimization correspondence requires actual successful record opening to
clear **the entire loan** after content, actual reads to copy before wiping the
exact consumed source interval, no intervening alias/concurrent writer, and
bounds `offset ≤ content ≤ loan`. The theorem does not establish compiler-level
erasure, destination alias safety, AEAD success, or a complete Rust refinement.
Error and Drop wiping remain outside this normal-read argument. Passing only a
short ciphertext-sized slice to a provider would require an additional invariant
for untouched backing storage across records; this proof does not supply it.
The earlier 113-theorem counts above describe their respective milestones.

## Active-prefix opening and clean backing across records

`Tls13/PlainBacking.lean` adds **11 modeled theorems**, importing the unchanged
stage-one `Zeroization.lean`. Main `lake build` passed (29 jobs), the source
guard passed, and the combined axiom audit passed for **138 theorem closures =
117 model + 21 linked**, using standard Lean foundations only. No custom
assumptions or admissions were introduced. `WholePlainClean` requires every byte below the
whole loan length to be zero. `WritesActivePrefix` requires the opening result
to equal its preceding memory at every index outside `[0, active)`; this is an
explicit provider/slice footprint hypothesis. Content is arbitrary, with
`content ≤ active ≤ loan`. Opening must clear `[content, active)`.

| Theorem (prefix `Tls13.`) | Checked result |
|---|---|
| `replacePlainPrefix_inside`, `replacePlainPrefix_footprint` | Functional prefix replacement exposes new prefix bytes and preserves every byte outside it. |
| `activeOpen_preserves_backing` | A clean backing loan remains zero outside the active prefix after a footprint-respecting operation. |
| `activeOpen_tail_recombined` | The newly cleared active tail and untouched backing combine into a zero tail over `[content, loan)`. |
| `activeOpen_clean` | Bounded active opening establishes the stage-one full-loan `CleanPlaintext` invariant at offset zero. |
| `replaceOpenedPrefix_clean` | The existing successful-open model, restricted to the active prefix and reinserted into clean backing, satisfies that invariant. |
| `activeOpen_complete_reads_clean` | Any complete stage-one read trace restores whole-loan cleanliness for the next record. |
| `fullClear_backing_clean`, `identity_backing_clean` | Whole-loan clearing establishes cleanliness regardless of previous bytes; an unchanged buffer preserves it. These are the control-message abstraction boundaries. |
| `plainBackingAction_clean`, `plainBackingCycles_clean` | Cleanliness survives any finite mixture of completed record/read cycles, full clears, and identity controls. An incomplete read is not a permitted new-record boundary. |

The actual engine must establish initial full-buffer cleanliness, gate new
records until the previous application content is exhausted, enforce active
slice bounds, and retain full error/Drop/control-message wipes. Actual opening
must respect the active slice and clear all bytes after content within it. No
alias, concurrent writer, retained provider write, or caller mutation may
invalidate the clean backing. Handshake/alert handling is represented by its
net full-clear effect and CCS by its unchanged effect; the proof does not
verify those Rust branches or their orchestration. AEAD, Rust/provider memory
semantics, and compiler-level erasure remain trusted/unlinked obligations.

No production helper, retained translation, or differential corpus changed.
This is a cross-record memory invariant, not a formal refinement of the Rust
connection and not a measured or proved CPU speedup. It supplies the stronger
backing invariant deliberately absent from the preceding stage-one proof.

## Observable clearing of consumed public wire bytes

`Tls13/WireClearing.lean` adds **10 modeled theorems**. Main Lake build (31 jobs),
source guard, and combined axiom audit pass: **148 closures = 127 model + 21
linked**, standard foundations only. Its memory is a byte-indexed
function, reusing `PlainMemory` as a generic byte representation. A recursive
one-byte clear loop is modeled independently of declarative range fill.
Volatility and compiler erasure behavior are deliberately absent from both.

| Theorem (prefix `Tls13.`) | Checked result |
|---|---|
| `wireClearLoop_equals_fill` | Sequential byte clearing and bulk range filling produce equal functions at every byte index. |
| `publicWireDrain_bounds` | A partial drain consumes no more than requested and advances within the valid wire length. |
| `publicWireDrain_clears_consumed`, `publicWireDrain_preserves_other` | Consumed bytes become zero; the live suffix and every other byte are unchanged. |
| `publicWireDrain_zero` | A zero-length drain changes no byte. |
| `publicWireDrain_prefix`, `publicWireDrain_complete` | The already-zero consumed prefix stays zero and extends with each drain; completing the drain leaves the whole valid wire region zero. |
| `wireFill_changes_exactly` | Exactly the initially nonzero bytes in the consumed interval change their values. |
| `wireFill_minimal_changed_footprint` | Any result satisfying the same consumed-bytes-zero contract must change every byte changed by range fill. This is a pointwise minimum of changed support. |
| `wireFill_mandatory_footprint` | When consumed bytes initially are all nonzero, any operation meeting the contract must include every consumed byte in its write footprint. |

The lower bound does **not** demand stores to already-zero bytes. Neither
minimal changed support nor worst-case mandatory footprint proves minimum CPU
instructions, cycles, memory traffic, or secure erasure. Copying drained bytes
to their recipient must happen before clearing; that ordering and destination
behavior are Rust correspondence obligations. Ordinary fill and volatile
zeroization are equated only at the modeled observable-state level, not as
compiler-level operations.

Applying this result requires the cleared bytes to be classified as consumed
public wire storage rather than plaintext, key material, or retained secrets.
This classification, absence of aliases/concurrent mutation, actual Rust/LLVM
semantics, and the continued use of protected erasure for secret/error/Drop
paths remain external obligations. The engine is not linked by these proofs;
no production helper, retained translation, or differential corpus changed.

## Chunked secret clearing and aligned partitions

`Tls13/ChunkedZeroization.lean` adds **20 modeled theorems**. Main Lake build
(33 jobs), source guard, and combined axiom audit passed for **168 closures =
147 model + 21 linked**, standard foundations only. It models in-place
clearing of adjacent chunks, with arbitrary byte values and no secret copying.
That abstract description does not prove the Rust library avoids copies or
implements volatile stores; those remain separate implementation obligations.

| Theorem (prefix `Tls13.`) | Checked result |
|---|---|
| `clearAdjacent_ranges`, `clearPlainChunks_equals_range` | Sequential clearing of adjacent ranges equals one clear over their total length. |
| `zeroizeChunk_partition`, `zeroizeChunk_decomposition` | Full-width blocks and the optional remainder cover exactly the input; all emitted chunks are positive and width-bounded for positive width. |
| `zeroizeChunk_endpoints_fit`, `zeroizeChunk_machine_bounds` | Every cumulative partition endpoint, full-block product, final offset, and count fits a machine maximum when the requested range does. No overflowing ceiling-addition expression is used. |
| `zeroizeChunk_count_minimal` | For fixed positive width, the full-block/remainder partition has minimum number of width-bounded chunks covering the same length. |
| `chunkedZeroization_equals_range`, `chunkedZeroization_zero`, `chunkedZeroization_inside`, `chunkedZeroization_outside` | Chunked clearing has exactly the original range's effect, including empty input and unchanged outside bytes. |
| `chunkedZeroization_read_clean`, `chunkedPlainReads_agree`, `chunkedPlainReads_complete_zero` | Partial/zero reads with chunked clearing preserve the original invariant; arbitrary read traces agree with the existing model and complete to a zero loan. |
| `alignedClearParts_sum`, `alignedClear_equals_range`, `alignedClear_machine_bounds`, `alignedClear_read_clean` | An arbitrary byte head, fixed-width middle, and byte tail are sufficient under exact coverage: same clear effect, bounded arithmetic, and preserved read invariant. No maximal middle is assumed. |
| `alignedClear_maximal_decomposition`, `alignedClear_maximal_count_minimal` | Only with positive width and tail<width does the fixed-head remainder equal quotient/remainder decomposition and minimize the number of remaining width-bounded chunks. |

The aligned API may legally return a nonmaximal middle. Its general safety
proof uses only exact coverage and disjoint adjacent range effects. Alignment
of machine addresses, bytemuck slice validity, lack of additional secret copies,
volatile word versus byte stores, barriers, CPU lowering, Rust/LLVM semantics,
and compiler-resistant erasure are **not** proved by this model. Applying it to
secret storage still requires each head/middle/tail operation to use the trusted
secret-zeroization primitive. The public-wire fill result does not supply that
obligation. Zero width is not a valid implementation configuration; bounded
partition/minimality theorems explicitly require positive width.

Minimum chunk count is not a minimum of byte/word stores, barriers, cache
traffic, CPU time, or all possible widths and alignments. The conditional
aligned theorem keeps the head fixed and counts each nonempty remaining chunk
once, excluding the actual byte-tail routine's internal costs. No helper was
translated and the endpoint remains unrefined; six linked functions and 4,923
numeric differential cases are unchanged.

### Reassembler Drop uses the same maintained aligned clearing

`tls-core::handshake::Reassembler::drop` now passes its entire caller scratch
loan through `bytemuck::pod_align_to_mut::<u8, u128>` and invokes maintained
`zeroize` on all three returned slices. The core dependency pins bytemuck
1.25.2 with default features disabled. Constructor behavior and failure/message
consumption clearing are unchanged. Constructor storage can contain arbitrary
bytes, so the relevant model is `alignedClear_equals_range`, not an assumption
that unused scratch is already clean. The caller loan must be cleared in full,
including storage beyond the configured message cap.

The pinned six-helper extraction was regenerated after this source change.
Generated `TlsCore.lean` is byte-identical; LLBC differs only in embedded
`handshake.rs` source text and its temporary output path. The manifest's source
hash was refreshed by extraction, not manually patched. Post-regeneration
standalone build (33 jobs), linked build (1728 jobs), all 168 theorem audits,
source/freshness checks, and all 4,923 Rust/Lean comparison cases passed. The linked handshake
claim remains `checked_handshake_total` arithmetic only. Neither Reassembler
Drop nor bytemuck/volatile erasure is translated or upgraded to linked/proved
status; the existing memory model and direct guarded Drop regression provide
separate scoped evidence. No global CPU-optimality claim follows.

## Scope and trust

The models do not prove X.509, identity matching, cryptographic primitives,
cryptographic collision resistance, full HRR message validation, implementation-level secret erasure, allocation bounds of the
full framer, constant-time execution, server/mTLS behavior, or complete TLS
conformance. Counter uniqueness is under sequential atomic state consumption;
key/nonce freshness and separation remain external obligations. Mathematical
bytes and naturals do not automatically prove Rust memory/slice semantics.

`verification/LEAN_DESIGN.md` defines the exact profile, numeric event codes,
argument domain, and cost-model exclusions. The translation experiment and
its toolchain assumptions are recorded separately by the coordinator.
