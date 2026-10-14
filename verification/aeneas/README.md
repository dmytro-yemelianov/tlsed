# Linked production arithmetic and type-guard proofs

This separate Lake project uses Lean 4.31.0 because that is the pinned Aeneas
backend version. The standalone TLS model remains on Lean 4.34.1. The
segmentation specification is compiled from the same `../../lean` source in
this project's own build directory; it is not a hand-maintained copy.

## Reproduce retained evidence

From the repository root:

```sh
python3 verification/check_translation.py
python3 verification/aeneas/bootstrap_dependencies.py
cd verification/aeneas
lake exe cache get
lake build
```

The bootstrap uses locked git revisions and shallow fetches. It is useful when
full-history GitHub clones fail. `lake exe cache get` obtains mathlib build
artifacts for the locked version; Lake then builds/checks the proof and Aeneas
backend. `Proof.lean`, `ReassemblyProof.lean`, `ProtectedProof.lean`,
`KeyScheduleProof.lean` and `ClientProof.lean` print twenty-one
theorem dependency audits during checking. `python3 verification/check_axioms.py`
from the root enforces standard-only foundational assumptions across all 168
model/linked theorem audits and retains the complete dependency report.
Warnings are errors for this project's proof/model/generated files.

## Regenerate from production Rust

Build or install the compatible upstream tools following the
[pinned Aeneas instructions](https://github.com/AeneasVerif/aeneas/blob/557eff83ecef5083b98a52a94ca7fae63d6c1dab/README.md):

| Component | Pin |
|---|---|
| Aeneas | `557eff83ecef5083b98a52a94ca7fae63d6c1dab` |
| Charon | `c8f15d7d658c86a95658f71ad99cddd4be002e04` |
| Extraction Rust | `nightly-2026-09-17` |
| Proof Lean | `v4.31.0` |
| mathlib | `fabf563a7c95a166b8d7b6efca11c8b4dc9d911f` |

Point `CHARON_BIN` and `AENEAS_BIN` at those binaries, then run from the root:

```sh
python3 verification/check_translation.py --regenerate
cd verification/aeneas
lake build
```

The script verifies the reported tool commits and Charon Rust version, extracts
the six selected production helpers and reachable definitions into a fresh temporary
target directory, retains LLBC/Lean output, and writes SHA256 source/artifact
evidence. Aeneas reports an eight-character commit prefix; that prefix is checked
against the full declared source pin. Tool provenance and translator soundness
remain trusted. Review regenerated changes; hash checks alone are not a proof.

## Exact claim

For all representable byte counts and positive capacities, the translated
production function succeeds without arithmetic overflow and returns the
minimum number of capacity-bounded records. The cost corollary minimizes
payload bytes plus fixed nonnegative overhead per record. Zero capacity returns
the intended error. Padding, flush latency, crypto CPU time, key boundaries and
varying capacities require other models. No global TLS performance optimum or
proof about the full record/handshake paths follows from this result. Additional
linked theorems check exact handshake-total, inner-length and content-type guard
correspondence, including rejected lengths and checked-add overflow paths.
The linked HKDF-label size helper also returns the exact minimum mandatory-format
footprint within uint16/u8 field bounds. Encoder writes and crypto calls remain
outside that refinement proof.

The sixth helper, `client_policy::client_phase_next`, has exact Option/model
agreement for every u8/Boolean input, including unverified-event rejection,
terminal failure and duplicate HRR. Its five linked theorems prove the scalar
transition function. Actual crypto verification evidence, retry-flag writes,
ClientFinished output handoff and application release remain outside that
refinement. Accepted-flight and single-HRR trace implications are model results
under the documented wiring assumptions; native client interop tests provide
separate implementation evidence.
