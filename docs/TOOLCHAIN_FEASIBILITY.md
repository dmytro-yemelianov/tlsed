# Aeneas / Charon feasibility

Investigation date2026-10-14, macOS ARM64. Neither binary was initially on PATH.
That is not proof of unavailability: existing native extraction tools were
found in another local project and Aeneas help/version runs successfully.

| Toolchain | Aeneas commit | Compatible Charon commit | Lean / Rust |
|---|---|---|---|
| Usable local candidate | 557eff83ecef5083b98a52a94ca7fae63d6c1dab | c8f15d7d658c86a95658f71ad99cddd4be002e04 | Lean4.31.0 / nightly2026-09-17 |
| Upstream HEAD surveyed | bbc0151747be4e3412ed7b113a0d4b170fba0de8 | b05c4774638599608f26b777b6bc49120446365a | Lean4.35.0-rc4 / nightly2026-09-17 |

The companion Charon commits come from each Aeneas charon-pin file; do not
independently select Charon HEAD. Main workspace Rust1.98.1 is separate from
Charon's rustc-private nightly. Do not silently repin the primary Lean project
to satisfy the extraction backend; isolate translation dependencies.

Local Aeneas binary:
`/Users/dmytro/github/DOOR-wt-m0-spike/spikes/m0-extraction/.toolchains/aeneas/bin/aeneas`
Local Charon binary:
`/Users/dmytro/.superset/worktrees/look/cuboid-run-175b4f38/.toolchains/extraction/aeneas/charon/charon/target/release/charon`
These machine-specific locations are discovery evidence, not portable build
instructions or vendored dependencies. Root coordinates actual translation,
artifact hashes and checked proof status in verification/PROOF_LEDGER.md.

[Upstream usage/build instructions](https://github.com/AeneasVerif/aeneas/blob/557eff83ecef5083b98a52a94ca7fae63d6c1dab/README.md)
require OCaml/OPAM and the compatible Charon checkout. A tiny standalone safe,
pure Rust crate is the first translation target:

```sh
# Inside that crate with compatible Charon on PATH:
charon cargo --preset=aeneas
# Use the output LLBC pathname actually emitted by Charon:
aeneas -backend lean -dest generated crate.llbc
# Add the matching Aeneas backends/lean package and Lean toolchain, then:
lake build
```

Successful translation alone is not a theorem relating Rust arithmetic to
our minimum-record-count specification. A checked refinement theorem about
the generated function, target integer width, success/error semantics and
capacity assumptions is required. Generated externals must have reviewed
models; no sorry or replacement axioms can stand in for production proofs.

The upstream tool covers a subset of safe Rust. Nested-loop outer control
flow, mutable references inside generic instantiations, concurrency and unsafe
remain limitations described by the pinned README. Socket I/O, C crypto,
external PKI and secret erasure stay outside this translation boundary. A
handwritten Lean model and executable differential traces remain useful while
translation/refinement work is incomplete, but are distinct assurance levels.

The current upstream release survey found Linux ARM64/x86_64 Aeneas binaries
and macOS ARM64 Charon. Docker ARM64 works locally; use pinned release digests
if a container route becomes needed. No expensive new upstream build was
necessary to discover the native candidate.
