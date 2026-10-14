# Experimental foundation fuzzing

Targets range from framing/model bookkeeping to real provider records, bounded
PKI and the experimental authenticated client. `fuzz` is an independent Cargo
workspace so libFuzzer/nightly instrumentation does not affect the stable core.
Its lockfile pins the fuzz dependencies. The library forbids unsafe code; the
external libFuzzer harness is trusted tooling.

From the repository root:

```sh
cargo install cargo-fuzz --version 0.13.1 --locked
rustup toolchain install nightly-2026-09-17 --profile minimal
cargo +nightly-2026-09-17 fuzz run record_parser -- -max_total_time=60
cargo +nightly-2026-09-17 fuzz run fragmented_records -- -max_total_time=60
cargo +nightly-2026-09-17 fuzz run auth_counter -- -max_total_time=60
```

On platforms where cargo-fuzz requires additional target/sanitizer support, use
an appropriate supported nightly/toolchain and record that exact toolchain with
results. Longer fuzzing and sanitizer/Miri runs remain security gates. Merely
building a target or running a short smoke campaign is not an audit.

Stable source/harness compilation (without claiming sanitizer coverage):

```sh
cargo check --manifest-path fuzz/Cargo.toml --locked --bins
```

Reproduce a discovered input with `cargo +nightly fuzz run TARGET PATH`. Keep
minimized regression inputs in `fuzz/corpus/TARGET` and add a deterministic Rust
regression for each fixed defect. Generated corpora/artifacts are ignored until
intentionally curated. Arbitrary fragmentation is checked against the borrowed
parser; successful ranges and buffering are bounded. Authentication events are
assertions in an abstract model, not verification of untrusted TLS messages.


The protected-record/reassembly milestone adds these pinned-toolchain smoke
commands (longer campaigns remain a gate):

```sh
cargo +nightly-2026-09-17 fuzz run handshake_reassembly -- -max_total_time=10 -max_len=4096
cargo +nightly-2026-09-17 fuzz run protected_records -- -max_total_time=10 -max_len=20000
```

`handshake_reassembly` checks exact transcript bytes across arbitrary physical
record splits and input/work fragmentation, coalescing, bounded copying,
retained-message backpressure, invalid u24 advertisements, and partial-message
control/epoch rejection. `protected_records` uses the real AWS-LC provider for
all three suites, constrained roundtrips, prefix/small-buffer retry, replay,
ciphertext/tag mutation, terminal wipe, and raw malformed record advertisements.
Deterministic test keys/IVs are recreated for independent harness cases; that
fixture pattern is not production usage or a global nonce/key-freshness proof.

Cargo-fuzz instruments the Rust path with ASan. Native provider C and assembly
are separate trusted dependencies: ordinary cargo-fuzz use does not establish
that those objects were rebuilt with sanitizer instrumentation. The retained
milestone results record the observed native-build flags/symbol checks; do not
infer complete native-backend sanitizer coverage from a passing campaign.

The `client_engine` target combines raw bounded input, codec/loan oracles and a
real maintained rustls server. It exercises three suites, two groups, HRR,
small/zero output, application bytes, automatic/requested KeyUpdate, mutations,
CCS and EOF/close handling. See [final client campaign evidence](results/2026-10-14-milestone4/README.md)
for exact sources, seeds and the native sanitizer boundary. Reproduce from a
fresh corpus directory:

```sh
mkdir -p fuzz/corpus/client_engine
cp fuzz/results/2026-10-14-milestone4/client-engine-seeds/seed-* fuzz/corpus/client_engine/
cargo +nightly-2026-09-17 fuzz run client_engine -- -max_total_time=10 -max_len=4096 -seed=71513
```

Short crash-free runs supplement protocol/ownership tests and independent
known-answer vectors. They do not prove security or cover the complete TLS
state space. Previous milestone logs identify historical sources; their counts
must not be presented as runs of changed current source.

The final optimized client has [fresh active-slice evidence](results/2026-10-14-active-slice/README.md)
with retained source hashes and15-second requested budget. The milestone4
client counts above describe the original pre-optimization code.

Latest client source evidence: [public-wire-clearing campaign](results/2026-10-14-wire-clearing/README.md)
passes14,546 Rust-ASan executions from a fresh retained seed corpus. Native
C/assembly sanitizer coverage remains unestablished; earlier campaigns retain
their historical source hashes.

Latest implementation: [aligned volatile secret-wipe campaign](results/2026-10-14-chunked-wipe/README.md)
passes23,054 Rust-ASan executions from fresh seeds, with native C/assembly
coverage still unestablished. Previous counts describe their retained source.
