# Aligned volatile secret wiping — implemented and measured

The remaining large-record receive hotspot is fixed while retaining secret
zeroization. AES128/X25519 16KiB receive improves **1.853x** against the prior
[public-wire optimized engine](WIRE_CLEARING.md) and now takes **0.835x native
rustls endpoint-pair time** in this local workload.1KiB receive improves1.528x;
connection lifecycle improves1.227x and remains1.119x native time. These are
separate paired measurements, not cumulative gains multiplied across experiments.

## Implementation and security contract

Private `zeroize_secret(&mut [u8])` uses pinned bytemuck1.25.2's safe
`pod_align_to_mut::<u8,u128>` to obtain disjoint byte head, aligned word middle
and byte tail. It calls pinned zeroize1.9.1 on all three. u8/u128 permit every
bitpattern and have no padding; the zero u128 representation has sixteen zero
bytes on either endian. The view allocates nothing and does not read or copy
secret values. Empty/small/unaligned slices work even if the library returns a
nonmaximal middle, because the byte edges still cover all remaining memory.

The word path delegates to zeroize's existing slice implementation, which writes
zero u128 values with volatile stores. This preserves compiler-resistant wiping;
ordinary `fill` or a custom assembly/barrier replacement is not used for secrets.
Volatile granularity changes; no atomic128-bit store promise is made. Workspace
`unsafe_code = forbid` remains, with no new own unsafe. The maintained bytemuck
view adds a trusted dependency boundary alongside zeroize and the compiler.
[Safe view API](https://docs.rs/bytemuck/latest/bytemuck/fn.pod_align_to_mut.html)
and [zeroize maintainer explanation](https://github.com/RustCrypto/utils/pull/1535)
support these boundaries; [exact pinned dependency snapshots/hashes](../crates/tls-bench/results/2026-10-14-chunked-wipe/dependency-sources.json)
identify the source actually built.

Every client byte-slice wipe uses this helper: constructor record/plaintext/output
loans, consumed application plaintext, completed handshake/control cleanup,
receive/processing failures, abort and those three loans on Drop. Byte effects,
accepted full capacities and call ordering are unchanged. Typed secrets/stack
arrays remain on their existing zeroize paths. Core reassembler/provider cleanup
is unchanged; its large handshake-loan wipe is a remaining lifecycle target.
The two successful public-wire fills from the previous change remain separate.
Authentication, PKI, nonce/key limits, admission gates and read APIs are unchanged.

## Native evidence and measurements

The previous receive sample found805/1639 main-thread samples in our byte loop.
In the final production ARM64 disassembly, the aligned middle uses
`stp xzr,xzr,[pointer],#16` per iteration, with byte loops only for edges.
The2-second follow-up has99 main-thread leaf samples in the measure function
versus its former805, and encryption/decryption/copies dominate the sampled
stacks. Windows are independent, include shared server/transport work and are not
calibrated whole-run CPU percentages. Hardware lowering is inspected here,
not assumed portable. Diagnostic partial CSVs are deliberately terminated and
excluded from canonical summaries.
[Retained sample, disassembly and exact binary hash](../crates/tls-bench/results/2026-10-14-chunked-wipe/)
identify that diagnostic; its binary hash matches the final paired after binary.

Canonical timing keeps the identical benchmark harness on both versions and the
same authenticated server/strict native-client control in each process. Six
paired repeats alternate version and client order;100 samples per workload,
256 records per bulk batch, three profiles and36 successful processes produce
**64,800 observations**. No builds, fuzzing or Miri run during timing. Every
application record is authenticated and compared exactly.

Times are medians of process medians divided by256. Speedups/native ratios are
medians of six paired ratios, so separately aggregated time columns need not
produce exactly the same ratios. These are batch-average endpoint-pair costs,
not individual record latency or isolated client CPU.

| AES128/X25519 | Before µs/record | After µs/record | Native µs/record | Paired speedup (range) | After/native time |
|---|---:|---:|---:|---:|---:|
| Receive 64 B | 0.212 | 0.199 | 0.226 | 1.060x (0.963–1.098) | 0.877x |
| Receive 1 KiB | 0.698 | 0.458 | 0.489 | 1.528x (1.452–1.533) | 0.936x |
| Receive 16 KiB | 8.258 | 4.433 | 5.324 | 1.853x (1.814–1.901) | 0.834x |

Normalizing16KiB/1KiB gains by each native control gives1.858x/1.526x.64B receive
ranges cross parity, so no isolated tiny-record gain is claimed. AES128 transmit
is unchanged within pair variation and takes1.029x native16KiB time.
Reused/fresh handshake speedups are1.173x/1.159x (normalized1.129x/1.138x) and
after/native ratios0.988x/0.986x: local median parity, not portable superiority.

ChaCha20 16KiB receive improves1.220x (1.216–1.239), finishing0.949x native time.
With64B network fragments, AES12816KiB receive improves1.167x (1.162–1.193),
finishing0.838x native time; driver/Vec costs contribute to that workload.
Lifecycle remains slower: AES1281.119x, ChaCha1.123x and fragment profile1.118x.

Apple M5 ARM64/macOS27.2 on AC has no affinity, frequency or scheduler isolation.
Keep all raw tails: AES1281KiB receive pooled CV is46.72%; a native ChaCha reused
handshake group reaches358.93% due to long outliers. Pair ranges and medians
support the specific bulk/lifecycle improvements, without a blanket speed claim
across platforms, suites, resumption, roles or the unimplemented full-v1 matrix.

[Paired ratios](../crates/tls-bench/results/2026-10-14-chunked-wipe/paired/before-after.csv),
[commands/binary hashes](../crates/tls-bench/results/2026-10-14-chunked-wipe/paired/run.json),
[before source hashes](../crates/tls-bench/results/2026-10-14-chunked-wipe/before-source-hashes.sha256),
[after source/proof hashes](../crates/tls-bench/results/2026-10-14-chunked-wipe/after-source-hashes.sha256)
and [host controls](../crates/tls-bench/results/2026-10-14-chunked-wipe/environment.txt)
identify the experiment. Changed historical manifest paths refer to byte-identical
archived source/lock/proof snapshots. Before and after binaries remain locally in
ignored target storage; reproducible source snapshots and hashes are retained.

## Verification

[ChunkedZeroization.lean](../lean/Tls13/ChunkedZeroization.lean) adds20 standalone
proofs: adjacent/chunk clearing equals one exact range clear, coverage and
representable endpoints/products hold, outside bytes are unchanged, and zero/
partial/arbitrary completed reads preserve the clean-loan invariant. Arbitrary
head/word-middle/tail equivalence requires exact coverage and **no maximal-middle
assumption**. Conditional minimum chunk count after a fixed head additionally
requires positive width and tail<width. That is a stated partition-cost result,
not an optimal choice of width/address alignment/CPU instructions or a linked
proof of Rust slice views/volatile erasure. Zeroize/bytemuck, representation,
compiler and noalias correspondence remain trusted. All **168 audited closures =
147 model +21 linked** use standard foundations only; the same six translated
production guards and their21 linked theorems are unchanged.

[Two new regressions](../crates/tls-client/src/secret_wiping_unit.rs) inspect2432
requested ranges across32 offsets, including empty/small/word-boundary and16KiB
sizes, with surrounding nonzero guards. Sixteen actual authenticated sessions
use varied loan starts and extra capacity, large-to-short records, partial/zero
reads, retained exact unread bytes, input backpressure and full accepted-loan
Drop wiping while outer storage stays untouched. Existing authentication-failure,
provider-fault, HRR/KeyUpdate and wire/nonce/alert tests remain passing.

[Miri evidence](../verification/results/2026-10-14-chunked-wipe/miri-checks.json)
checks2304 guarded ranges each on aarch64-apple-darwin,32-bit i686-unknown-linux-gnu
and big-endian powerpc64-unknown-linux-gnu. It executes an exact, hash-guarded copy
of the production helper body in an isolated dependency-only crate to avoid native
provider FFI. This validates the copied helper's memory behavior, not whole-engine
cross-platform interop or machine-code erasure. The retained source, Cargo manifest/
lock and [body hash/scope](../verification/results/2026-10-14-chunked-wipe/miri-helper-source.json)
allow reproducing that probe without a stand-in implementation.

[Final checks](../verification/results/2026-10-14-chunked-wipe/checks.json) pass114
Rust unit/integration tests,14 compile-fail doctests,26 client tests in release,
formatting, strict Clippy, proof source guard, translation freshness and4,923
Rust/Lean cases across ten unchanged operations. The fresh
[Rust-ASan campaign](../fuzz/results/2026-10-14-chunked-wipe/README.md) passes
23,054 executions in16 seconds; native C/assembly coverage remains unestablished.
External audit, full endpoint refinement and server/mTLS/OpenSSL/full-v1 gates
remain open. Remaining lifecycle and native deframer/alternative-issuer PKI
experiments are scoped in [the source review](SOURCE_COMPARISON.md).
