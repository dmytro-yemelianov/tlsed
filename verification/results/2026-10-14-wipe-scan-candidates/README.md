# Candidate measurements: inner scan and record wipes, 2026-10-14

Question: how much of the padded-record and corrupted-record cost measured in `2026-10-14-inner-scan-audit` do the candidate changes remove, and do they keep the tests green?

Three candidates, each applied to a copy of its crate, never to production:

1. **wipe** (`tls-core/src/protected.rs`). Erase caller bytes with aligned u128 stores (`bytemuck::pod_align_to_mut`, the pattern `Reassembler::drop` already uses). Applied to the two `fail` wipes and the tail wipe in `ProtectedReader::open`.
2. **scan** (`tls-core/src/protected.rs`). `last_nonzero` skips zero blocks from the end, then scans the last nonzero block bytewise. Same result as `iter().rposition(|&b| b != 0)`. Block size 64.
3. **awslc** (`tls-crypto-awslc/src/lib.rs`). The same aligned wipe for the ciphertext that `AwsLcKey::open_in_place` and `seal_in_place` erase on error. Both error paths get the same code, and the trait's "wipe on every error" contract is unchanged. This adds `bytemuck` to the provider crate; the workspace lock already pins it at `=1.25.2`.

Production is not modified. `crates/tls-core/src/protected.rs` still matches the Aeneas pin (sha256 `33b69fec…`).

## Method

- **Variants.** Six builds: `production_copy` (no edits), `wipe`, `scan`, `wipe_scan`, `awslc`, `wipe_scan_awslc`. Each is a copy of the crates with its edits applied. The diffs are in `variants/`. Each variant has its own `CARGO_TARGET_DIR`. Copies of one package share a metadata hash, so a shared target directory lets one variant reuse another's artifacts; see the bugs list below.
- **Kernels** (`candidate_kernels`): production expressions against candidates, isolated. Six repeats; each candidate is checked against production before timing.
- **End to end** (the audit's bench, 8 cases). Ten repeats. Every repeat runs all six variants, with the order rotated, so drift and background load fall on each variant about equally. Ratios are paired within a repeat. The load average is recorded for every run.
- **Noise floor.** The `long` case is untouched by every candidate, so its ratio shows the run's noise: 0.94–1.07 across variants and repeats.

Environment: Apple M5 (10 CPUs), macOS 27.2, rustc 1.98.1, **battery power** (as in the audit). Background load varied: an earlier end-to-end pass ran at a 1-minute load of about 8 (another process was using a full core), and the final passes ran at about 4.5. The final numbers come from the lower-load passes; the earlier pass gave the same ratios within 0.01.

## Bugs found in this pass and fixed

1. `candidates.py` counted failing tests with the wrong regex group (it summed the passed count). The return-code check still caught failures, but the reported count was wrong.
2. Reruns crashed: the results directories were created with `exist_ok=False`. Generated directories are now replaced on each run.
3. The end-to-end pass ran each variant's six repeats back to back. A variant was therefore confounded with machine state at its time slot. Repeats are now interleaved with rotating order, 10 repeats each.
4. The kernel repeats in the first pass ran under heavy background load, and their ranges were wide. They were rerun at lower load, and the load is recorded per repeat.
5. The audit README claimed, from reading the code, that a failed reader re-wipes its output on every later `open`. That is now measured (see Kernel results), and the audit README is updated.
6. Stale outputs from the earlier four-variant run were removed (`profile-wipe_scan-*`, `client-tests/wipe_scan.log`) and replaced by the full candidate's files.
7. Smaller cleanups: an unused constant, and an inline `__import__` replaced by a normal import.

Two earlier bugs, already fixed in the previous pass: the shared target directory, and a `vec!` in the `no_std` crate's new tests.

## Kernel results (6 repeats, median ns per op, load about 4.6)

| Input | Production | block 8 | block 16 | block 32 | block 64 |
|---|---:|---:|---:|---:|---:|
| scan, 1,023 zeros | 258.0 | 44.7 | 21.6 | 18.2 | 24.9 |
| scan, 4,095 zeros | 984.2 | 161.7 | 85.4 | 58.1 | 48.3 |
| scan, 16,383 zeros | 3,886.0 | 597.0 | 309.2 | 177.8 | **158.4** |

| Wipe | Production | aligned u128 |
|---|---:|---:|
| 17 B (a long record's tail) | 5.4 | 1.2 |
| 16,400 B (padmax tail) | 3,889.2 | 253.7 |
| 16,401 B (failed 16 KiB record) | 3,889.4 | 252.5 |

| Failed reader | ns per call |
|---|---:|
| `open` on a reader already in the failed state, 16,401 B output | 3,883.6 |

The failed-reader cost equals one 16,401 B wipe (3,889 ns). So the code-reading claim holds: every later `open` on a failed reader re-wipes the caller's output before returning `Failed`.

Block size: the audit targets maximum padding, so the choice is made on 16,383 zeros, where 64-byte blocks are fastest. At 1 KiB padding, 32-byte blocks are about 7 ns faster, an absolute difference that does not affect the conclusions.

## End-to-end results (10 interleaved repeats, median ns per record)

Ratio is variant ÷ `production_copy` in the same repeat, median over repeats.

| Case | production | wipe | scan | awslc | wipe + scan | wipe + scan + awslc |
|---|---:|---:|---:|---:|---:|---:|
| long: 16 KiB, no padding | 1,617 | 1.00x | 1.00x | 1.00x | 1.00x | 1.00x |
| padmax: 1 B + 16,383 zero pad | 9,569 | 0.62x | 0.60x | 1.00x | 0.22x | **0.22x** (2,106 ns) |
| inner_padmax: invalid type after 16,383 zeros | 9,587 | 0.61x | 0.60x | 0.99x | 0.22x | **0.22x** |
| pad4k | 2,668 | 0.63x | 0.62x | 1.00x | 0.28x | 0.28x |
| pad1k | 827 | 0.68x | 0.66x | 1.00x | 0.37x | 0.37x |
| tag_long: bad tag, 16 KiB | 9,912 | 0.62x | 0.99x | 0.62x | 0.62x | **0.25x** (2,486 ns) |
| tag_short | 84 | 0.98x | 1.00x | 0.98x | 0.97x | 0.95x |
| short | 60 | 1.01x | 1.00x | 1.01x | 1.00x | 1.00x |

Per-row ratio ranges across repeats are in `e2e/e2e-comparison.csv`. The two interleaved end-to-end passes agree: the full candidate's maximum-padding ratio was 0.216 and 0.217, and its bad-tag ratio was 0.252 and 0.250.

How the three candidates combine:

- Each candidate removes its own cost. Wipe removes the `fail` output wipe, and the awslc candidate removes the ciphertext wipe on error. Both lie on the bad-tag path, and together they take `tag_long` from 9.9 µs to 2.5 µs.
- Scan removes the bytewise scan, which only authenticated records reach. It leaves bad-tag records alone, because they fail in AEAD first.
- Long records, short records, and tag_short are unchanged within the noise floor.

## Profiles of the full candidate

`sample` output in `profile-wipe_scan_awslc-*.sample.txt`. Shares of total samples.

- **padmax:** AES-GCM 64%, wipe 14%, copy 12%, scan 9%. A maximum-padding record is now mostly crypto.
- **inner_padmax:** AES-GCM 61%, failure wipe 13%, copy 12%, scan 9%.
- **tag_long:** AES-GCM 52%. About 12% is a `memset` under AWS-LC's `EVP_AEAD_CTX_open`, which clears the output on tag failure. That is inside AWS-LC and unchanged. The failure wipe is 11%, the aligned ciphertext wipe 10%, and the copy 10%.

## Correctness

- **tls-core suite.** Production: 61 passing. `wipe`: 62. `scan`: 62. `wipe_scan`: 63. `awslc`: 61 in tls-core plus 23 in tls-crypto-awslc. Full candidate: 63 plus 23. Production's tls-crypto-awslc suite has 22 passing; the 23rd is the candidate's test. No failures in any variant.
- **Equivalence tests**, which exist only in the variants:
  - `candidate_equivalence::last_nonzero_matches_rposition`: all-zero inputs, every single-nonzero position for lengths up to 300 and sampled positions beyond, and random sparse patterns up to length 16,385.
  - `candidate_equivalence::wipe_zeroes_exact_range`: offsets 0–31 against sizes up to 16,385. The wiped range is exact, and nothing outside it changes.
  - `candidate_wipe::failed_seal_and_open_wipe_the_whole_buffer` (awslc): seal into a buffer too small for its plaintext, open a buffer shorter than a tag, and open a valid record with a flipped tag. Each failure must leave the whole buffer zero. Lengths 1 to 16,401.
- **tls-client suite** (`interop`, `faults`, `read_wiping`; an in-process rustls peer, no external tools). Production: 26 passing. Workspace copy with the full candidate's three crates swapped in: 26 passing. The build log confirms that `tls-core`, `tls-crypto-awslc`, and `tls-client` were compiled from the variant's paths.

## Not done, and what landing would involve

- **Production is unchanged.** Nothing is committed or pushed.
- **Aeneas pin.** The translation manifest pins `tls-core`'s `schedule.rs`, `lib.rs`, `handshake.rs`, `protected.rs`, `key_schedule.rs`, `client_policy.rs`, and the generated `TlsCore.lean`. Landing the `wipe` or `scan` candidates means retranslating with the pinned Charon/Aeneas toolchain (`verification/check_translation.py`) and updating the pin. The provider crate is not in the manifest, so the `awslc` candidate does not touch the extraction pin. The Lean proofs are not re-checked here.
- **Trust boundary.** `tls-crypto-awslc` is the provider adapter. The handover treats it as trusted, so changing its erasure code needs a review on its own, separate from the `tls-core` change. The candidate keeps the same semantics (the test covers each error path), and adds the `bytemuck` dependency.
- **Scan block size.** Fixed at 64 as above. Changing the block size later changes only one constant and needs the equivalence test rerun.

## Caveats

- Battery power, and background load varied between passes. The noise floor is shown by `long`.
- AES-128-GCM, receive side, single thread. ChaCha20 and x86-64 were not measured.
- Variant manifests replace workspace inheritance with literal values, so each variant builds standalone. `production_copy` is byte-identical to production. The `tls-client` check used the production manifest, plus the `bytemuck` line for the provider.
- The production `tls-client` run reused a cached build of the unchanged tree.

## Files

- `kernels/`: six repeats, `kernels.csv` (median, min, max, ns per byte), and the load per repeat in `manifest.json`.
- `e2e/`: per-variant repeats and `e2e-comparison.csv`.
- `variants/`: unified diffs of each variant against production (`*-protected.diff`, `*-tls-crypto-awslc-lib.diff`).
- `tests/`: test logs per variant and crate (`<variant>-tls-core.log`, `<variant>-tls-crypto-awslc.log`), plus `production-tls-crypto-awslc.log`.
- `client-tests/`: tls-client logs, production and full candidate.
- `profile-wipe_scan_awslc-*.sample.txt`: `sample` output for the full candidate.
- `manifest.json`: binary and source hashes, commands, host, and loads.
