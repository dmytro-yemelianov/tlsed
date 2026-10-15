# Extractable inner scan: kernel and end-to-end timing, 2026-10-15

Question: the landed `protected::last_nonzero` uses slice equality and an iterator adaptor, which Aeneas does not extract. Does the rewritten form (an OR reduction over each 64-byte sub-slice, index loops only) keep the landed speed?

Answer: yes. End to end, the rewrite matches the landed build within noise on every padded case, and on the unpadded cases it is unchanged.

## What was measured

- **Kernel** (`candidate_kernels`, `kernels/`): the scan variants alone, on inputs of 0, 1,023, 4,095, and 16,383 zero bytes after a valid type byte. Each variant is checked against the pre-landing `rposition` before timing. Pooled median over 6 repeats × 60 samples, ns per call.
- **End to end** (`tlsed-inner-scan-audit bench`, `e2e/`): the committed tree against the pre-landing build, 6 fresh-process repeats, order alternating by repeat. Ratios are computed per repeat, then the median is taken.

Environment: Apple M5, macOS 27.2, rustc 1.98.1, AC power. The 1-minute load was 3–4.5 during the runs (`e2e/load.txt`). Hashes are in `manifest.json`.

## Kernel results (ns per call)

| Variant | Form | 1,023 zeros | 4,095 zeros | 16,383 zeros |
|---|---|---:|---:|---:|
| production (pre-landing) | `rposition` | 249.7 | 947.2 | 3,733.2 |
| x_or | OR reduction, whole-block index loop | 125.0 | 416.5 | 1,588.2 |
| **x_sub** (committed) | OR reduction over a 64-byte sub-slice | **24.6** | **48.4** | **169.8** |
| x_exit | early-exit index loop | 265.8 | 1,033.5 | 4,095.8 |
| x_bytewise | bytewise scan only | 247.6 | 943.9 | 3,722.1 |
| block64 (landed) | slice equality | 26.8 | 47.3 | 152.5 |

Notes:

- `x_sub` is the committed form. Against the landed slice-equality version it is about 11% slower at 16,383 zeros (170 vs 153 ns) and equal at smaller sizes. The scan was about 9% of a padmax record in the earlier profile (`2026-10-14-wipe-scan-candidates`), so 11% of that is about 1% of the record. That is below the end-to-end noise floor (see below).
- The shape of the block test matters. The same OR reduction over the whole block (`x_or`) is 9× slower than over a sub-slice (`x_sub`) at 16,383 zeros. The likely cause is that the sub-slice lets the compiler drop per-byte bounds checks and vectorize; this is not verified in the assembly. The early-exit form (`x_exit`) does not vectorize and is no faster than bytewise.
- The kernel harness is standalone: it has its own copies of each variant, so the production edit does not change these numbers. The only production-linked row is `failed_reopen_16401`, which never reaches the scan.

## End-to-end results (paired, median over 6 repeats)

Ratio is extractable ÷ pre-landing, per repeat, median over repeats. Ranges are the min–max over the 6 repeats.

| Case | Pre-landing ns | Extractable ns | Ratio | Range |
|---|---:|---:|---:|---|
| padmax: 1 B + 16,383 zero pad | 9,443 | 2,052 | 0.215 | 0.212–0.228 |
| inner_padmax: invalid type after 16,383 zeros | 9,450 | 2,070 | 0.217 | 0.212–0.229 |
| pad4k | 2,638 | 724 | 0.274 | 0.264–0.331 |
| pad1k | 812 | 299 | 0.366 | 0.358–0.392 |
| tag_long: bad tag, 16 KiB | 9,709 | 2,466 | 0.254 | 0.223–0.262 |
| long: 16 KiB, no padding | 1,604 | 1,618 | 1.009 | 0.995–1.080 |
| short: 1 B | 59 | 61 | 0.996 | 0.873–1.111 |
| tag_short | 83 | 81 | 0.960 | 0.956–1.003 |

Read against the earlier landed-check (`2026-10-14-landed-check`, the landed build before this rewrite): padmax was 0.216 there and is 0.215 now; inner_padmax 0.218 → 0.217; pad4k 0.286 → 0.274; pad1k 0.374 → 0.366. tag_long moved from 0.249 to 0.254. That path never reaches the scan (the bad tag fails in AEAD first), so the difference is run-to-run noise. The `long` and `short` rows are unchanged within their noise.

## Limits

- One machine, one session, AC power. Use the ratios, not the absolute values.
- The kernel run (10:32) used the harness as committed. Two doc comments in `candidate_kernels.rs` were reworded after that run; no code changed.
- The end-to-end pre-landing binary is the `production_copy` variant built on 2026-10-14. The extractable binary was built from the committed tree (`ff33eab`).
- This shows speed only. The Lean loop proofs for `last_nonzero`, `block_is_zero`, and `last_nonzero_below` are not written yet, so the Aeneas pin covers the extracted code but does not yet prove it.
- AES-128-GCM and the receive side only. x86-64 is not measured here; see `bench-x86.yml`.

## Files

- `kernels/repeat-*.csv`: raw kernel samples; `kernels/kernels.csv`: pooled medians, min, max.
- `e2e/pre_landing-repeat-*.csv`, `e2e/now-repeat-*.csv`: raw bench output per repeat; `e2e/comparison.csv`: the table above; `e2e/load.txt`: uptime before each run.
- `manifest.json`: host, binary and source hashes, order.
