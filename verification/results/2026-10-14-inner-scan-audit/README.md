# Inner-plaintext scan and wipe audit, 2026-10-14

Question: what do long, padded, and corrupted records cost in `ProtectedReader::open`, and how much of that is the inner scan (`decode_inner`), the tail wipe, or AEAD? Measurement only. No production code changed.

Harness: `verification/experiments/inner-scan-audit/` (`src/main.rs`, `run.py`). It calls the production `ProtectedReader::open` with AES-128-GCM via AWS-LC. The read buffer is the active prefix `record.len() - 5`, which is what `tls-client/src/lib.rs` passes (`plain[..record.len() - 5]`, around line 645). The kernels are verbatim copies of the `rposition` scan (`protected.rs:88`) and the tail wipe `output[content_len..].zeroize()` (`protected.rs:321`).

Environment: Apple M5, macOS 27.2, rustc 1.98.1, dependency versions pinned to the production `Cargo.lock`. **The machine was on battery power**, while the cpu-audit runs were on AC. Absolute numbers are not comparable with those runs. The within-run ratios and the decomposition are the usable part.

Run-to-run drift: a first run of the same code before rustfmt gave absolute values 3–5% lower (e.g. padmax 9,474 ns, long 1,608 ns). Ratios agreed within about 1%. The tables below are from the final run, whose `run.json` hashes match the source as recorded.

Method: 6 fresh-process repeats, 60 samples per case after 5 warm-ups, 512 records per batch. Cases and kernels rotate order each sample. Reader and key setup stays outside the timer. Every case is validated before timing.

## Per-record time (median of 6 repeats)

| Case | Wire bytes | ns / record | vs long | ratio range across repeats |
|---|---:|---:|---:|---|
| short: 1 B, no padding | 18 | 65 | 0.04x | 0.037–0.040 |
| tag_short: bad tag, 1 B | 18 | 88 | 0.05x | 0.052–0.054 |
| pad1k: 1 B + 1,023 zero pad | 1,041 | 866 | 0.51x | 0.508–0.518 |
| pad4k: 1 B + 4,095 zero pad | 4,113 | 2,754 | 1.62x | 1.615–1.632 |
| long: 16,384 B, no padding | 16,401 | 1,700 | 1.00x | — |
| padmax: 1 B + 16,383 zero pad | 16,401 | 9,969 | 5.87x | 5.840–6.018 |
| inner_padmax: authenticated, invalid type after 16,383 zeros | 16,401 | 10,040 | 5.92x | 5.860–5.976 |
| tag_long: bad tag, 16 KiB | 16,401 | 10,277 | 6.05x | 5.984–6.196 |

## Components (isolated kernels, same run)

| Component | Cost |
|---|---|
| inner scan, `rposition` over zeros | 0.25 ns/byte (16,383 zeros: 4,094 ns) |
| tail wipe, `zeroize` | 0.25 ns/byte (16,400 B: 4,101 ns; 17 B: 5.1 ns) |
| AEAD open of 16,401 B, copy included | 1,605 ns, of which copy 199 ns, so AEAD ≈ 1,405 ns (≈ 0.09 ns/byte) |
| AEAD open of 18 B, copy included | 56 ns, of which copy 2 ns |

**Decomposition.** padmax and long carry the same AEAD input (both 16,401 wire bytes), so their difference should equal scan(16,383) + wipe(16,400) − wipe(17). Predicted 7,982–8,216 ns per repeat. Measured 8,231–8,380 ns. Measured/predicted is 1.006–1.031 across the six repeats (`decomposition.csv`).

## Profiles

`sample <pid> 2 1` on a `loop` run, starting 1 s after launch. Shares are of total samples in each profile.

- **long:** AES-GCM decrypt 82%, copy (memmove) 16%, `open` self 0.6%.
- **padmax:** `decode_inner` 42%, `ProtectedReader::open` self 40%, AES-GCM 14%, copy 3%. The open-self share includes the tail wipe, which appears inlined into `open`. This is inferred from the decomposition: open-self is 0.6% for `long`, where the wipe is 17 bytes.
- **tag_long:** `AwsLcKey::open_in_place` self 41% (ciphertext wipe on the error path), `ProtectedReader::fail` output wipe 39%, AES-GCM 13%.
- **inner_padmax:** `fail` output wipe 41%, `decode_inner` 38%, AES-GCM 15%.

Raw sample files: `profile-{long,padmax,tag_long,inner_padmax}.sample.txt`.

## Reading

1. **Padding costs CPU per padding byte.** The scan and tail wipe together cost about 0.5 ns per padding byte, against about 0.09 ns per byte for AEAD. A 1-byte record with maximum padding costs about 5.9× a full 16 KiB record.
2. **Padding sits inside the AEAD.** Only a holder of the traffic key can send padded records, so this is a per-record throughput cost, not an unauthenticated amplification. Bad-tag records never reach `decode_inner`. They fail in AEAD first (`protected.rs:305-315`).
3. **Corrupted records cost two 16 KiB wipes.** The AWS-LC wrapper wipes the ciphertext on error, and `fail` wipes the output. AEAD is about 13% of the time. After a failure, every later `open` call on the same reader re-wipes the output buffer before returning `Failed` (`protected.rs:282-284`). Measured in `2026-10-14-wipe-scan-candidates` (`failed_reopen_16401`): 3,884 ns per call, equal to one 16,401 B wipe (3,889 ns).
4. **Both loops are byte-scalar.** The handshake `Drop` change replaced byte-wise erasure with aligned u128 erasure, measured in the cpu-audit primitive at 14.7 → 0.95 µs per 65,540 B. The tail wipe here is the same kind of loop, so the same treatment is a candidate. Measured in `2026-10-14-wipe-scan-candidates`: the aligned wipe is about 15× faster on 16 KiB, and a block-skipping scan (64-byte blocks) is about 25× faster at maximum padding, with equivalence tests. Neither is landed; see that README for what landing involves.

## Caveats

- Battery power, so absolute ns differ from the AC runs. Run-to-run drift of 3–5% is visible even within one power state.
- AES-128-GCM only, receive side, single thread. ChaCha20 not measured. x86-64 not measured.
- The `decode_inner` kernel is a copy of the expression. In the production build `decode_inner` is a separate symbol (see the padmax profile), so the copy is representative, not identical.
- Tail-wipe cost depends on the caller buffer. The client passes the active prefix. A caller that passes a larger buffer pays more on every record, including short ones. This audit covers the client convention only.

## Files

`comparison.csv` (medians, ratio ranges, per-repeat values), `decomposition.csv`, `repeat-0..5.csv` (raw samples), `profile-*.sample.txt`, `run.json` (argv, binary and source SHA-256, host, power source).
