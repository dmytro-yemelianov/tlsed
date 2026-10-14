# Landed production versus pre-landing build, 2026-10-14

Paired timing of the production build with the landed changes against the build from before the landing: `protected.rs` (aligned wipes and block-skip scan) and `tls-crypto-awslc` (aligned erasure on error paths). The pre-landing binary is the `production_copy` variant from `2026-10-14-wipe-scan-candidates`.

- **Method:** `landed_check.py`. Six repeats; the two binaries alternate order by repeat. Median per case, with the per-repeat ratio range. Nothing builds during timing, and the load average is recorded per run.
- **Environment:** Apple M5, AC power, 1-minute load about 4.9 at start.

## Result (landed / pre-landing; below 1 means faster)

| Case | Pre-landing, ns | Landed, ns | Ratio | Range |
|---|---:|---:|---:|---|
| 1 B + 16,383 zero padding | 9,896 | 2,177 | 0.216 | 0.213–0.234 |
| 1 B + 4,095 zero padding | 2,749 | 801 | 0.286 | 0.282–0.306 |
| 1 B + 1,023 zero padding | 860 | 325 | 0.374 | 0.365–0.393 |
| Bad tag, 16 KiB | 10,177 | 2,585 | 0.249 | 0.246–0.269 |
| 16 KiB, no padding | 1,685 | 1,705 | 0.997 | 0.989–1.067 |
| 1 B, no padding | 65 | 64 | 0.975 | 0.938–1.027 |
| Bad tag, 1 B | 87 | 84 | 0.948 | 0.934–1.015 |

Records that the changes don't touch are within the noise. The changes affect only padded and failing records.

## Files

- `comparison.csv`, raw per-repeat CSVs, `run.json` (argv, loads, binary and source hashes).
