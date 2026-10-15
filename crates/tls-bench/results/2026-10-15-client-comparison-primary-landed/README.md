# Client comparison, primary profile, landed build, 2026-10-15

Question: after the landed erasure and scan changes, does the primary profile (AES-128-GCM, X25519, 16,645-byte fragments) still match the pre-landing result?

Answer: yes. Every row is within the run-to-run range of the pre-landing run (`2026-10-14-client-comparison-transport-fixed`).

## Setup

- `client_compare` against an identical rustls 0.23.45 server, shared strict `tls-pki` policy, authenticated client.
- 6 fresh-process repeats, 100 samples per workload, 256 bulk records per sample. Order alternates by repeat.
- Binary `client_compare` sha256 `2d90458c…`, built 2026-10-14 22:32 from the landed tree. This is the build before the extractable scan rewrite (`ff33eab`). The rewrite does not change unpadded records: both forms test the last 64 bytes, then return after one byte. The `long` row of the extractable-scan run (1.009 vs pre-landing) is the measured check.
- Controls, from `run.json`: no concurrent compilation or fuzzing; affinity and frequency isolation unavailable. Power source and host details are not recorded in `run.json`.

## Results (TLSed ÷ rustls, median over repeats; range in brackets)

| Workload | Direction | Bytes | Landed run (this) | Pre-landing run (2026-10-14) |
|---|---|---:|---|---|
| bulk | client → server | 64 | 0.866 [0.827, 0.932] | 0.901 [0.841, 1.002] |
| bulk | client → server | 1,024 | 0.909 [0.899, 0.940] | 0.942 [0.919, 0.975] |
| bulk | client → server | 16,384 | 1.017 [0.992, 1.042] | 1.019 [1.003, 1.028] |
| bulk | server → client | 64 | 0.882 [0.864, 0.912] | 0.906 [0.870, 0.957] |
| bulk | server → client | 1,024 | 0.936 [0.919, 0.970] | 0.950 [0.926, 0.993] |
| bulk | server → client | 16,384 | 0.884 [0.867, 0.905] | 0.862 [0.850, 0.867] |
| full handshake, fresh buffers | both | — | 0.993 [0.973, 1.021] | 1.025 [0.988, 1.089] |
| full handshake, reused buffers | both | — | 0.969 [0.958, 1.020] | 0.998 [0.957, 1.124] |
| connection lifecycle | both | — | 0.997 [0.976, 1.030] | 1.018 [0.967, 1.121] |

Reading: the handshake and lifecycle rows are at parity with rustls, as before. TLSed is somewhat faster than rustls on small and medium server-to-client bulk and on 16 KiB server-to-client, and at parity on 16 KiB client-to-server. The 16 KiB server-to-client row moved from 0.862 to 0.884 between the two runs, and the two ranges only touch at 0.867. Each run is a single session, so treat that as drift rather than an effect of the landing.

## Pki diagnostic (`pki/`)

`pki_compare` in the same session: strict `tls-pki` policy against the webpki native policy, on valid, invalid-signature, and wrong-name server identities, 600 samples each. `pki/summary.csv` has the means and percentiles. On valid chains the strict policy is about 3% slower than native in this run.

## Limits

- Single session, one machine. Ratios are useful; absolute values are not comparable across sessions.
- The primary profile does not exercise the padded or bad-tag paths that the landing changed; those are covered by `verification/results/2026-10-15-extractable-scan/`.
- Power source for this run is not recorded.

## Files

- `comparison.csv`: per workload and direction, median, min, max, and each repeat's ratio.
- `aes128-x25519/repeat-*.csv`, `summary.csv`: raw per-repeat data.
- `pki/`: `pki_compare` per repeat and summary.
- `run.json`: argv, binary hashes, order, controls.
