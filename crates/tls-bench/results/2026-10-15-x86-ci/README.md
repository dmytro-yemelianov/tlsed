# x86 benchmarks in GitHub Actions, 2026-10-15

**Caveat on the server-to-client 16 KiB row.** The 0.56 below reproduces on both EPYC 9V74 runners. Other x86 runners give 0.70 (EPYC 7763) and 0.99 (EPYC 9V45). On the EPYC 7763 the gap is memory copying in rustls's read path, measured with perf and callgrind; see `../2026-10-15-server-to-client-investigation/README.md`. The other rows were checked on one or two runners only.

Question: do the macOS results (Apple M5) hold on x86-64, and does the padded-record cost fall as the landed erasure and scan predict?

Run: [`bench-x86` workflow, run 38702456224](https://github.com/dmytro-yemelianov/tlsed/actions/runs/38702456224), `workflow_dispatch` on `main` at `8dc154a` (the merge of PR #1). Runner: `ubuntu-24.04`, GitHub-hosted.

**Indicative only.** The host is a shared cloud VM, not a dedicated machine. The client comparison has 3 fresh-process repeats, and the padded bench is one process. Use the ratios and their repeat spread, not the absolute values. Nothing here is a throughput claim.

## Host (`host-lscpu.txt`)

AMD EPYC 9V74 (family 25, model 17), 4 vCPU (2 cores × 2 threads), Hyper-V guest, AVX-512 and AES-NI present, L3 32 MiB. Other tenants and host scheduling are outside our control.

## Client comparison: TLSed ÷ rustls (`client-comparison/`)

Primary profile (AES-128-GCM, X25519, 16,645 B fragments), median over 3 repeats, min–max in brackets. Ratio below 1 means TLSed is faster.

| Workload | Direction | Bytes | TLSed ÷ rustls | macOS, landed primary run |
|---|---|---:|---:|---:|
| bulk | client → server | 64 | 0.906 [0.898, 0.912] | 0.866 |
| bulk | client → server | 1,024 | 0.893 [0.857, 0.938] | 0.909 |
| bulk | client → server | 16,384 | 0.996 [0.959, 1.001] | 1.017 |
| bulk | server → client | 64 | 0.852 [0.844, 0.860] | 0.882 |
| bulk | server → client | 1,024 | 0.951 [0.943, 0.969] | 0.936 |
| bulk | server → client | 16,384 | **0.560 [0.551, 0.593]** | 0.884 |
| full handshake, fresh buffers | both | — | 0.994 [0.991, 0.996] | 0.993 |
| full handshake, reused buffers | both | — | 0.985 [0.979, 0.986] | 0.969 |
| connection lifecycle | both | — | 1.000 [0.997, 1.004] | 0.997 |

Fragment-64 (`client-comparison/aes128-x25519-fragment64/`): c → s 64 B 0.843, 1 KiB 0.705, 16 KiB 0.846; s → c 64 B 0.743, 1 KiB 0.646, 16 KiB 0.445. Handshake 0.993, lifecycle 1.004.

What holds: the handshake and lifecycle are at parity with rustls, as on macOS. Small bulk records (64 B and 1 KiB) are faster than rustls in both directions: 5–15% here, 6–13% on macOS.

What did not hold: **server → client at 16 KiB was 0.56 on this runner and 0.88 on macOS.** The three repeats agreed tightly (raw per-sample times in `client-comparison/aes128-x25519/repeat-*.csv`: TLSed about 0.68 ms per 128 records, rustls about 1.23 ms, in every repeat). The same measurement gives 0.56 on the second EPYC 9V74 runner, 0.70 on an EPYC 7763 runner, and 0.99 on an EPYC 9V45 runner. The investigation README has the evidence.

## Padded records: inner-scan audit (`padded-x86.csv`)

Median ns per record, 60 samples, current tree (`ff33eab` scan). The x86 run has no pre-landing build, so it gives no landed-vs-pre ratio; compare the within-run ratios to long records instead.

| Case | ns / record | ÷ long |
|---|---:|---:|
| short: 1 B | 159 | 0.07 |
| tag_short | 196 | 0.09 |
| pad1k: 1 B + 1,023 zeros | 499 | 0.22 |
| pad4k: 1 B + 4,095 zeros | 1,156 | 0.51 |
| long: 16 KiB, no padding | 2,274 | 1.00 |
| padmax: 1 B + 16,383 zeros | 2,802 | 1.23 |
| inner_padmax: invalid type after 16,383 zeros | 2,942 | 1.29 |
| tag_long: bad tag, 16 KiB | 3,308 | 1.46 |

Compare with macOS (`verification/results/2026-10-15-extractable-scan/`, landed build against the pre-landing build): on that machine padmax was 9,443 ns before the landing and 2,052 ns after, so padmax ÷ long went from 5.9 to 1.27. On x86 it is 1.23. On both machines the padded-record cost is now a small multiple of a long record, which is what the landing was meant to achieve. The machines differ in absolute terms, so this ratio is the only comparison to draw.

## Files

- `host-lscpu.txt`: `lscpu` from the runner.
- `padded-x86.csv`: raw bench output, all cases and samples.
- `client-comparison/comparison.csv`: the table above, plus per-repeat ratios.
- `client-comparison/aes128-x25519/`, `…-fragment64/`, `pki/`: raw per-repeat CSVs and stderr.
- `client-comparison/run.json`: argv, binary hashes, order, controls.
