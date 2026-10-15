# Server-to-client 16 KiB, x86: investigation, 2026-10-15

## Result

The x86 ratio for server-to-client 16 KiB (TLSed ÷ rustls) depends on the runner. It is not a fixed property of the clients.

- **Slow runners** (runs `38702456224` and `38709562536`): the combined run gives **0.56** (ranges 0.55–0.59 and 0.557–0.562). TLSed takes about 5.4 µs per 16 KiB record and rustls about 9.6 µs. The padded-record `long` case, which is TLSed's open alone, takes 2.2–2.3 µs.
- **Fast runner** (run `38708921581`): the combined run gives **0.97–0.99**, and separate processes give **1.02**. TLSed takes 2.7 µs per record and rustls 2.8 µs. TLSed's open takes 1.24 µs.

Between the slow and fast runners, TLSed's combined cost changes by about 2× (1.8× for the open alone) and rustls's by about 3.4×. So on the slow runners rustls costs about 4.2 µs more per record than TLSed, and on the fast runner about 0.1 µs more.

**Correction.** An earlier version of this file, and a comment on the x86 results, said the 0.56 did not reproduce. That was premature: it reproduced on two of the three x86 runs. The conclusion that it is a runner effect still holds, because the fast runner gives parity. The cause is not established.

## Evidence

| Run | Runner state | Combined, TLSed ÷ rustls, s→c 16 KiB | Separate processes | TLSed open (`long`, ns) | Per record, combined (TLSed / rustls, ns) |
|---|---|---:|---:|---:|---|
| `38702456224` | slow | 0.560 | not run | 2,274 | 5,375 / 9,604 |
| `38708921581` | fast | 0.991 (0.961–0.993 per repeat) | 1.02 | 1,236 | 2,721 / 2,816 |
| `38709562536` | slow | 0.558 (0.557–0.562) | not run | 2,231 | 5,363 / 9,631 |

Ratios in the first and third columns are the median of per-repeat ratios, from `comparison.csv`. Per-record values are the medians from the same file, divided by 128 records per sample.

Other sources:

- **macOS (Apple M5)**, four configurations (combined, separate, both orders, full workload): 0.86–0.90 in every one. The process mode does not matter on macOS. See `mac-process-check/`.
- **Linux arm64 in Docker (glibc 2.36)**, separate processes: 1.04 (5,914 vs 5,664 ns per record). See `linux-arm64/`.

The per-repeat ratios on the slow runners are very tight, so this is a stable effect on those machines, not noise.

## What the checks do and do not cover

Two checks were run only on the fast runner, so they say nothing about the slow state.

- **Separate versus combined processes.** On the fast runner, separate processes give the same ratio as the combined run (1.02 and 0.97–0.99). On macOS the process mode does not change the ratio. On the slow runners only the combined run was measured, so a process effect there is **not ruled out**.
- **Minor page faults.** On the fast runner the 100-sample timing run had 147 faults for TLSed and 154 for rustls, and the 400-sample perf run 145 and 156. On Linux arm64 the 40-sample run had 137 and 145. These counts are small, so per-record allocator faults do not occur in this setup. But the counts were not taken on the slow runners, so they are **not ruled out** there.

Two checks hold regardless of runner state:

- **Instruction count.** Callgrind over the same workload gives 696.6M instructions for TLSed and 677.1M for rustls, including shared harness work. Rustls does not execute more instructions. Since instruction counts do not depend on the machine, the slow-state gap must come from time per instruction, which points at memory or cache behaviour.
- **Profile shares.** On the fast runner, both clients are dominated by `aes_gcm` decrypt and encrypt and `memmove`, with similar shares (`x86-deep-dive/*-perf-report.txt`, `*-callgrind.txt`). The profile does not show what changes on a slow runner, because it was not taken there.

## Open questions

- What makes rustls's per-record path slower on the slow runners, when it executes no more instructions? Memory bandwidth or cache contention from other tenants is a plausible candidate, but nothing here tests it.
- Whether separate processes behave differently on the slow runners.
- Whether minor page faults differ on the slow runners.

Each of these needs a slow runner. The runners are allocated at random, so the next step is to dispatch the deep dive until one lands slow, and to read its faults and profile.

## Other findings

- **Padded-record baseline (Linux arm64).** The pre-landing scan and tail wipe, reconstructed from `verification/experiments/inner-scan-audit/baseline/prelanding.diff`, give padded records at 0.27× the current cost (padmax 10,737 → 2,878 ns, inner_padmax 0.271, tag_long 0.304, pad4k 0.330, pad1k 0.419). Long records are unchanged at 1.00. The macOS landed-check gave 0.215 for padmax.
- **Padded-record baseline (x86, run `38709562536`)**, from the same runner as the slow combined run: padmax 0.310, inner_padmax 0.318, tag_long 0.454, pad4k 0.417, pad1k 0.567 of the pre-landing cost. Long records are unchanged at 1.02. The raw numbers are in `x86-baseline/`.
- **Harness change.** `client_compare --impl tlsed|rustls` runs one client per process, and it prints minor faults per run on Linux. The combined default is unchanged.

## Caveats

- One fast and two slow runners. A larger sample would say how often each state occurs, but each run takes about 12 minutes and the states cannot be chosen.
- The deep-dive perf and callgrind runs are short (829 samples for rustls, 5 callgrind samples). They are good enough for shares, not for small differences.
- The raw `perf.data` and callgrind files are not committed. The text reports are.

## Files

- `x86-deep-dive/`: fast-runner per-client timings, minor faults, perf reports, callgrind annotations.
- `x86-same-machine-combined/`: the combined `bench-x86` output from the fast runner (`38708921581`).
- `x86-baseline/`: the slow runner from `38709562536`: pre-landing and current padded records, combined primary comparison.
- `mac-process-check/`: macOS combined and separate runs, three repeats each.
- `linux-arm64/`: Linux arm64 separate-process runs and the padded-record baseline check.
