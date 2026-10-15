# Server-to-client 16 KiB, x86: investigation, 2026-10-15

## Result

On x86, the server-to-client 16 KiB ratio (TLSed ÷ rustls) depends on the runner's CPU, and rustls is the side that gets slower. The extra cost is memory copying, not AES-GCM and not process mode. The copy-time gap is measured on one runner (EPYC 7763), and the signature matches on the other slow runners, but those runners were not profiled.

| Run | CPU | Combined, TLSed ÷ rustls | Separate processes | Per record, combined (TLSed / rustls, ns) |
|---|---|---:|---:|---|
| `38702456224` | EPYC 9V74 | 0.560 | not run | 5,375 / 9,604 |
| `38709562536` | EPYC 9V74 | 0.558 (0.557–0.562) | not run | 5,363 / 9,631 |
| `38710051326` | EPYC 7763 | 0.697 | 0.685 (10,962 / 15,989) | 11,121 / 16,010 |
| `38708921581` | EPYC 9V45 | 0.991 (0.961–0.993) | 1.02 (2,719 / 2,667) | 2,721 / 2,816 |

Ratios in the combined column are the median of per-repeat ratios from `comparison.csv`. Per-record values are the medians from the same file, divided by 128 records per sample.

Other sources: macOS (Apple M5) gives 0.86–0.90 in four configurations, and Linux arm64 in Docker gives 1.04 in separate processes.

**Correction.** Earlier versions of this file, and a comment on the x86 results, said the 0.56 did not reproduce. That was premature: it reproduced on both EPYC 9V74 runs. The 0.99 comes from a different CPU, which is the fast one.

## Mechanism, measured on EPYC 7763 (run `38710051326`)

Perf over the same workload (`x86-zen3-slow/perf-breakdown.txt`, task-clock samples):

| | TLSed | rustls | Gap |
|---|---:|---:|---:|
| AES-GCM (`_aesni_ctr32_ghash_6x`) | 423.6 ms | 427.9 ms | 4.3 ms |
| `memmove`/`memcpy` | 94.0 ms | 413.8 ms | **319.8 ms** |
| Total | 627.3 ms | 946.6 ms | 319.3 ms |

The whole CPU-time gap is in `memmove`. AES-GCM does the same work for both clients (within 1%).

Copy calls per bulk record, from callgrind on the same run, excluding entropy copies that both clients share:

- **rustls:** its client read path makes about 9 copy calls per record, `Cursor::read` into the deframer buffer about 5.0 and `DeframerVecBuffer::discard` about 4.0.
- **TLSed:** no copies are attributed inside its own code. The counted copies are in the harness `Client::step` (about 3.1 per record, which includes the inlined TLSed call), and in the shared outbound and harness write paths (about 1 each).

The counts do not say how many bytes move, or whether each copy costs more, so this file does not separate those two. The copy calls are the code-level evidence that rustls's read path copies more; the time breakdown is the evidence that the copies account for the gap.

On the EPYC 9V45 runner, `memmove` was about 21% of time for TLSed and 19% for rustls, so copies were cheap there, and the two clients were at parity. The copy cost therefore depends on the host, and rustls's extra copies are where it shows.

The slow 9V74 runners show the same signature: rustls about 4–5 µs slower per record, with TLSed's and rustls's AES work unchanged. They were not profiled, so their copy-time share is an inference.

## What was ruled out

- **Instruction count.** Callgrind gives 692.1M instructions for TLSed and 672.3M for rustls on EPYC 7763, and 696.6M and 677.1M on EPYC 9V45. Rustls does not execute more instructions.
- **Simulated cache misses.** Cachegrind on Linux arm64, same binary: TLSed has 5.0M L1 misses and 140k last-level misses, rustls 4.7M and 119k. Rustls does not miss more.
- **System calls.** `strace` over the whole run: rustls makes 13 `mmap` and 7 `munmap` calls in total, not per record. TLSed makes 40 `futex` and 5 `getrandom`. No per-record syscalls on either side.
- **Minor page faults.** On EPYC 7763: 141–143 for TLSed and 151–152 for rustls per run. On EPYC 9V45: 147 and 154. On Linux arm64: 137 and 145. These are too few to matter.
- **Process mode.** Separate and combined runs agree on EPYC 9V45 (1.02 and 0.99) and EPYC 7763 (0.685 and 0.697), and on macOS.

## Open questions

- Do rustls's copies move more bytes than TLSed's, or does each copy cost more? A size-instrumented run would separate these.
- The `--fragment` option changes the chunk size rustls's deframer sees. If `DeframerVecBuffer::discard` moves whole records, varying it should change rustls's copy time. This has not been run.
- Why the same copy costs more on the EPYC 7763 and 9V74 runners than on the 9V45 runner. Memory bandwidth and cache state on the host are plausible, but nothing here measures them.
- Profiles of the EPYC 9V74 slow runners, to confirm the copy signature there directly.

## Other findings

- **Padded-record baseline (Linux arm64).** The pre-landing scan and tail wipe, reconstructed from `verification/experiments/inner-scan-audit/baseline/prelanding.diff`, give padded records at 0.27× the current cost (padmax 10,737 → 2,878 ns, inner_padmax 0.271, tag_long 0.304, pad4k 0.330, pad1k 0.419). Long records are unchanged at 1.00. The macOS landed-check gave 0.215 for padmax.
- **Padded-record baseline (x86, EPYC 9V74, run `38709562536`):** padmax 0.310, inner_padmax 0.318, tag_long 0.454, pad4k 0.417, pad1k 0.567 of the pre-landing cost. Long records are unchanged at 1.02. Raw data in `x86-baseline/`.
- **Harness change.** `client_compare --impl tlsed|rustls` runs one client per process, and it prints minor faults per run on Linux. The combined default is unchanged.

## Caveats

- Four x86 runs on three CPU models. The runners are allocated at random, and each run takes about 12 minutes, so the sample is small.
- Perf uses task-clock, a software event, because the runners do not expose hardware counters. The shares are sampled, and the event totals are per process, including handshakes.
- Callgrind counts are per process and include the shared harness work. They give copy-call counts per record, not bytes.
- The raw `perf.data` and callgrind files are not committed. Text reports are.

## Files

- `x86-zen3-slow/`: EPYC 7763 run: bench output, per-client timings, perf and callgrind reports, `perf-breakdown.txt`.
- `x86-deep-dive/`: EPYC 9V45 run: per-client timings, minor faults, perf and callgrind reports.
- `x86-same-machine-combined/`: the combined `bench-x86` output from the EPYC 9V45 run (`38708921581`).
- `x86-baseline/`: EPYC 9V74 run (`38709562536`): pre-landing and current padded records, combined primary comparison.
- `mac-process-check/`: macOS combined and separate runs, three repeats each.
- `linux-arm64/`: separate-process runs, the padded-record baseline check, cachegrind summaries and strace counts.
