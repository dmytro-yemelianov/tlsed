# Server-to-client 16 KiB, x86: investigation, 2026-10-15

## Result

On x86, the server-to-client 16 KiB ratio (TLSed ÷ rustls) depends on the runner's CPU, and rustls is the side that gets slower. The extra cost is memory copying, not AES-GCM and not process mode. The copy-time gap is measured on one runner (EPYC 7763), and the signature matches on the other slow runners, but those runners were not profiled.

| Run | CPU | Combined, TLSed ÷ rustls | Separate processes | Per record, combined (TLSed / rustls, ns) |
|---|---|---:|---:|---|
| `38702456224` | EPYC 9V74 | 0.560 | not run | 5,375 / 9,604 |
| `38709562536` | EPYC 9V74 | 0.558 (0.557–0.562) | not run | 5,363 / 9,631 |
| `38710051326` | EPYC 7763 | 0.697 | 0.685 (10,962 / 15,989) | 11,121 / 16,010 |
| `38708921581` | EPYC 9V45 | 0.991 (0.961–0.993) | 1.02 (2,719 / 2,667) | 2,721 / 2,816 |
| `38712799344` | Xeon Platinum 8370C | 1.042 (1.019–1.061) | not run | 5,403 / 5,222 at 16,645-byte fragments |

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

## Copy volume: rustls copies more bytes (`copy-volume/`)

An `LD_PRELOAD` shim (`copyshim.c`) counts every `memcpy` and `memmove` call and its bytes, on the Linux arm64 build. Each client runs at 5 and at 15 samples, and the slope between them gives bytes per bulk record. That removes handshake and warm-up bytes. The shim sees calls from Rust and from aws-lc through the PLT.

| Fragment | TLSed bytes/record | rustls bytes/record | TLSed copy calls/record | rustls copy calls/record |
|---:|---:|---:|---:|---:|
| 16,645 (default) | 82,597 | 127,676 | 10.4 | 18.9 |
| 4,096 | 86,732 | 127,655 | 16.0 | 17.9 |
| 1,024 | 93,917 | 233,204 | 28.0 | 45.7 |

So rustls copies about 1.5× TLSed's bytes at the default fragment size, and about 2.5× at 1 KiB. For a 16 KiB record, the copy volume is about 5 (TLSed) and 8 (rustls) record-sized copies, so both clients copy several times, and rustls more.

Per-byte cost, approximate, from the EPYC 7763 perf run (`x86-zen3-slow/perf-breakdown.txt`) divided by 51,840 records: TLSed moves about 83 KB in about 1.8 µs of `memmove`, roughly 46 GB/s, and rustls about 128 KB in about 8.0 µs, roughly 16 GB/s. The byte counts come from the Linux arm64 build, and the copy calls are the same code on the EPYC run. The throughput figures include a shared per-process component and are approximate.

So on the slow host, rustls moves about 1.5× the bytes at about a third of TLSed's copy throughput. Both factors add to the gap.

## Fragment sweep: time does not follow bytes on these hosts (`fragment-sweep/`)

Separate processes, two repeats, TLSed ÷ rustls, server-to-client 16 KiB:

| Fragment | Linux arm64, Docker | macOS (Apple M5) |
|---:|---|---|
| 16,645 | 0.96, 1.01 | 0.87, 0.86 |
| 4,096 | 1.08, 1.08 | 0.95, 0.91 |
| 1,024 | 1.03, 1.01 | 0.84, 0.94 |

Smaller fragments raise rustls's copy volume, but on these two hosts the time ratio stays between 0.84 and 1.08 and shows no trend with fragment size. The same sweep on an x86 runner (Xeon Platinum 8370C, run `38712799344`, `x86-fragment-sweep-xeon-8370c/`) gives TLSed ÷ rustls of 1.035 at 16,645 bytes, 1.052 at 4,096 and 0.948 at 1,024, again with no trend. This runner has parity with rustls at every fragment size, so the byte counts do not produce a penalty there either. Copy throughput was not measured on these hosts, so the reason is not established. The large penalty appeared on the slow EPYC runners, where copies are expensive. A sweep on one of those runners would show whether the gap follows the byte counts there, and that needs a dispatch that lands on one.

## Open questions

- Why copy throughput on the EPYC 7763 and 9V74 hosts is roughly a third of TLSed's copy throughput on the same host. Rustls's copies may land in cold memory, because it allocates a new buffer per record, but nothing here measures cache state at the copy.
- The fragment sweep on a slow EPYC runner, to see whether the time gap widens at small fragments as the byte counts predict. The sweep has run on the Xeon 8370C (no trend) but not on an EPYC runner, and the EPYC 7763 is the one where the penalty is memmove-bound.
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
- `x86-fragment-sweep-xeon-8370c/`: the Xeon 8370C run (`38712799344`): bench output, the combined comparison, and the fragment sweep.
- `copy-volume/`: the copy-counting shim source, raw runs at each fragment and sample count, and `per-record.txt`.
- `fragment-sweep/`: separate-process timings on Linux arm64 and macOS at three fragment sizes, two repeats each.
