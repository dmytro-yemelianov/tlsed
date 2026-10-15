# Server-to-client 16 KiB, x86: investigation, 2026-10-15

## Result

**The x86 ratio of 0.56 (TLSed ÷ rustls, server-to-client, 16 KiB) does not reproduce, and it is not a property of TLSed or rustls.** It came from the first `bench-x86` run on the shared runner, run `38702456224`. On a second runner, the same combined measurement gives 0.99, and separate-process measurements give 1.02. The first runner ran TLSed about 1.9× and rustls about 3.4× slower than the second, and the two clients did not slow down by the same factor. The mechanism behind that is not established.

Treat the x86 server-to-client 16 KiB row as machine-dependent, and do not present it as a TLSed advantage. This is a retraction of the 0.56 claim in `../2026-10-15-x86-ci/README.md`.

## Evidence

| Check | Where | TLSed ÷ rustls, s→c 16 KiB | Notes |
|---|---|---:|---|
| First x86 run, combined (both clients, one process) | `../2026-10-15-x86-ci/` (run `38702456224`) | 0.56 [0.55, 0.59] | Per record: TLSed 5,274 ns, rustls 9,603 ns |
| Second x86 runner, combined, same job as the deep dive | `x86-same-machine-combined/` (run `38708921581`) | **0.991** [0.961, 0.993] | Per record: TLSed 2,721 ns, rustls 2,815 ns |
| Second x86 runner, separate processes | `x86-deep-dive/*-timing.csv` (run `38708921581`) | **1.02** | 100 samples per client. TLSed 2,719 ns, rustls 2,667 ns per record |
| macOS (Apple M5), four configurations | `mac-process-check/` | 0.86–0.90 in every configuration | Combined and separate agree. Macs are not affected by the process mode |
| Linux arm64 in Docker (glibc 2.36), separate processes | `linux-arm64/run-*.csv` | 1.04 | 5,914 vs 5,664 ns per record |

The first x86 run's ratio was consistent across its 3 repeats (0.55–0.59), so the difference is stable on that machine. That is why it looked real. The second runner is the one that reproduces the expected parity.

## Hypotheses checked

- **Per-record page faults, from glibc's allocator (rejected).** Rustls allocates per record and TLSed reuses buffers, so faults were the first suspect. On Linux arm64, the whole 40-sample run had 137 faults for TLSed and 145 for rustls, so per-record faults are negligible there. On x86 the faults were also small. The 100-sample timing run had 147 for TLSed and 154 for rustls, the 400-sample perf run 145 and 156, and the 5-sample callgrind run 745 and 776 (callgrind adds its own overhead). The faults do not explain a 3.4× gap.
- **Interaction between the two clients in one process (rejected).** On macOS, the combined and separate configurations agree within a few percent. On the second x86 runner, the combined run gives 0.99, the same as the separate runs.
- **A different instruction count per record (rejected).** Callgrind over the same workload gives 696.6M instructions for TLSed and 677.1M for rustls, including the shared harness work. Both profiles are dominated by `aes_gcm` decrypt and encrypt and `memmove`, with similar shares (`x86-deep-dive/*-perf-report.txt`, `*-callgrind.txt`).
- **Machine state (supported by the data, mechanism untested).** The two runners differ by about 1.9× for TLSed and 3.4× for rustls on the same workload, so the difference depends on the machine, not on the code. The profiles do not identify the cause. Memory-bandwidth or cache contention from other tenants on the first host is a plausible candidate, but nothing here tests it, and the shared runners do not allow a controlled load test.

## Other findings from this investigation

- **Padded-record baseline (Linux arm64).** The pre-landing scan and tail wipe, reconstructed from the diff in `verification/experiments/inner-scan-audit/baseline/prelanding.diff`, give a padded-record cost of 0.27× the current cost on this platform (padmax 10,737 → 2,878 ns, inner_padmax 0.271, tag_long 0.304, pad4k 0.330, pad1k 0.419). Long records are unchanged at 1.00. The macOS landed-check gave 0.215 for padmax. The effect is the same kind on both platforms, with a different absolute size. `linux-arm64/pre-*.csv` and `head-*.csv` have the raw runs.
- **Harness change.** `client_compare --impl tlsed|rustls` runs one client per process, and it prints minor faults per run on Linux. The combined default is unchanged.

## Caveats

- Each condition ran on one runner or one machine. The first x86 runner is no longer available, so the 0.56 cannot be re-measured on it.
- The deep-dive perf and callgrind runs are short (829 samples for rustls, 5 callgrind samples). They are good enough for shares, not for small differences.
- The raw `perf.data` and callgrind files are not committed. The text reports are.

## Files

- `x86-deep-dive/`: per-client timing CSVs and stderr, minor faults, perf reports, callgrind annotations.
- `x86-same-machine-combined/`: the combined `bench-x86` output from run `38708921581`, on the second runner.
- `mac-process-check/`: macOS combined and separate runs, three repeats each.
- `linux-arm64/`: Linux arm64 separate-process runs and the padded-record baseline check.
