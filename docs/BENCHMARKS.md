# Authenticated baseline benchmark

**Historical exploratory phase0 evidence.** The new
[authenticated tlsed/rustls comparison](CLIENT_BENCHMARKS.md) and
[PKI costs](PKI_BENCHMARKS.md) contain current own-client measurements.
The results below measure maintained
reference implementations only. Both reference endpoints complete authenticated TLS1.3
handshakes in process with memory transports and independently verify received
application bytes. Raw observations are in [results](../crates/tls-bench/results/).

## Reproduce

```sh
cargo run --locked --release -p tls-bench -- --samples 30 --bulk-records 256 > crates/tls-bench/results/rustls.csv
# macOS Homebrew OpenSSL3; adjust prefix for other platforms:
cc -O3 -Wall -Wextra -Werror -I/opt/homebrew/opt/openssl@3/include crates/tls-bench/openssl-memory.c -L/opt/homebrew/opt/openssl@3/lib -Wl,-rpath,/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -o /tmp/tls-bench-openssl
/tmp/tls-bench-openssl crates/tls-bench/fixtures 30 256 > crates/tls-bench/results/openssl.csv
python3 crates/tls-bench/summarize.py crates/tls-bench/results/rustls.csv crates/tls-bench/results/openssl.csv > crates/tls-bench/results/summary.csv
```

Compile outside measured timing. For a controlled experiment alternate complete
reference runs, use at least five independent repeats, record power/frequency
and scheduler state, and measure on x86_64 and ARM64. These initial samples
are consecutive observations within one run, not independent randomized trials.
`summarize.py` uses nearest-rank p50/p95/p99, sample standard deviation, coefficient
of variation, and plaintext GiB/s = payload*iterations/time/2^30. With30 samples,
p99 is simply the maximum; do not interpret it as a stable tail estimate.

## Identical logical workload

Reference profile: rustls0.23.45, rustls-webpki0.103.15, aws-lc-rs1.18.2;
OpenSSL3.6.5 (2026-09-29). Both roles; TLS1.3 only, AES128GCM/SHA256,
X25519, fixed P256/SHA256 CA-signed leaf, explicit CA trust, hostname localhost,
SNI localhost, ALPN bench/1. Client certificates disabled in both. Session
caches/tickets/resumption and early data disabled. Randomness is real secure
provider randomness; fixtures, not ephemeral keys, are deterministic.

Full handshake times include connection construction and both peers' crypto,
certificate/hostname verification and memory transport. Shared configuration
construction and fixture loading are outside timing; connection destruction
is outside timing. Five fresh full handshakes warm up before samples.
These are pair completion times, not separately attributable client/server
latencies and not network RTT or service handshakes/second at concurrency.

Bulk uses an already-authenticated pair per direction/size, with256 writes
of64B/1KiB/16KiB per sample and matching reads, comparing all plaintext bytes.
Each write is immediately transported and drained; no coalescing across writes.
Both encryption and decryption plus memory transport and comparison are timed.
It is not an isolated AEAD microbenchmark or separate encrypt/decrypt rate.

Rust uses a reused Vec transport; OpenSSL uses memory BIOs and a stack shuttle
buffer. Their transport/allocation/API overheads differ. Algorithms, identities,
record payloads and security policy are controlled, but these first results
cannot isolate library-only cost or justify a competitive winner. The C helper
is benchmark-only established-library glue, outside the Rust unsafe prohibition
and outside formal proof claims.

## First observed run

| Reference | Pair handshake p50 / p95 (µs) | Handshake CV | 16KiB client→server mean GiB/s | Bulk CV |
|---|---:|---:|---:|---:|
| rustls |123.208 /129.458 |2.19% |2.824 |4.35% |
| OpenSSL |273 /583 |37.68% |1.595 |12.92% |

These describe the saved observations only. Provider differences (AWS-LC versus
OpenSSL), transport implementation and substantial run/scheduler variance
prevent attributing the gap to Rust, proof machinery or our unfinished engine.
All directions/sizes, sample standard deviations and percentiles are retained
in [summary.csv](../crates/tls-bench/results/summary.csv). The negative hostname
regression `cargo test -p tls-bench` confirms the Rust baseline rejects the
wrong reference identity rather than silently disabling verification.

## Environment and limitations

Measured2026-10-14: Apple M5 ARM64, macOS27.2 build26B5086k,
Darwin27.2.0. Rust1.98.1; workspace release thin LTO and one codegen unit;
C clang -O3, Homebrew headers/library/rpath. OpenSSL system executable is
LibreSSL3.3.6 and is deliberately not used. No CPU affinity, frequency locking
or scheduler isolation; other work and initial toolchain compilation occurred
on the machine. Timing precision and scheduler/power noise matter at these
short intervals. Inspect coefficient of variation in summary.csv before using
any value. No cycles/byte, retired instructions, allocation counts, RSS or
connection-concurrency data were collected. No external s2n/BoringSSL baseline,
network benchmark or resumption benchmark was collected. Current tlsed/rustls
client interoperability is documented separately in [CLIENT_INTEROP.md](CLIENT_INTEROP.md);
it is not a timing result. Current timing evidence is in the two reports linked above.

Likely cost centers to profile later: certificate path/signature verification,
ECDHE/RNG, per-write memory transport and small-record call overhead. The current
measurements do not attribute costs to these components. ARM AES acceleration
may dominate bulk; provider microbenchmarks and profiles must test that hypothesis.

The [rustls benchmark guidance](https://github.com/rustls/rustls/blob/v/0.23.45/BENCHMARKING.md)
inspired separate handshake and bulk measurements. This harness is not a
reproduction of rustls's full benchmark suite. Future comparison with our
engine requires identical security, ciphers, provider where feasible, identities,
record sizing, feature scope and verification behavior; a parser-only timing
cannot be presented as faster TLS.
