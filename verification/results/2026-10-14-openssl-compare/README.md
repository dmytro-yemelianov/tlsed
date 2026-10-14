# TLSed vs OpenSSL client comparison, core profiles, 2026-10-14

Question: how does the TLSed client compare with an OpenSSL 3 client on the same workloads, against the same peer?

## Corrections (read first)

Two harness defects were found and fixed during this comparison. Numbers from before the fixes are superseded, and the fixes change some conclusions.

1. **Shim error-queue clear.** The C shim called `ERR_clear_error()` on every `WANT_READ`, which happens on every partial-record step. Fixed: the clear now happens only on fatal errors. Effect on OpenSSL: 64-byte client-to-server records (ratio 0.36 → 0.55) and 16 KiB fragment-64 client-to-server (0.26 → 0.66).
2. **Transport drain.** The memory transport removed each consumed fragment with `Vec::drain(..n)`, which shifts the whole remaining record on every step. On the 64-byte-fragment receive path that was 78% of TLSed's own samples. Fixed: a read cursor, compacted only when at least half the buffer is consumed. Effect: fragment-64 server-to-client at 16 KiB moved from 0.63 to 0.28.

**Consequence for earlier work:** the repo's `crates/tls-bench/src/bin/client_compare.rs` has the same drain transport. The fragment-64 TLSed-vs-rustls numbers from `tls-bench` (the `client-comparison` and `cpu-audit` results, and the summary I gave earlier) were measured through that transport and are not valid until they are rerun. The non-fragment rows are much less affected.

## Setup

- **One peer for every client:** a rustls 0.23.45 server with the fixture certificate, TLS 1.3, ALPN `bench/1`, no resumption, no tickets.
- **Three clients, same workloads, same memory transport:**
  - `tlsed`: `tls-client`, strict `tls-pki` policy.
  - `rustls_strict`: rustls 0.23.45 client with the same strict verifier.
  - `openssl`: OpenSSL 3.6.5 (Homebrew) client over memory BIOs. Fixture CA, `X509_PURPOSE_SSL_SERVER`, `X509_V_FLAG_X509_STRICT`, host `localhost`, TLS 1.3 only, one suite per profile. Its certificate check is OpenSSL's, not `tls-pki`.
- **Harness:** `verification/experiments/openssl-compare/`. `src/main.rs` is the rustls harness plus an OpenSSL client; `src/openssl_shim.c` is the C client; `src/ossl.rs` is its safe Rust wrapper; `run.py` is the driver.
- **Method:** 6 fresh-process repeats per profile, 100 samples per workload (256 records per bulk sample), implementation order rotated by repeat. Ratios are computed per repeat; the table gives the median and the min–max range.
- **Correctness gate:** the reject-wrong-identity test passes for all three clients, and every handshake checks TLS 1.3, the expected suite, verified chain and host, and ALPN `bench/1`.
- **Environment:** Apple M5, macOS 27.2, rustc 1.98.1, **AC power** (battery in the earlier runs; absolute numbers shift a little), 1-minute load about 3.

## Results (ratio = client time ÷ OpenSSL time; below 1 means the client is faster)

AES-128-GCM, X25519, 16,645-byte fragments:

| Workload | Direction | Bytes | TLSed ÷ OpenSSL | rustls ÷ OpenSSL | TLSed ÷ rustls |
|---|---|---:|---:|---:|---:|
| bulk | client → server | 64 | 0.55 [0.52, 0.61] | 0.63 | 0.88 |
| bulk | client → server | 1,024 | 0.69 [0.67, 0.72] | 0.72 | 0.96 |
| bulk | client → server | 16,384 | 0.78 [0.76, 0.83] | 0.76 | 1.02 |
| bulk | server → client | 64 | 0.68 [0.63, 0.74] | 0.73 | 0.94 |
| bulk | server → client | 1,024 | 0.77 [0.47, 0.79] | 0.81 | 0.95 |
| bulk | server → client | 16,384 | 0.91 [0.85, 0.95] | 1.00 | 0.90 |
| full handshake, fresh buffers | both | — | 0.65 [0.62, 0.67] | 0.66 | 0.99 |
| full handshake, reused buffers | both | — | 0.64 [0.62, 0.66] | 0.65 | 0.98 |
| connection lifecycle | both | — | 0.66 [0.60, 0.71] | 0.66 | 1.01 |

Absolute medians (ns): handshake fresh TLSed 121,448, rustls 122,146, OpenSSL 186,416. Bulk 16 KiB client → server: TLSed 5,312, rustls 5,204, OpenSSL 6,908.

Other profiles (TLSed ÷ OpenSSL, medians):

| Profile | Handshake, fresh | Bulk 64 B c→s / s→c | Bulk 1 KiB c→s / s→c | Bulk 16 KiB c→s / s→c |
|---|---:|---:|---:|---:|
| AES-128-GCM, 64-byte fragments | 0.65 | 0.61 / 0.59 | 0.65 / 0.35 | 0.67 / 0.28 |
| ChaCha20-Poly1305, 16 KiB records | 0.65 | 0.65 / 0.71 | 0.89 / 1.03 | 0.98 / 1.03 |

Full per-workload table with ranges: `comparison.csv`. The AES-256, P-256, and HRR profiles are in `../2026-10-14-openssl-compare-extended/` and `../2026-10-14-openssl-compare-p256-hrr-12/`.

## What the numbers say

1. **The handshake is about 1.5× slower on OpenSSL, and that holds for every profile.** The gap is not AEAD: ChaCha has the same 0.65. Certificate policy explains only part of it. OpenSSL's chain check takes about 40 µs on this machine, against 28 µs for `tls-pki` strict and webpki native, measured in the same session (`diagnostics/`). The rest is OpenSSL's own handshake work, mostly P-256 and X25519 field arithmetic and its record and state-machine code.
2. **64-byte client-to-server records are about 1.8× slower on OpenSSL.** The 64-byte attribution is OpenSSL's record builder and memory-BIO bookkeeping (about 30% of samples), memory copies and allocation (about 20%), and only 7–11% in its AES-GCM kernel (`diagnostics/attribution-current-harness.txt`).
3. **Bulk server-to-client at 16 KiB is close to parity on AES-128.** OpenSSL's AES-GCM decrypt kernel is 40% of that window, and AWS-LC (the rustls peer's encrypt) is 27%. ChaCha bulk is at parity (0.98–1.03), so the AES bulk gap is largely the AEAD implementation. TLSed and rustls use AWS-LC; the OpenSSL client uses libcrypto.
4. **Fragment-64 reads are dominated by OpenSSL's record and BIO path.** With the fixed transport, 61% of the 16 KiB receive window is OpenSSL's own record and memory-BIO code and only about 10% is its AEAD kernel. A real socket delivers larger chunks, so this is a worst case for OpenSSL, not a throughput claim for real traffic.

## Caveats

- **Crypto backends differ.** TLSed and rustls use AWS-LC; the OpenSSL client uses libcrypto 3.6.5 for AES-GCM, P-256, X25519, and ECDSA. This is a comparison of two complete TLS client implementations as built, not of protocol code alone.
- **Certificate policy differs.** OpenSSL uses its own chain checks with the strict flags above, not the maintained `tls-pki` policy. The `diagnostics/` numbers put the difference at roughly 12 µs per handshake.
- **The timed region includes the peer.** The rustls server runs inside every timed loop, so ratios are diluted toward 1. The client-only gap is larger than shown, in the same direction.
- **Outlier repeats.** A single process runs the three clients back to back, so a load spike lands on one client's block. The AES-128 1 KiB server-to-client row has a repeat at 0.47 that pulls its minimum down; the median is unaffected.
- **One machine, one session.** Use the ratios, not the absolute values.

## Files

- `comparison.csv`: per profile, workload, and direction: absolute medians for each client, TLSed ÷ OpenSSL with min and max, rustls ÷ OpenSSL, and TLSed ÷ rustls.
- `aes128-x25519/`, `aes128-x25519-fragment64/`, `chacha-x25519/`: raw per-repeat CSVs.
- `diagnostics/`:
  - `x509_verify_micro.txt`, `x509_verify_micro.c`: OpenSSL chain-verification cost (about 40 µs per verification).
  - `pki_compare-now.csv`: the repo's `tls-pki` benchmark in the same session (strict 28.4 µs, native 28.0 µs).
  - `attribution-current-harness.txt`: the owner-grouped sample shares for six paths on the fixed harness.
  - `profile-openssl-first-*.sample.txt`: the raw `sample` output behind them.
- `run.json`: argv, binary and source hashes, host, loads.
