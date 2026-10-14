# TLSed vs OpenSSL, extended profiles, 2026-10-14

The same paired harness, peer, and driver as `../2026-10-14-openssl-compare/`, on three more profiles: AES-256-GCM / X25519, AES-128-GCM / P-256, and AES-128-GCM / X25519 with HelloRetryRequest. Read the core README's **Corrections** section first: these numbers come from the fixed shim and transport.

- **HelloRetryRequest.** The peer accepts only P-256 in this profile, so a successful handshake must have gone through HRR. The OpenSSL client is configured with `X25519:P-256`, the same preference order as the rustls client.
- **Method:** 6 fresh-process repeats per profile, 100 samples per workload, implementation order rotated by repeat. Ratio = TLSed ÷ OpenSSL (below 1: TLSed is faster). Median over repeats; min–max in brackets.
- **Environment:** Apple M5, AC power, one session, 1-minute load about 3.5.

## Results (median, with min–max)

| Profile | Handshake, fresh | Handshake, reused | Bulk 64 B c→s / s→c | Bulk 1 KiB c→s / s→c | Bulk 16 KiB c→s / s→c |
|---|---:|---:|---:|---:|---:|
| AES-256-GCM / X25519 | 0.68 [0.63, 0.74] | 0.67 [0.65, 0.71] | 0.57 / 0.72 | 0.75 / 0.84 | 0.82 / 0.95 |
| AES-128-GCM / P-256 | 0.67 [0.65, 0.72] | 0.65 [0.64, 0.70] | 0.56 / 0.71 | 0.71 / 0.80 | 0.79 / 0.90 |
| AES-128-GCM / X25519, HRR | 0.67 [0.63, 0.71] | 0.65 [0.62, 0.70] | 0.57 / 0.69 | 0.70 / 0.78 | 0.80 / 0.90 |

Bulk-row ranges are in `comparison.csv`. Two of them are wide because of one outlier repeat: P-256 16 KiB client-to-server (max 1.05) and HRR 1 KiB server-to-client (max 1.33).

## Reading

- **Handshakes:** TLSed is about 0.65–0.68 of OpenSSL for AES-256, P-256, and HRR, the same as the AES-128 X25519 profile in the core run. The key-exchange group and the HRR path do not change the ranking.
- **HRR cost:** in this session the HRR handshake is about 20–25% slower than the direct X25519 handshake measured in the core session (TLSed 149 µs against 121 µs, OpenSSL 223 µs against 186 µs). The two sessions differ, so treat that as indicative.
- **AES-256:** the handshake gap matches AES-128, and the 16 KiB bulk gap is narrower (0.82 and 0.95). That fits the attribution of the AES bulk gap to the AEAD implementation, but this run does not isolate the cause.

## Earlier numbers that are superseded

- The P-256 handshake at 0.76 (an earlier 6-repeat run, not kept in the repo) came from outlier repeats. The 12-repeat run in `../2026-10-14-openssl-compare-p256-hrr-12/` gives 0.66, and this run gives 0.67.
- The "HRR adds 25%" figure came from the same noisy 6-repeat run.

## Files

- `comparison.csv`: per profile, workload, and direction, with absolute medians, TLSed ÷ OpenSSL with min and max, rustls ÷ OpenSSL, and TLSed ÷ rustls.
- `aes256-x25519/`, `aes128-p256/`, `aes128-hrr/`: raw per-repeat CSVs.
- `run.json`: argv, binary and source hashes, host, loads.

## Known limits

- The `run.py` driver and the harness changed after the core run (profile-set switch, generalized `--only`, the shim and transport fixes). The core, extended, and P-256/HRR sets were all rerun with the final versions, so their `run.json` hashes match each other.
- Same caveats as the core run: different crypto backends (AWS-LC for TLSed and rustls, libcrypto for OpenSSL), OpenSSL's own certificate checks, the rustls peer inside every timed loop, one machine, one session.
