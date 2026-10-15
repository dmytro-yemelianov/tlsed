# TLSed vs OpenSSL, P-256 and HelloRetryRequest, 12 repeats, 2026-10-14

Rerun of two extended profiles with 12 repeats, because the 6-repeat handshake rows were noisy. Same paired harness, peer, and driver as `../2026-10-14-openssl-compare/`. Read the core README's **Corrections** section first: these numbers come from the fixed shim and transport.

- **Profiles:** AES-128-GCM with P-256 key exchange, and AES-128-GCM with X25519 and HelloRetryRequest (the peer accepts only P-256, so a successful handshake must have gone through HRR).
- **Method:** 12 fresh-process repeats per profile, 100 samples per workload, implementation order rotated by repeat. Ratio = TLSed ÷ OpenSSL (below 1: TLSed is faster). Median over repeats; min–max in brackets.
- **Environment:** Apple M5, AC power, one session, 1-minute load about 3.9.

## Results

| Profile | Handshake, fresh | Handshake, reused | Bulk 64 B c→s / s→c | Bulk 1 KiB c→s / s→c | Bulk 16 KiB c→s / s→c |
|---|---:|---:|---:|---:|---:|
| AES-128-GCM / P-256 | 0.66 [0.62, 0.70] | 0.63 [0.60, 0.67] | 0.56 / 0.66 | 0.71 / 0.77 | 0.81 / 0.90 |
| AES-128-GCM / X25519, HRR | 0.67 [0.29, 0.71] | 0.65 [0.63, 0.69] | 0.55 / 0.67 | 0.70 / 0.78 | 0.79 / 0.89 |

Absolute medians (ns): P-256 handshake (fresh) TLSed 131,448, rustls 150,562, OpenSSL 199,312. HRR handshake (fresh) TLSed 151,948, OpenSSL 235,219.

## Noise

- **P-256:** all 12 repeats of the fresh handshake fall in 0.62–0.70.
- **HRR:** one repeat is an outlier at 0.29 (the fresh handshake's minimum). The other 11 repeats sit at 0.62–0.71. The median (0.67) is unaffected. Its 1 KiB client-to-server minimum (0.39) is the same kind of outlier.

## Reading

- P-256 and X25519 give the same handshake ratio (0.63–0.67), so the key-exchange group does not change the ranking.
- The HRR path ends at the same ratio as the direct handshake, about 0.65–0.67.
- The earlier P-256 handshake reading of 0.76 was an artifact of outlier repeats; this 12-repeat run gives 0.66.

## Files

- `comparison.csv`: per profile, workload, and direction, with absolute medians, TLSed ÷ OpenSSL with min and max, rustls ÷ OpenSSL, and TLSed ÷ rustls.
- `aes128-p256/`, `aes128-hrr/`: raw per-repeat CSVs (12 each).
- `run.json`: argv, binary and source hashes, host, loads.
