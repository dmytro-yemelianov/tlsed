# tls-bench client comparison, transport fixed, fragment-64 and primary profile, 2026-10-14

Rerun of the TLSed vs rustls comparison with the memory transport fixed (`client_compare.rs`: a read cursor instead of `Vec::drain` per fragment). Only two profiles were run: the 64-byte fragment profile, which is the one the defect affected, and the primary AES-128 / X25519 profile as a control.

- **Method:** `compare_clients.py --repeats 6 --samples 100 --bulk-records 256 --only-profiles aes128-x25519,aes128-x25519-fragment64`. Fresh process per repeat; order alternates by repeat. Ratio = TLSed ÷ rustls (below 1: TLSed is faster). Median over repeats, min–max in brackets.
- **Binary:** `client_compare` built from this tree (`run.json` has the hashes).
- **Environment:** Apple M5, AC power, one session.

## Why this rerun exists

`Transport::pump` in `client_compare.rs` removed each consumed fragment with `Vec::drain(..n)`, which shifts the rest of the buffered record on every step. On the 64-byte fragment path that cost dominated every client's time. The OpenSSL harness had the same defect and was fixed first (see `../../../../verification/results/2026-10-14-openssl-compare/README.md`). The frozen cpu-audit baseline and the earlier `client-comparison` fragment rows were measured through the drain transport.

## Results

Fragment-64 profile (TLSed ÷ rustls):

| Workload | Direction | Bytes | Fixed transport | Drain transport (cpu-audit frozen baseline) |
|---|---|---:|---:|---:|
| bulk | client → server | 64 | 0.87 [0.82, 0.92] | 0.87 |
| bulk | client → server | 1,024 | 0.76 [0.42, 0.82] | 0.79 |
| bulk | client → server | 16,384 | 0.74 [0.71, 0.75] | 0.75 |
| bulk | server → client | 64 | 0.78 [0.75, 0.80] | 0.79 |
| bulk | server → client | 1,024 | 0.67 [0.65, 0.70] | 0.71 |
| bulk | server → client | 16,384 | **0.62** [0.60, 0.63] | **0.84** |
| full handshake, fresh buffers | both | — | 0.99 [0.97, 1.01] | 0.99 |
| connection lifecycle | both | — | 1.00 [0.98, 1.01] | 1.12 (before the Drop fix) |

Primary AES-128 / X25519 profile (control, TLSed ÷ rustls):

| Workload | Direction | Bytes | Fixed transport | cpu-audit frozen baseline |
|---|---|---:|---:|---:|
| bulk | client → server | 1,024 | 0.94 [0.92, 0.98] | 0.93 |
| bulk | client → server | 16,384 | 1.02 [1.00, 1.03] | 1.02 |
| bulk | server → client | 1,024 | 0.95 [0.93, 0.99] | 0.92 |
| bulk | server → client | 16,384 | 0.86 [0.85, 0.87] | 0.83 |
| full handshake, fresh buffers | both | — | 1.03 [0.99, 1.09] | 0.99 |

## Reading

- **Server-to-client, fragment 64:** the drain inflated the rustls-relative figure. With the fixed transport TLSed is 0.62× rustls at 16 KiB instead of the 0.84× in the frozen baseline. The client-to-server figure is unchanged (0.74 against 0.75), so the defect affected receives.
- **Primary profile:** the control matches the frozen baseline within about 4% on every bulk row and the handshake. The transport fix leaves the non-fragmented path unchanged, as expected.
- **Handshake and lifecycle:** TLSed and rustls are level (0.99–1.03). The frozen lifecycle figure of 1.12 predates the `Drop` fix.

## Superseded: the 2026-10-14 `client-comparison` run

`../2026-10-14-client-comparison/` (binary `9f1f8ec…`) does not reproduce: its primary-profile ratios are 1.42 for 1 KiB client-to-server and 2.9 for 16 KiB server-to-client, against 0.93 and 0.83 in the frozen baseline and 0.94 and 0.86 here. Its TLSed per-record time for 1 KiB server-to-client is 7,956 ns against 446 ns for rustls, which is not consistent with any other run. Treat that directory as superseded and do not cite it. Its cause is not established: it was built from a different source state.

## Files

- `comparison.csv`: per profile, workload, and direction, with medians, ratios, and the per-repeat ratios.
- `aes128-x25519-fragment64/`, `aes128-x25519/`: raw per-repeat CSVs and stderr logs.
- `pki/`: the PKI comparison run in the same session.
- `run.json`: argv, binary and source hashes, host, commands.
