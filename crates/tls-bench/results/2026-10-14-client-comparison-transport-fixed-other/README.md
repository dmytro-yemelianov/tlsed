# tls-bench client comparison, transport fixed, remaining profiles, 2026-10-14

The fixed-transport rerun of the profiles that were not covered by `../2026-10-14-client-comparison-transport-fixed/`: AES-256-GCM / X25519, ChaCha20-Poly1305 / X25519, AES-128-GCM / P-256, and AES-128-GCM / HRR.

- **Method:** `compare_clients.py --repeats 6 --samples 100 --bulk-records 256 --only-profiles aes256-x25519,chacha-x25519,aes128-p256,aes128-hrr`. Fresh process per repeat, order alternating. Ratio = TLSed ÷ rustls; below 1 means TLSed is faster.
- **Binary:** built from the current tree, with the landed production sources.
- **Comparison baseline:** `../../../../verification/results/2026-10-14-cpu-audit/baseline/comparison.csv`, the frozen run that measured the same profiles through the drain transport and before the `Drop` fix.

## Result

Moving from the drain transport to the cursor transport changes most rows by 5% or less, which is within the run-to-run noise. Those rows are the non-fragmented bulk, handshakes, and HRR. The lifecycle rows differ more (about 0.1) because the frozen baseline predates the `Drop` fix.

Largest moves, with the frozen value first and the fixed value second:
- AES-128 HRR server-to-client 1 KiB: 0.93 → 0.99. The maximum repeat is 1.58, so this row is noisy.
- AES-128 HRR server-to-client 16 KiB: 0.84 → 0.88.
- AES-128 P-256 lifecycle: 1.03 → 0.92 (the `Drop` fix).
- AES-256 client-to-server 16 KiB: 1.02 → 0.87, a change of about 14%, with a repeat range of 0.69–1.67. The row is too noisy to attribute to the transport. Read the AES-256 bulk and lifecycle medians with caution.

The drain-transport artifact mainly affected fragment-64, which is covered in the primary-profile README. These profiles show no comparable effect.

## Files

- `comparison.csv`: per profile, workload, and direction, with medians, ratios, and per-repeat ratios.
- Raw per-repeat CSVs and stderr logs per profile; `pki/`; `run.json`.
