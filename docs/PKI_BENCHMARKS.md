# Measured PKI validation costs

The 2026-10-14 fixed-input comparison measured about **25–27 µs per
validation** on the recorded Apple M5 environment. For the valid direct-root
leaf, the median batch average was **25.464 µs** for maintained webpki and
**26.216 µs** for the strict tls-pki adapter. The whole adapter difference was
about **0.752 µs / 2.95%** at the median. These measurements do **not** suggest
that strict KeyUsage parsing dominates this valid workload. They do not isolate
KeyUsage parsing from preflight, callback/token overhead or measurement noise,
and they do not establish the cost of longer or ambiguous certificate paths.

## Results and retained evidence

Each implementation/workload has five fresh-process repeats  × 100 samples
 × 256 validations: 500 measured batches and 128000 validations. The harness
warms each workload/implementation 20 times per process and alternates
implementation order across samples. The table divides each batch statistic
by 256 and 1000 to express microseconds per validation. Median/p95 are quantiles
of **batch averages**, not quantiles of individual validation latency. CV is
computed over the original batch durations.

| Workload | Implementation | Mean µs | Median µs | p95 batch average µs | Batch CV |
|---|---|---:|---:|---:|---:|
| Valid leaf | webpki native policy |25.880 |25.464 |26.571 |13.12% |
| Valid leaf | tls-pki strict KeyUsage |26.536 |26.216 |27.370 |6.90% |
| Wrong reference name | webpki native policy |25.892 |25.561 |26.813 |8.51% |
| Wrong reference name | tls-pki strict KeyUsage |26.780 |26.364 |27.668 |9.61% |
| Invalid issuer signature | webpki native policy |25.783 |25.471 |26.881 |5.20% |
| Invalid issuer signature | tls-pki strict KeyUsage |25.740 |25.488 |26.694 |6.24% |

Across the five process repeats, valid-leaf strict/native median ratios ranged
from 1.0245 to1.0357. Wrong-name ratios ranged from 1.0278 to1.0416; invalid-signature
ratios ranged from 0.9967 to1.0018. Invalid-signature work fails native path
verification before the adapter's leaf KeyUsage check, consistent with the
similar measured costs. This is a source-supported interpretation, not a
profile proving which native instruction dominates. Aggregate means differ
from medians and CV reaches 13.12%; small negative-path differences must not be
reported as wins.

Retained [summary CSV](../crates/tls-bench/results/2026-10-14-client-comparison/pki/summary.csv),
[raw repeat0](../crates/tls-bench/results/2026-10-14-client-comparison/pki/repeat-0.csv)
(and repeats1–4 alongside it), [policy stderr](../crates/tls-bench/results/2026-10-14-client-comparison/pki/repeat-0.stderr)
and [run commands/controls](../crates/tls-bench/results/2026-10-14-client-comparison/run.json)
allow independent recomputation. The retained pki_compare binary SHA256 is
`3aceb369c20af899512a47c00d20026f23d796469f697fd2abc7600d8a68a173`.

## Policy and timing boundaries

This supplements the authenticated endpoint comparison; it is **not** a
comparison of independent PKI implementations or identical policy. Both paths
use maintained webpki 0.103.15 and AWS-LC. `webpki_native_policy` performs native
chain/serverAuth/name validation without our strict KeyUsage supplement.
`tls_pki_strict_key_usage` adds configured count/DER-byte preflight and maintained
X.509/ASN.1 parsing to enforce digitalSignature on the leaf and keyCertSign on
selected issuing intermediates when KeyUsage exists. This fixture has no
intermediates, so no issuer KeyUsage parsing occurs. The explicitly supplied
trust anchor is separate from leaf and issuing-intermediate KeyUsage policy. Native webpki's different
KeyUsage scope is a backend policy boundary, not an established rustls
vulnerability. Both paths accept this valid leaf and reject the same wrong-name
and invalid-signature cases with their exact native error classes.

The shared inputs are one explicit CA anchor, a 432-byte P256/SHA256 CA-signed
leaf, DNS reference `localhost` (or `wrong.invalid`), serverAuth EKU and
`UnixTime(1792022400)` = 2026-10-15 00:00:00 UTC. The leaf has SAN localhost and
digitalSignature and is valid from 2026-10-14 through 2036-10-11. The signature
negative flips the final signature byte while retaining certificate structure.
There is no CRL/OCSP data or revocation assertion, network access, system root
loading or machine-clock consultation. Root/configuration/name construction,
fixture mutation and warmup are outside timed samples; each iteration includes
leaf parse, path/signature validation, subject-name validation and outcome
assertion. These measurements exclude CertificateVerify, TLS Finished, sockets,
record crypto, `VerifiedServerCert::to_owned`, root-store construction and
complete handshake lifecycle.

The native algorithm allowlist exactly matches the adapter's thirteen modern
certificate-signature entries: ECDSA P256/SHA256, P384/SHA384, P521/SHA512;
Ed25519; RSA PKCS1 SHA256/384/512 with both accepted parameter forms; and
RSA-PSS SHA256/384/512 with legacy RSA key OIDs. Only P256/SHA256 is exercised
by this fixture. These issuer algorithms are separate from TLS handshake
CertificateVerify's smaller whitelist.

Pins in [Cargo.lock](../Cargo.lock) are aws-lc-rs 1.18.2,
aws-lc-sys 0.46.0, rustls-webpki 0.103.15, rustls-pki-types 1.15.1 and
x509-parser 0.18.1; the harness imports shared types from rustls 0.23.45.
The [recorded environment](../crates/tls-bench/results/2026-10-14-client-comparison/environment.txt) is
Apple M5 ARM64, macOS 27.2, Rust 1.98.1, release thin LTO/codegen-units 1.
The run records no concurrent agent compilation/fuzzing; affinity, frequency
and scheduler isolation were unavailable. These are local repeated measurements,
not portable performance guarantees, confidence intervals, constant-time
measurements or external security review.

The [fixture README](../crates/tls-bench/fixtures/README.md) records their public
local-test provenance. DER SHA256 values are:

- CA: `d6517b3f2f31d119fcc2880ddc29257696f8ab43b0b8a737a304e2fe34bb8e75`.
- Leaf: `f17604ae2e4e42abad2583d8de33d52ea399e1d9073c761839ae773e7f62bc50`.

Source paths are the [comparison harness](../crates/tls-bench/src/bin/pki_compare.rs)
(`Context::native`, `Context::strict`, `run`), the
[strict adapter](../crates/tls-pki/src/lib.rs)
(`ServerVerifier::verify_server_certificate`, `check_key_usage`),
[PKI policy](PKI.md) and [project README](../README.md).
Reproduce one process with:

```sh
cargo run --release -p tls-bench --bin pki_compare --locked -- \
  --samples 100 --iterations 256 --warmup 20
```

## Next profiling hypotheses

First profile this common native path and separately measure the strict
supplement; the current aggregate delta gives no reason to treat KeyUsage
parsing as the dominant optimization target. Measure Rust/native allocations
independently and preserve strict policy while exploring fewer redundant parses.
A parsed-leaf lifetime design is only a hypothesis until correctness and repeated
measurements establish its value.

Pinned webpki source provides concrete additional workloads. `build_chain_inner`
scans anchors and candidate intermediates; `check_signed_chain` validates each
candidate path before the application path callback. Ambiguous/cross-signed
issuers can repeat parsing and shared signature work. `PartialPath` uses fixed
six-intermediate storage, so heap allocation per path node is not an assumption.
Profile direct-root, multilevel, ambiguous issuer and bounded adversarial paths
before considering indexes or signature caches. Native signature, path-call
and name-comparison budgets must remain fail closed. These mechanisms are
visible in [pinned path builder](https://raw.githubusercontent.com/rustls/webpki/v/0.103.15/src/verify_cert.rs).

Algorithm filtering in [signed_data](https://raw.githubusercontent.com/rustls/webpki/v/0.103.15/src/signed_data.rs)
and native public-key handling in the [AWS-LC adapter](https://raw.githubusercontent.com/rustls/webpki/v/0.103.15/src/aws_lc_rs_algs.rs)
are profiling targets, not demonstrated bottlenecks or measured wins. This
single-root P256 corpus does not exercise large trust stores, RSA/Ed25519,
name constraints, revocation, issuer selection ambiguity or expensive error
construction. Any later optimization of webpki or our wrapper must preserve
trust/time/identity/algorithm/constraint/KeyUsage semantics, selected-path retry,
budget/error behavior and bounded memory, with proof scope and controlled
benchmarks stated separately.

The subsequent [source comparison](SOURCE_COMPARISON.md) proposes a bounded
alternative-issuer workload using strict bad-KU/good-path regressions. The current
direct-root data does not establish path-ordering, caching or webpki patch gains.
