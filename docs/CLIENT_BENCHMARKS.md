# Authenticated tlsed versus rustls client measurements

Latest measured client: [aligned volatile secret wiping](SECRET_WIPING.md),
with separate before/after observations against the prior optimized source.

Latest follow-up: [public wire clearing](WIRE_CLEARING.md) has separate paired
measurements against the already optimized engine. This report retains its
historical source-specific measurements and validation counts.

This report retains the baseline before buffer-clearing optimization. Current
[paired before/after measurements](READ_OPTIMIZATION.md) bring64-byte receive
near native parity; the original results below remain unchanged historical evidence.

The first controlled local comparison finds **tlsed slower on most measured
paths**. With AES128/X25519, fresh-buffer handshake is about16% slower and a
complete connection lifecycle about34% slower.16KiB transmit takes1.67x the
pair time; receive takes2.94x.64-byte receive takes36.5x. Small transmit is
approximately tied; its apparent advantage depends on run order.

Both implementations are actual authenticated clients talking to the same
maintained rustls server. The baseline is **rustls with shared strict tls-pki
certificate validation**, rather than the stock rustls verifier. This holds the
project's additional KeyUsage policy equal. Native CertificateVerify and Finished
remain active; wrong-name tests and exact application bytes are checked.

## Primary results

For AES128GCM/SHA256, X25519 and coalesced caller transport, the times below are
the median of each process repeat's median. Bulk times divide a256-record batch
by256; they are batch-average costs, not individual record latency percentiles.
The ratio column is the median of five paired repeat ratios; it need not equal
the ratio of the separately aggregated time columns.

| Workload | tlsed | rustls with strict PKI | tlsed/rustls time, repeat range |
|---|---:|---:|---:|
| Handshake, reused caller scratch |135.44 µs |116.98 µs |1.158x (1.106–1.243) |
| Handshake, fresh caller scratch |135.60 µs |116.67 µs |1.164x (1.123–1.265) |
| Construct + handshake + Drop/storage release |159.58 µs |120.00 µs |1.340x (1.328–1.434) |
|64 B transmit |0.206 µs/record |0.217 µs/record |0.960x (0.915–1.003) |
|64 B receive |7.734 µs/record |0.210 µs/record |36.535x (35.030–38.333) |
|1KiB transmit |0.646 µs/record |0.461 µs/record |1.419x (1.396–1.437) |
|1KiB receive |7.961 µs/record |0.446 µs/record |17.855x (17.393–18.311) |
|16KiB transmit |8.867 µs/record |5.336 µs/record |1.666x (1.650–1.789) |
|16KiB receive |14.652 µs/record |4.982 µs/record |2.937x (2.924–2.958) |

Primary pooled mean throughput at16KiB is1.673 versus2.849GiB/s transmit,
and1.028 versus3.060GiB/s receive. These use mean batch durations, while the
table uses medians; keep their aggregations separate. All encryption,
decryption, API/transport work and byte comparison are included.

For64-byte transmit the paired ratio is0.993 with tlsed-first repeats and0.915
with rustls-first repeats. The order dependence and range crossing parity
prevent a reliable tiny-write speed claim. The larger slowdowns retain the
same direction in every repeat.500 pooled samples per row are clustered within
five processes; no independent500-trial confidence interval is claimed.

## Other measured profiles

Each row uses median paired repeat ratios. Each implementation has100 samples
per workload per process, across five fresh processes with alternating run order.

| Profile | Fresh-buffer handshake |16KiB transmit |16KiB receive |64 B receive |
|---|---:|---:|---:|---:|
|AES128/X25519 |1.164x |1.666x |2.937x |36.535x |
|AES256/X25519 |1.132x |1.590x |2.685x |35.090x |
|ChaCha20/X25519 |1.155x |1.205x |1.541x |18.517x |
|AES128/P256 |1.107x |1.681x |2.941x |35.416x |
|AES128/HRR to P256 |1.157x |1.679x |2.985x |35.804x |
|AES128/X25519,64-byte network fragments |1.166x |1.031x |1.244x |30.037x |

The fragmentation profile includes bounded Vec transport shifts and many driver
calls; it is a transport/API experiment, not isolated cryptography. P256 clients
advertise the same two groups in different order: tlsed[X25519,P256], native
rustls[P256,X25519], both with initial P256 shares. Default X25519 and HRR group
offers have matching order. No byte-identical ClientHello claim applies: native
compatibility session IDs and extra extensions also differ.

## Scope and reproduction

Pins: rustls0.23.45, source commit2976d90fd1c2db6b518700dd101b714069cfcb17;
aws-lc-rs1.18.2/aws-lc-sys0.46.0; webpki0.103.15; Rust1.98.1.
[The upstream release](https://github.com/rustls/rustls/releases/tag/v/0.23.45)
was rechecked before measurements. Apple M5 ARM64, macOS27.2, AC power,
thin LTO and one codegen unit. No competing agent builds/fuzzing ran during the
canonical measurements. Affinity/frequency locking and scheduler isolation were
not applied; power/scheduler effects remain, with CV and repeat ranges retained.

One suite is offered per profile. Native hybrid defaults are removed. Both
clients offer X25519/P256 and the same five TLS1.3 signature schemes. Shared
public CA/P256 leaf, roots, localhost SAN/SNI, ALPN bench/1 and fixed native
TimeProvider/time2026-10-15 UTC are used. Session resumption, server tickets,
0-RTT, client certificates, key logging, padding and sockets are absent.

Fixtures, shared configuration and transport buffers are prepared outside timed
samples. Fresh/reused handshake timing includes connection construction and
both peers' RNG/KEX/PKI/CV/Finished through server acceptance of client Finished;
printing and Drop are outside. The separate lifecycle includes Drop/zeroization
and new connection scratch allocation/free. Reused tlsed caller storage is
115470 bytes; its constructor wiping stays inside timing. Native rustls's
internal connection allocations occur inside construction. Both clients have
one benchmark wrapper Box. The costs include each public API's real buffering
and copy behavior, not pure client CPU. Bulk uses preauthenticated pairs,
immediate transfer/drain per write and exact byte comparisons; warmup is excluded.

```sh
cargo build --locked --release -p tls-bench --bins
python3 crates/tls-bench/compare_clients.py \
  --output crates/tls-bench/results/NEW_COMPARISON \
  --repeats 5 --samples 100 --bulk-records 256
```

Use a new output directory. The canonical run contains54000 TLS observations
and3000 PKI batches. See [paired comparisons](../crates/tls-bench/results/2026-10-14-client-comparison/comparison.csv),
[primary summary](../crates/tls-bench/results/2026-10-14-client-comparison/aes128-x25519/summary.csv),
[exact commands/binary hashes](../crates/tls-bench/results/2026-10-14-client-comparison/run.json),
[source/fixture hashes](../crates/tls-bench/results/2026-10-14-client-comparison/source-hashes.sha256)
and [environment](../crates/tls-bench/results/2026-10-14-client-comparison/environment.txt).
Raw repeat CSVs and other profile summaries are stored alongside them.
[The harness](../crates/tls-bench/src/bin/client_compare.rs) and
[runner](../crates/tls-bench/compare_clients.py) are repository source artifacts;
native binaries are hashed and excluded from retained results. Remote CI smoke is configured but
has not been observed running. Local strict Clippy, format and regression checks pass.

## Measurements followed by code review

The first actionable tlsed hotspot is inbound clearing. After the canonical
run, a separate two-second native sampling diagnostic during tlsed64-byte
receive collected1690 main-thread samples.820 top frames land in an inlined
client-step zero loop;823 in the final client-read zero loop:97.2% together
in this narrow sampling window. The retained assembly at those exact offsets
shows `strb wzr`/decrement/branch loops. This is sampling attribution for one
phase, not a calibrated whole-run CPU percentage or proof of a predicted speedup.
See [sample](../crates/tls-bench/results/2026-10-14-client-comparison/client-sample.txt),
[hot-loop disassembly](../crates/tls-bench/results/2026-10-14-client-comparison/sample-hot-loop-disassembly.txt)
and [diagnostic command/early termination](../crates/tls-bench/results/2026-10-14-client-comparison/profile-run.json).
The deliberately terminated driver's partial CSV is excluded from all summaries.

Source explains the fixed clearing cost:

- `ProtectedReader::open` wipes everything after the content through the full
  output capacity. A64-byte payload in a16640-byte loan clears16576 unused,
  type/tag/padding bytes.
- `ClientConnection::read_plaintext` clears each consumed range, then clears the
  whole16640-byte loan when the record is fully read. This repeats clearing
  already-erased content and tail.
- Successful `receive_record` clears only its actual wire range; full-record
  storage wipe occurs on error/Drop. Do not attribute the observed success-path
  cost to a nonexistent full-record clearing operation.

First change hypothesis: remove the redundant final whole-plaintext wipe only
after establishing that the core has cleared the tail and all consumed ranges
cover the full content on completion. A second hypothesis is a tighter active
output slice in the engine, with an invariant proving unused backing storage
already clean. Preserve full failure/Drop wipes, no unauthenticated release,
partial-read behavior and provider-fault ownership; add meaningful regressions
and explicit proof/correspondence scope, then rerun these same measurements.
The current linked guards are unchanged and do not prove either buffer change.
Further transmit/lifecycle profiling should precede changes to copy or erasure
semantics. No production optimization has yet been applied in this comparison.

For rustls/application users, measured per-write overhead supports a batching
experiment where latency permits:64-byte immediate writes give0.270GiB/s
versus2.849GiB/s at16KiB on the primary native path. This changes record/flush
semantics and does not promise the same gain for the original workload. No
internal rustls defect or unprofiled native optimization win is inferred.
Both libraries can next be compared with vectored/coalesced transport and
measured allocation/copy counts while retaining equivalent authentication.

[Separate PKI measurements](PKI_BENCHMARKS.md) put valid native policy near
25.46µs and the stricter adapter near26.22µs. That roughly3% difference does
not support blaming KeyUsage checks for the endpoint's large inbound gap.
Long/ambiguous paths and signature/parse allocations need separate profiling
before any webpki indexing/cache proposal. Compiler/provider/PKI trust,
no-revocation policy, incomplete server/mTLS and scoped Lean optimality remain
explicit; this experiment establishes no global TLS CPU optimum.
