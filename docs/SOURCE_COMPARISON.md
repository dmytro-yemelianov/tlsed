# Source review after authenticated benchmarks

Latest implementation: [aligned volatile secret wiping](SECRET_WIPING.md) fixes
the former large receive hotspot without removing secret erasure. AES12816KiB
receive now takes0.835x native pair time in a new paired experiment; lifecycle
remains1.119x. The earlier source/profile observations below retain their stage
context and do not imply the old1.538x receive deficit still exists.

Scope: the authenticated TLS1.3 client overlap and local endpoint-pair workloads,
followed by the strict PKI comparison. TLSed's server/OpenSSL endpoints and full v1
remain open. Native dependency inputs are rustls0.23.45 at
`2976d90fd1c2db6b518700dd101b714069cfcb17` and webpki0.103.15 at
`c14836d8de33c0ad0ac7dcb28fe9aade20831a4d`; exact registry-source snapshots,
commits and hashes are in [upstream-sources.json](../crates/tls-bench/results/2026-10-14-wire-clearing/upstream-sources.json).

| Measured observation | TLSed path | Native path / implication | Status |
|---|---|---|---|
| Original tiny-record receive gap | Full plaintext-tail clearing plus repeated full-loan read wipe | Different in-place/buffering design | Two measured, model-backed changes bring64B near native; [earlier experiment](READ_OPTIMIZATION.md) |
| Remaining public-wire byte loops | Successful immutable receive prefix; consumed sealed outgoing prefix | Outgoing chunk consumption advances offsets/drops chunks without prefix scrubbing | Replaced our public-wire zeroize with ordinary fill;16KiB AES128 TX/RX1.640x/1.475x; [paired evidence](WIRE_CLEARING.md) |
| Previous16KiB AES128 receive1.538x native time | Consumed secret plaintext still compiler-resistant wiped; separate wire-to-plain copy | Native ownership/retention and release behavior differ | Aligned volatile erasure implemented and measured; latest0.835x native; total copy contribution remains unisolated |
| Native-server realloc stacks during large TX | Shared native server is inside our endpoint-pair time | Deframer can shrink on empty then regrow across subsequent reads | Concrete bounded-capacity hypothesis below; no measured patch |
| Strict direct-root PKI costs~3% extra | x509 usage supplement and same webpki path/identity backend | Default native profile has intentional policy difference | [PKI result](PKI_BENCHMARKS.md); no isolated KU-dominance or upstream defect claim |

## Why the previous receive gap existed

The confirmed previous hotspot was our consumed-plaintext byte zeroize. In the final
16KiB AES128 receive diagnostic,805 of1639 main-thread samples are in its inlined
byte-store loop. This is a two-second window rather than calibrated whole-run CPU
time or an exact decomposition of the1.538x gap. Our read copies content to caller
output and zeroizes the consumed source. Native `ChunkVecBuffer::read/consume`
copies content, advances offsets and drops exhausted Vec chunks, without the
corresponding consumed-prefix zeroize. These paths have different memory-clearing
contracts even though authentication/PKI/provider controls are shared.

Native `GcmMessageDecrypter` decrypts its mutable inbound payload in place; our
`ProtectedReader::open` first copies immutable wire payload into separate plaintext
scratch. However, native buffered `take_received_plaintext` also converts the
payload to an owned Vec before `Reader` output. Thus in-place crypto does not
establish end-to-end zero-copy or a proven lower total copy count. Buffer ownership,
copy timing and specialized TLS-record key APIs need separate isolated measurements;
they are not assigned a measured share of the remaining gap.

[Native AEAD source](https://github.com/rustls/rustls/blob/2976d90fd1c2db6b518700dd101b714069cfcb17/rustls/src/crypto/aws_lc_rs/tls13.rs#L324),
[plaintext buffering](https://github.com/rustls/rustls/blob/2976d90fd1c2db6b518700dd101b714069cfcb17/rustls/src/common_state.rs#L483),
[our read](../crates/tls-client/src/lib.rs) and
[retained diagnostic](../crates/tls-bench/results/2026-10-14-wire-clearing/profile-after-rx.sample.txt)
provide the specific paths.16KiB transmit is already1.018x native pair time in
the latest paired run; there is no blanket claim that rustls wins every workload.

## Candidate improvement for rustls

Pinned `DeframerVecBuffer::prepare_read` computes a4KiB read increment and bounds
it by ordinary wire size or a64KiB handshake cap. When empty it resizes and
shrinks storage; subsequent partial reads grow it. This is consistent with
reserve/realloc stacks in our TLSed-pair TX diagnostic, which includes the native
server. A reviewable hypothesis is to retain ordinary-record capacity across
empty reads, preserving logical read windows and bounds, with separate oversized
handshake shrinking or idle hysteresis. [Pinned deframer source](https://github.com/rustls/rustls/blob/2976d90fd1c2db6b518700dd101b714069cfcb17/rustls/src/msgs/deframer/buffers.rs#L214).

Tradeoffs: retained memory per concurrent/idle connection, allocator rounding,
initialized bytes and decrypted-buffer retention. Measure allocations plus time
for large/small fragmented records and churn; keep overflow/cap/EOF tests. Change
the shared server symmetrically in both endpoint pairs. This is a source-backed
hypothesis, not an established speedup or a correctness bug.

`ChunkVecBuffer::consume` advances prefix usage and releases complete chunks;
`write_to` uses bounded vectored output. A chunk-reuse pool would separately
trade memory and partial-write complexity for allocation churn. Its outgoing
wire handling supported our public-byte distinction, but does not justify
weakening plaintext/provider clearing. [Pinned chunk source](https://github.com/rustls/rustls/blob/2976d90fd1c2db6b518700dd101b714069cfcb17/rustls/src/vecbuf.rs#L172).

## Candidate investigation for webpki and our adapter

The measured direct-root P256 path does not exercise ambiguous issuers. Use our
existing strict [bad-KU/good-issuer alternative regression](../crates/tls-pki/tests/pki.rs)
to benchmark unique-good, rejected-first and good-first chains at identical
roots/name/time/policy/caps. The pinned builder examines issuer candidates and
verifies complete candidate chains before invoking callbacks; retrying an
adapter-rejected chain can repeat work. Count candidate parses, full-chain
signature work, callback rejection and allocation/latency separately.
[Maintained path builder](https://github.com/rustls/webpki/blob/c14836d8de33c0ad0ac7dcb28fe9aade20831a4d/src/verify_cert.rs#L53).

Preserve native signature/path/name-constraint budgets and depth limits, alternative
path success, strict usage and exact error behavior. Candidate ordering, parse
reuse or early policy checks need proof that every accepted/rejected path retains
its semantics. No cache, upstream code change or measured win is established by
the current direct-root data; trust/time/name/revocation invalidation cannot be
assumed away. Revocation remains explicitly `NoRevocationData`.

The current TLSed changes are implemented and measured locally. The rustls and
webpki items are scoped follow-up experiments; no upstream patch or contact has
been made, and no comparative full-server/global optimality claim is made.
