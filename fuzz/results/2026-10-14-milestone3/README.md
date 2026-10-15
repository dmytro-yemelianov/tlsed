# Transcript, labels and bounded server PKI fuzz evidence

Local Apple M5 / macOS27.2 / ARM64, pinned nightly-2026-09-17,
cargo-fuzz0.13.1 and libfuzzer-sys0.4.10. These are short component campaigns;
they do not establish complete TLS interoperability or independent security review.

## Transcript and labels

The final `transcript_labels` run passed **463,286 executions in11 seconds**
(10-second requested budget), seed3069676395, with reused local corpus and
maximum input4096. Exact command and environment are in
[run metadata](run-metadata.txt), with the [final raw log](transcript_labels.log).

The target uses actual AWS-LC SHA256/384 contexts, bounded message-operation
traces, snapshots, complete HRR rewrites and freeze/terminal/resource oracles.
It deliberately preloads hash contexts, checking that the corrected constructor
resets hidden history. Successful transcripts match one-shot encoded-history
hashes. Label encoding checks exact fields and output bounds, with maintained
HKDF-Expand and error-wipe comparisons. There is no secret-output logging.

[Source hashes](source-hashes.sha256) identify the final production/target source
and retained manifest/lock snapshots. Those snapshots are kept because the
independent PKI target subsequently changes the shared fuzz manifest/lock.
The binary hash is retained without committing a native executable. Earlier
first-oracle/pre-constructor-reset logs are historical evidence only.

## Coverage limits

The fuzzer is Rust ASan/libFuzzer. The
[native diagnostic](native-sanitizer-check.txt) shows no explicit C sanitizer
flags and zero undefined ASan/sanitizer references in the built AWS-LC archive.
AWS-LC native C/assembly instrumentation is therefore **not established**.
Do not treat Rust sanitizer passage as native cryptographic-provider coverage.
The HKDF test oracle shares the maintained backend; it checks orchestration,
not an independent primitive implementation. Published RFC known answers and
static independent SHA384 fixtures remain separate deterministic evidence.

Campaign length and generated-input sizes are limited. These runs supplement
the unit/integration corpus; no long-running campaign, complete handshake
state-space coverage, constant-time, PKIX or cryptographic-security proof follows.

## Bounded server PKI

The `bounded_server_pki` campaign passed **370,269 executions in11 seconds**
(10-second requested budget), seed71513, maximum input8192, starting from12
curated cases. See [raw log](bounded_server_pki.log),
[metadata](bounded_server_pki.metadata.txt), [source/fixture hashes](bounded_server_pki.source-hashes.sha256)
and [post-run verification](bounded_server_pki.postcheck.txt).

It exercises fixed trusted test roots, valid and invalid KU fixtures, alternative
same-key issuer paths, absent KU, malformed DER mutations/raw leaf/issuer input,
time/name variants, chain byte/count caps and CertificateVerify hash/scheme/
signature checks. Raw certificate bytes are bounded to4096, wrapper policy
allows four certificates/2048 bytes each/4096 aggregate, and local test
construction has at most five entries to exercise count rejection.

No input bytes become trust anchors. Three fixed self-signed negative fixtures
are explicitly trusted by the harness only to reach malformed KU parsing after
native validation; they are never accepted as valid leaf authentication. Named
bit0..8/canonical DER policy errors have concrete oracles alongside good-path
and alternate-path outcomes. Most mutated signed certificates fail native
validation before the KU parser, so this is not unrestricted inner-parser or
all-PKIX state-space coverage. The fixed curated seeds are retained separately.

The [PKI native diagnostic](bounded_server_pki.native-sanitizer-check.txt)
also finds zero undefined ASan/sanitizer references in the built AWS-LC archives.
Native C/assembly coverage remains unestablished. The wrapper, webpki and
maintained Rust ASN.1 parser participate in this Rust sanitizer build;
cryptographic security, constant-time behavior and full RFC conformity are not
established by a short crash-free run.

Reproduce the PKI campaign from the retained initial seeds:

```sh
mkdir -p fuzz/corpus/bounded_server_pki
cp fuzz/results/2026-10-14-milestone3/pki-seeds/seed-* fuzz/corpus/bounded_server_pki/
cargo +nightly-2026-09-17 fuzz run bounded_server_pki -- -max_total_time=10 -max_len=8192 -seed=71513
```

Existing generated corpus, scheduling and instrumentation may change execution
counts. The retained observed count belongs to the exact recorded local run.
