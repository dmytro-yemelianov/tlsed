# Pre-landing baseline for the inner-scan audit

`prelanding.diff` turns the current tree back into the production state from before the
inner-scan and wipe landing. It touches two files:

- `crates/tls-core/src/protected.rs`: restores the `rposition` inner scan and the byte-wise
  tail wipe. The pre-landing file is `production_copy/tls-core/src/protected.rs` from the
  candidate run in `verification/results/2026-10-14-wipe-scan-candidates/`.
- `crates/tls-crypto-awslc/src/lib.rs`: restores the pre-landing error-path erasure. The
  reverse of the recorded candidate diff `awslc-tls-crypto-awslc-lib.diff` gives the same
  three hunks. The fourth hunk in that diff is a test module. HEAD's own test module stays
  in place, since it is test-only and does not change the benchmark binary.

The history cannot supply this baseline. The first commit that adds `protected.rs` already
contains the landed scan, so no pre-landing commit exists in git.

## Use

    git archive HEAD | tar -x -C "$DIR"
    patch -d "$DIR" -p1 < "$DIR/verification/experiments/inner-scan-audit/baseline/prelanding.diff"
    cargo build --manifest-path "$DIR/verification/experiments/inner-scan-audit/Cargo.toml" --release --bin tlsed-inner-scan-audit

Checked: the patched export matches the pre-landing `protected.rs` and `lib.rs` byte for
byte. On Linux arm64, the baseline gives padded records at 0.27× the current cost, and
long records at 1.00 (see `../../../../crates/tls-bench/results/2026-10-15-server-to-client-investigation/`).
