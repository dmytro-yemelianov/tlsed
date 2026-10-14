# Read-only performance constraints/native backend audit

Observed2026-10-14; no builds, profiling or benchmarks performed for this audit.
Exact evidence hashes are in `target/audit/native-source-sha256.txt`. This is
scratch evidence, not an edited production/report/verification artifact.

## Constraints and API

- Workspace Cargo.toml declares Rust1.98/edition2024, toolchain pins1.98.1,
  unsafe_code=forbid, release thin LTO/codegen-units1. Cargo release fingerprints
  for client_compare and native dependencies contain rustflags=[]: no explicit
  target-cpu=native or Rust target-feature override was recorded.
- tls-core/src/lib.rs:10 and tls-crypto/src/lib.rs:3 are no_std. tls-client uses
  std::sync::Arc, Vec-backed configuration and maintained PKI; tls-pki and
  tls-crypto-awslc are std components. Pinned aws-lc-rs/src/lib.rs:214 explicitly
  says it requires std and does not support no_std. A no_std foundation is not
  evidence of a no_std complete client. Default-features=false on bytemuck and
  zeroize does not change that endpoint requirement.
- rustls0.23.45 declares MSRV1.71; aws-lc-rs1.18.2 and aws-lc-sys0.46.0 declare
  MSRV1.71.0. Those are dependency claims, not a tested lower workspace MSRV.
  Rustls itself forbids unsafe_code at src/lib.rs:332. Unsafe native FFI and
  bytemuck's maintained safe casting implementation remain external trust.
- Current client API still borrows four bounded caller buffers, takes explicit
  identity/time and Arc immutable configuration, exposes consumed/produced
  backpressure and serial mutable state. No socket/runtime API was introduced.
  Private zeroize_secret uses pod_align_to_mut::<u8,u128>, zeroize of each
  partition and no content copies or custom unsafe. General u128 volatile
  hardware lowering is target-dependent, not guaranteed one instruction.

## Actual native artifact evidence and compiler-limit qualification

Both existing release native archives are byte-identical:
`target/release/build/aws-lc-sys-{1b4f30d4f471bf45,486c12369d913e1d}/out/libaws_lc_0_46_0_crypto.a`
SHA256 `3ca5aff32f48eb44b7ea52288f786ed9a7c1c14ae50d22125473b1e551c4b8ab`.
The two retained builds differ in Cargo feature metadata (prebuilt-nasm), not
these native archive bytes. ARM64 uses generated assembly sources; the NASM
feature is not evidence of x86 code executing here.

Retained build outputs explicitly record CC builder, aarch64-apple-darwin,
symbol prefix aws_lc_0_46_0, successful c11/stdalign/builtin_swap/neon_sha3
checks, accepted -ffile-prefix-map, CFLAGS/host/target overrides=None and native
link search path. Current selected compiler reports Apple clang21.0.0
(clang-2100.3.34.2), arm64-apple-darwin27.2.0, consistent with retained environment.
The historical complete C argv/compiler-version line was NOT retained in the
CC output. Do not invent a complete historical compiler command from this.

Pinned builder/cc_builder.rs source reconstructs applicable options: c11 from
successful probe; -Wno-unused-parameter and -pthread; _DARWIN_C_SOURCE=1;
BORINGSSL_IMPLEMENTATION=1 and BORINGSSL_PREFIX=aws_lc_0_46_0; includes for
prefix/public/native headers and s2n-bignum; AWS_LC_STDALIGN_AVAILABLE=1,
AWS_LC_BUILTIN_SWAP_SUPPORTED=1 and MY_ASSEMBLER_SUPPORTS_NEON_SHA3_EXTENSION=1
from the recorded successful checks. Release generic C optimization follows
Cargo/cc defaults (-O3 for this release profile), inferred from build policy,
not a captured argv. Jitter-entropy source is deliberately built separately at
-O0; do not describe every native object as O3. The probe's
-march=armv8.4-a+sha3 is a probe/specific-source feature, not evidence that every
C object was built with that target flag. No OPENSSL_NO_ASM build: compiled
ARM assembly objects and samples establish assembly execution. No FIPS feature
in the recorded fingerprints; fipsmodule source paths do not imply certification.

Artifact output hashes:
-1b4f30d4f471bf45/output:8ec0153d6a7ac91c9e70c78cdcbcd8f2fdbcb346be343b6c96a12520bdd7535b.
-486c12369d913e1d/output:b84b9ae286f69d4b2dc554623164f5f2f8a08dfc4ed190c0a1bf80573ac3ee04.

## Runtime selection and observed vs predicted paths

The crate's .cargo_vcs_info identifies aws-lc-rs commit
9df497501436596d4da77109217806b3af7f56cb. Official GitHub submodule metadata,
retained in target/audit/aws-lc-submodule.json, pins vendored AWS-LC to
fa9bc8d6f7cfb2cf849b247fb06bbbfc41ecc9d6.

Pinned crypto/fipsmodule/cpucap/cpu_aarch64_apple.c:51 initializes static
NEON/AES/PMULL/SHA1/SHA256 capabilities, queries SHA512/SHA3/DIT, recognizes
Apple M brand, and supports OPENSSL_armcap override. Read-only sysctl currently
reports AES=1, PMULL=1, SHA256=1, SHA512=1, armv8_2_sha3=1, DIT=1 and
machdep.cpu.brand_string=Apple M5. This identifies host capability, not a
per-process traced armcap value. An environment override would need separate
capture when running diagnostics.

- AES/GCM: cpucap/internal.h:242 selects8x when SHA3 plus Apple-M/eligible
  Neoverse. modes/gcm.c:119/:156 chooses8x for length>=256, otherwise the
  smaller kernel. Retained wire-clearing TX sample lines39–45 directly observes
  EVP_AEAD_CTX_open→aead_aes_gcm_open_gather→CRYPTO_gcm128_decrypt_ctr32→
  aesv8_gcm_8x_dec_128. Both peers already use AES/PMULL assembly. The sample's
  native-server work is inside the whole pair, not solely TLSed client overhead.
- ChaCha20/Poly1305: cipher_extra/internal.h:142 checks NEON on AArch64;
  e_chacha20poly1305.c:196/:284 routes to combined assembly seal/open.
  Generated chacha-armv8 and chacha20_poly1305_armv8 objects are present. This
  establishes compiled availability and predicted native dispatch on this host;
  the retained AES-focused sample is not proof of a sampled ChaCha call.
- SHA256/SHA384: sha/internal.h:158/:165 capability tests select ARM SHA256 or
  SHA512 support; sha256.c:337 and sha512.c:634 call hardware block functions.
  SHA384 shares SHA512 compression. Apple generated assembly contains both
  nohw/hw functions. Host features predict HW selection with default armcap;
  no retained per-call SHA samples were found by this audit.

## Relevant own-code opportunities and portability tradeoffs

TLSed AwsLcKey and rustls crypto/aws_lc_rs/tls13.rs both use maintained
LessSafeKey::open_in_place; TLSed seal_in_place_separate_tag also delegates
native AEAD. Reimplementing AES/PMULL/ChaCha/SHA in Rust intrinsics would
duplicate a backend already using hardware, expand crypto trust/proof scope,
and require architecture/features/fallback handling. Rust std::arch APIs are
architecture dependent, and operations requiring unsafe do not fit workspace
policy; features can make some intrinsic calls safe, but that needs exact API
and target review, not a blanket exception.

The measured distinctions remain buffer work, copies, allocation and orchestration:
core ProtectedReader copies received ciphertext into separate plaintext before
native in-place authentication; client owns fixed buffers and erases consumed
secret ranges. Rustls deframer decrypts in its receive storage and copies accepted
plaintext into its delivery buffer; its growth/shrink/chunk lifecycle differs.
Changes here must retain unauthenticated-release prevention, exact partial I/O,
nonce ordering, guard/loan boundaries and failure/Drop erasure. Current ordinary
public-wire fill and maintained aligned volatile secret wipe separate two
contracts without discarding either. Data-dependent checks/PKI/native crypto
are not globally constant-time proved.

Investigate post-optimization samples before pursuing more specialization.
No per-target native flag, aligned-word width, retained capacity, cache or
intrinsic candidate is a portable speed guarantee. Any compiler/native change
must be applied symmetrically to the shared-provider comparison and preserve
fallback capability; explicit native CPU tuning narrows deployable CPU scope.

Primary sources:
https://raw.githubusercontent.com/aws/aws-lc-rs/v1.18.2/aws-lc-rs/Cargo.toml
https://raw.githubusercontent.com/rustls/rustls/v/0.23.45/rustls/Cargo.toml
https://raw.githubusercontent.com/aws/aws-lc/fa9bc8d6f7cfb2cf849b247fb06bbbfc41ecc9d6/crypto/fipsmodule/cpucap/cpu_aarch64_apple.c
https://raw.githubusercontent.com/aws/aws-lc/fa9bc8d6f7cfb2cf849b247fb06bbbfc41ecc9d6/crypto/fipsmodule/modes/gcm.c
https://doc.rust-lang.org/std/arch/index.html


## Exact logging reproduction added

The root subsequently rebuilt the isolated clone with CC_ENABLE_DEBUG_OUTPUT=1.
`native-flags-report.md`, `native-commands.json`, `native-flag-sets.json` and
`native-command-sourcehashes.json` now retain actual complete compiler/assembly
commands and available source hashes. `native-archive-comparison.json` confirms
the clone-before, rebuilt-clone and two stable production archives all match
SHA2563ca5aff32f48eb44b7ea52288f786ed9a7c1c14ae50d22125473b1e551c4b8ab.
This supersedes the absence of exact flags for a reproduction: observed main
crypto uses O3, targetarm64-apple-macosx, minimum macOS27.0, C11/PIC/section
flags and recorded defines. Jitterentropy ends with O0; the sole explicit
marcharmv8.4-a+sha3 is a probe, not a universal flag. This is matching native-byte
reproduction evidence, not direct observation of historicalbaseline argv.
