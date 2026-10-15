# Exact isolated native logging reproduction

This parses the root-launched CC_ENABLE_DEBUG_OUTPUT=1 isolated clone build.
It is new reproduction evidence, not direct historical baseline argv capture.
No build, profile or benchmark was launched by the parsing agent.

The clone archive before logging, its current rebuilt archive, and both stable
production release archives have identical SHA256:
`3ca5aff32f48eb44b7ea52288f786ed9a7c1c14ae50d22125473b1e551c4b8ab`.
See native-archive-comparison.json for exact paths/hash comparison. Thus this
logging reproduction produced matching native bytes. It does not retroactively
prove the historical command lines were directly observed.

native-commands.json retains all437 running-command records, complete argv/raw
command, original log line, source and classified flags/defines. Classification:
250 crypto C,115 crypto assembly,6 jitterentropy,19 compiler probes and47
archive/tool-query commands. This counts log records, not unique source files or
successful cryptographic calls. native-command-sourcehashes.json fingerprints
available exact input sources; removed temporary probes are marked unavailable.
native-flag-sets.json retains complete representative commands and distinct
flag/define sets; logging-build.log remains authoritative.

## Actual representative main crypto flags and defines

bcm.c (log1279) and AES-GCM8x assembly (log1613) use:
-O3 -ffunction-sections -fdata-sections -fPIC
--target=arm64-apple-macosx -mmacosx-version-min=27.0 -std=c11
-Wall -Wextra -Wno-unused-parameter -pthread
-ffile-prefix-map=<exact registry aws-lc-sys0.46.0 path>=
-Wno-overriding-option; seven explicit include paths are retained in argv.
Defines: BORINGSSL_IMPLEMENTATION=1, BORINGSSL_PREFIX=aws_lc_0_46_0,
_DARWIN_C_SOURCE=1, AWS_LC_STDALIGN_AVAILABLE=1,
AWS_LC_BUILTIN_SWAP_SUPPORTED=1, MY_ASSEMBLER_SUPPORTS_NEON_SHA3_EXTENSION=1.
These are observed flags/defines of this reproduction, not inferred defaults.
NDEBUG is not a -D argument in these representative commands. This observation
alone does not claim every assertion or target-header conditional is enabled.

## Jitterentropy and architecture-specific distinctions

jitterentropy-base.c (log1030) has initial-O3 but later-O0: effective optimization
is O0, not O3. It also uses fwrapv, ssp-buffer-size4, hidden visibility,
cast-align/missing-field/shadow/switch warnings, pedantic/Wconversion, forced
boringssl_prefix_symbols.h, path stripping and AWSLC=1/Darwin/prefix defines.
The path-stripping sanitizer option does not enable sanitizer instrumentation.

The only logged -march=armv8.4-a+sha3 command is compiler feature probe
neon_sha3_check.c at722. Do not assign it to the complete crypto archive.
The architecture-specific s2n SHA3 assembly representative at928 uses ordinary
main flags plus S2N_BN_HIDE_SYMBOLS=1 and forced prefix-symbol assembly header;
actual architecture instructions are in the generated .S source. Compiled
assembly source availability plus runtime capability checks remain separate
from Rust target-feature or target-cpu overrides.

## Complete representative commands

crypto_c, logging-build.log:1279:

```text
"cc" "-O3" "-ffunction-sections" "-fdata-sections" "-fPIC" "--target=arm64-apple-macosx" "-mmacosx-version-min=27.0" "-std=c11" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/generated-include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/s2n-bignum/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/s2n-bignum/s2n-bignum-imported/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/jitterentropy/jitterentropy-library" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/jitterentropy/jitterentropy-library/src" "-Wall" "-Wextra" "-Wno-unused-parameter" "-pthread" "-ffile-prefix-map=/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0=" "-Wno-overriding-option" "-DBORINGSSL_IMPLEMENTATION=1" "-DBORINGSSL_PREFIX=aws_lc_0_46_0" "-D_DARWIN_C_SOURCE=1" "-DAWS_LC_STDALIGN_AVAILABLE=1" "-DAWS_LC_BUILTIN_SWAP_SUPPORTED=1" "-DMY_ASSEMBLER_SUPPORTS_NEON_SHA3_EXTENSION=1" "-o" "/Users/dmytro/.superset/worktrees/tlsed/gregarious-arthropod-d698612e/target/cpu-audit/workspace/target/release/build/aws-lc-sys-1b4f30d4f471bf45/out/f8e4fd781484bd36-bcm.o" "-c" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/crypto/fipsmodule/bcm.c"
```

crypto_assembly, logging-build.log:1613:

```text
"cc" "-O3" "-ffunction-sections" "-fdata-sections" "-fPIC" "--target=arm64-apple-macosx" "-mmacosx-version-min=27.0" "-std=c11" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/generated-include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/s2n-bignum/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/s2n-bignum/s2n-bignum-imported/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/jitterentropy/jitterentropy-library" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/jitterentropy/jitterentropy-library/src" "-Wall" "-Wextra" "-Wno-unused-parameter" "-pthread" "-ffile-prefix-map=/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0=" "-Wno-overriding-option" "-DBORINGSSL_IMPLEMENTATION=1" "-DBORINGSSL_PREFIX=aws_lc_0_46_0" "-D_DARWIN_C_SOURCE=1" "-DAWS_LC_STDALIGN_AVAILABLE=1" "-DAWS_LC_BUILTIN_SWAP_SUPPORTED=1" "-DMY_ASSEMBLER_SUPPORTS_NEON_SHA3_EXTENSION=1" "-o" "/Users/dmytro/.superset/worktrees/tlsed/gregarious-arthropod-d698612e/target/cpu-audit/workspace/target/release/build/aws-lc-sys-1b4f30d4f471bf45/out/c4391ac3c46825d6-aesv8-gcm-armv8-unroll8.o" "-c" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/generated-src/ios-aarch64/crypto/fipsmodule/aesv8-gcm-armv8-unroll8.S"
```

jitterentropy, logging-build.log:1030:

```text
"cc" "-O3" "-ffunction-sections" "-fdata-sections" "-fPIC" "--target=arm64-apple-macosx" "-mmacosx-version-min=27.0" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/generated-include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/s2n-bignum/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/s2n-bignum/s2n-bignum-imported/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/jitterentropy/jitterentropy-library" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/jitterentropy/jitterentropy-library/src" "-Wall" "-Wextra" "-fwrapv" "--param" "ssp-buffer-size=4" "-fvisibility=hidden" "-Wcast-align" "-Wmissing-field-initializers" "-Wshadow" "-Wswitch-enum" "-Wextra" "-Wall" "-pedantic" "-O0" "-fwrapv" "-Wconversion" "-ffile-prefix-map=/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0=" "-fsanitize-undefined-strip-path-components=-1" "--include=/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/generated-include/openssl/boringssl_prefix_symbols.h" "-DBORINGSSL_IMPLEMENTATION=1" "-DBORINGSSL_PREFIX=aws_lc_0_46_0" "-DAWSLC=1" "-D_DARWIN_C_SOURCE=1" "-o" "/Users/dmytro/.superset/worktrees/tlsed/gregarious-arthropod-d698612e/target/cpu-audit/workspace/target/release/build/aws-lc-sys-1b4f30d4f471bf45/out/2d40dbbd793ef942-jitterentropy-base.o" "-c" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/jitterentropy/jitterentropy-library/src/jitterentropy-base.c"
```

sha3_probe, logging-build.log:722:

```text
"cc" "-O3" "-ffunction-sections" "-fdata-sections" "-fPIC" "--target=arm64-apple-macosx" "-mmacosx-version-min=27.0" "-Werror" "-Wall" "-Wextra" "-march=armv8.4-a+sha3" "-Wno-unused-parameter" "-o" "/Users/dmytro/.superset/worktrees/tlsed/gregarious-arthropod-d698612e/target/cpu-audit/workspace/target/release/build/aws-lc-sys-1b4f30d4f471bf45/out/out-neon_sha3_check/7dfda64fdf5a526c-neon_sha3_check.o" "-c" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/tests/compiler_features_tests/neon_sha3_check.c"
```

architecture_specific, logging-build.log:928:

```text
"cc" "-O3" "-ffunction-sections" "-fdata-sections" "-fPIC" "--target=arm64-apple-macosx" "-mmacosx-version-min=27.0" "-std=c11" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/generated-include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/s2n-bignum/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/s2n-bignum/s2n-bignum-imported/include" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/jitterentropy/jitterentropy-library" "-I" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/jitterentropy/jitterentropy-library/src" "-Wall" "-Wextra" "-Wno-unused-parameter" "-pthread" "-ffile-prefix-map=/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0=" "-Wno-overriding-option" "--include=/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/generated-include/openssl/boringssl_prefix_symbols_asm.h" "-DBORINGSSL_IMPLEMENTATION=1" "-DBORINGSSL_PREFIX=aws_lc_0_46_0" "-D_DARWIN_C_SOURCE=1" "-DAWS_LC_STDALIGN_AVAILABLE=1" "-DAWS_LC_BUILTIN_SWAP_SUPPORTED=1" "-DMY_ASSEMBLER_SUPPORTS_NEON_SHA3_EXTENSION=1" "-DS2N_BN_HIDE_SYMBOLS=1" "-o" "/Users/dmytro/.superset/worktrees/tlsed/gregarious-arthropod-d698612e/target/cpu-audit/workspace/target/release/build/aws-lc-sys-1b4f30d4f471bf45/out/ac9a06e0f1f9cd7d-sha3_keccak_f1600_alt.o" "-c" "/Users/dmytro/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.46.0/aws-lc/third_party/s2n-bignum/s2n-bignum-imported/arm/sha3/sha3_keccak_f1600_alt.S"
```
