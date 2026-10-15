#!/usr/bin/env python3
"""Measure candidate replacements for the inner scan and the record wipes.

Candidates, each applied to a copy of the crate, never to production:
  wipe    tls-core protected.rs: aligned u128 wipes for the failure and tail erasures.
  scan    tls-core protected.rs: last_nonzero skips zero blocks instead of a bytewise rposition.
  awslc   tls-crypto-awslc lib.rs: aligned u128 wipe for the ciphertext erased on a failed
          open_in_place or seal_in_place.

Subcommands:
  build         generate every variant under target/inner-scan-audit/variants/, apply its edits,
                run its crate test suites (including new equivalence tests), and build its bench.
  kernels       six repeats of candidate_kernels: production expressions vs candidates, isolated.
  e2e           six repeats of each variant's bench, plus sampling profiles of the full candidate.
  client-tests  tls-client suite on production and on the full candidate's workspace copy.

Each variant has its own CARGO_TARGET_DIR: copies of one package share a metadata hash, so a
shared target dir lets one variant's artifacts stand in for another's.
"""
import argparse
import csv
import difflib
import filecmp
import hashlib
import json
import os
import re
import shutil
import statistics
import subprocess
import time
from collections import defaultdict
from pathlib import Path

root = Path(__file__).resolve().parents[3]
experiment = Path(__file__).resolve().parent
target = root / 'target/inner-scan-audit'
variants_root = target / 'variants'
results = root / 'verification/results/2026-10-14-wipe-scan-candidates'
PRODUCTION_PROTECTED = root / 'crates/tls-core/src/protected.rs'
PRODUCTION_AWSLC = root / 'crates/tls-crypto-awslc/src/lib.rs'
REPEATS = 6
E2E_REPEATS = 10
IGNORE = shutil.ignore_patterns('target')

# name -> (wipe, scan, awslc)
VARIANTS = {
    'production_copy': (False, False, False),
    'wipe': (True, False, False),
    'scan': (False, True, False),
    'wipe_scan': (True, True, False),
    'awslc': (False, False, True),
    'wipe_scan_awslc': (True, True, True),
}
FULL = 'wipe_scan_awslc'

WIPE_HELPER = '''/// Erase caller bytes with aligned u128 stores, as `Reassembler::drop` does.
fn wipe(bytes: &mut [u8]) {
    let (head, words, tail) = bytemuck::pod_align_to_mut::<u8, u128>(bytes);
    head.zeroize();
    words.zeroize();
    tail.zeroize();
}

'''

SCAN_HELPER = '''/// Index of the last nonzero byte. Zero blocks are skipped from the end, so long
/// padding costs one comparison per block. Same result as `rposition(|&b| b != 0)`.
const SCAN_BLOCK: usize = {block};

fn last_nonzero(bytes: &[u8]) -> Option<usize> {{
    let mut end = bytes.len();
    while end >= SCAN_BLOCK && bytes[end - SCAN_BLOCK..end] == [0u8; SCAN_BLOCK] {{
        end -= SCAN_BLOCK;
    }}
    bytes[..end].iter().rposition(|&byte| byte != 0)
}}

'''

TEST_HEADER = '''
#[cfg(test)]
mod candidate_equivalence {
    use super::*;
'''

TEST_SCAN = '''
    #[test]
    fn last_nonzero_matches_rposition() {
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut bytes = [0u8; 16_385];
        for len in (0..=300).chain([1_023, 1_024, 4_095, 16_383, 16_384, 16_385]) {
            assert_eq!(last_nonzero(&bytes[..len]), None, "zeros len={len}");
            let step = if len <= 300 { 1 } else { 97 };
            for pos in (0..len).step_by(step) {
                bytes[pos] = 1;
                assert_eq!(
                    last_nonzero(&bytes[..len]),
                    bytes[..len].iter().rposition(|&b| b != 0),
                    "single len={len} pos={pos}"
                );
                bytes[pos] = 0;
            }
            for _ in 0..64 {
                bytes[..len].fill(0);
                if len > 0 {
                    for _ in 0..(next() % 8) {
                        let pos = (next() as usize) % len;
                        bytes[pos] = (next() as u8) | 1;
                    }
                }
                assert_eq!(
                    last_nonzero(&bytes[..len]),
                    bytes[..len].iter().rposition(|&b| b != 0),
                    "random len={len}"
                );
            }
            bytes[..len].fill(0);
        }
    }
'''

TEST_WIPE = '''
    #[test]
    fn wipe_zeroes_exact_range() {
        for offset in 0..32 {
            for size in (0..=257).chain([1_023, 1_024, 1_025, 16_383, 16_384, 16_385]) {
                let start = 16 + offset;
                let mut data = [0xa5u8; 16_512];
                let mut expected = [0xa5u8; 16_512];
                expected[start..start + size].fill(0);
                wipe(&mut data[start..start + size]);
                assert!(data == expected, "size={size} offset={offset}");
            }
        }
    }
'''

FAIL_WIPE_OLD = "        output.zeroize();\n        self.iv.zeroize();"
FAIL_WIPE_NEW = "        wipe(output);\n        self.iv.zeroize();"
TAIL_WIPE_OLD = "        output[content_len..].zeroize();"
TAIL_WIPE_NEW = "        wipe(&mut output[content_len..]);"
SCAN_OLD = (
    "    let index = inner\n"
    "        .iter()\n"
    "        .rposition(|&byte| byte != 0)\n"
    "        .ok_or(ProtectedError::InvalidInner)?;"
)
SCAN_NEW = "    let index = last_nonzero(inner).ok_or(ProtectedError::InvalidInner)?;"
DECODE_ANCHOR = "fn decode_inner(inner: &[u8], limit: usize)"

AWSLC_HELPER = WIPE_HELPER
AWSLC_OLD = "        if result.is_err() {\n            buffer.zeroize();\n        }"
AWSLC_NEW = "        if result.is_err() {\n            wipe(buffer);\n        }"
AWSLC_ANCHOR = "impl AeadKey for AwsLcKey {"

# The provider wipe covers both the seal and open error paths: two identical blocks.
TEST_AWSLC = '''
#[cfg(test)]
mod candidate_wipe {
    use super::*;

    #[test]
    fn failed_seal_and_open_wipe_the_whole_buffer() {
        let key = AwsLcProvider
            .aead_key(CipherSuite::Aes128GcmSha256, &[7; 16])
            .unwrap();
        let nonce = [0u8; NONCE_LEN];
        let aad = b"header";
        for total in [1usize, 15, 16, 17, 1_041, 16_401] {
            // Plaintext longer than the buffer: seal fails and wipes everything.
            let mut small = vec![0xA5u8; total];
            assert!(key.seal_in_place(&nonce, aad, &mut small, total + 1).is_err());
            assert!(small.iter().all(|&b| b == 0), "seal total={total}");
            if total < TAG_LEN {
                // Too short to hold a tag: open fails and wipes everything.
                let mut short = vec![0x5Au8; total];
                assert!(key.open_in_place(&nonce, aad, &mut short).is_err());
                assert!(short.iter().all(|&b| b == 0), "short open total={total}");
            } else {
                // Valid record with a flipped tag: open fails and wipes everything.
                let mut record = vec![0x5Au8; total];
                key.seal_in_place(&nonce, aad, &mut record, total - TAG_LEN).unwrap();
                let last = record.len() - 1;
                record[last] ^= 1;
                assert!(key.open_in_place(&nonce, aad, &mut record).is_err());
                assert!(record.iter().all(|&b| b == 0), "tag open total={total}");
            }
        }
    }
}
'''

# Manifest rewrites that make a copied crate build standalone under target/.
COMMON_REWRITES = [
    ("\nversion.workspace = true", '\nversion = "0.1.0"'),
    ("\nedition.workspace = true", '\nedition = "2024"'),
    ("\nrust-version.workspace = true", '\nrust-version = "1.98"'),
    ("\nlicense.workspace = true", '\nlicense = "MIT OR Apache-2.0"'),
    ('path = "../tls-crypto"', f'path = "{root}/crates/tls-crypto"'),
    ("[lints]\nworkspace = true", '[lints.rust]\nunsafe_code = "forbid"'),
]
AWSLC_BYTEMUCK = ("\n[dependencies]\n",
                  '\n[dependencies]\nbytemuck = { version = "=1.25.2", default-features = false }\n')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def host():
    def text(command):
        return subprocess.run(command, capture_output=True, text=True, check=True).stdout.strip()

    return {
        'cpu': text(['sysctl', '-n', 'machdep.cpu.brand_string']),
        'macos': text(['sw_vers', '-productVersion']),
        'rustc': text(['rustc', '--version']),
        'power': text(['pmset', '-g', 'batt']).splitlines()[0],
    }


def manifest_update(section, data):
    path = results / 'manifest.json'
    manifest = json.loads(path.read_text()) if path.exists() else {}
    manifest['host'] = host()
    manifest[section] = data
    path.write_text(json.dumps(manifest, indent=2) + '\n')


def variant_binary(name):
    return variants_root / name / 'target/release' / f'tlsed-inner-scan-audit-{name}'


def replace_exactly(text, old, new, count, label):
    found = text.count(old)
    assert found == count, f'{label}: {old[:40]!r} found {found}, expected {count}'
    return text.replace(old, new)


def rewrite_manifest(path, label, extra=()):
    text = path.read_text()
    for old, new in list(COMMON_REWRITES) + list(extra):
        text = replace_exactly(text, old, new, 1, f'{label} manifest')
    path.write_text(text + '\n[workspace]\n')


def build_variant(name, block):
    wipe, scan, awslc = VARIANTS[name]
    dst = variants_root / name
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)

    # tls-crypto-awslc: a copy only when the candidate touches it, otherwise the production path.
    if awslc:
        awslc_dir = dst / 'tls-crypto-awslc'
        shutil.copytree(root / 'crates/tls-crypto-awslc', awslc_dir, ignore=IGNORE)
        rewrite_manifest(awslc_dir / 'Cargo.toml', f'{name}/awslc', extra=[AWSLC_BYTEMUCK])
        shutil.copy(root / 'Cargo.lock', awslc_dir / 'Cargo.lock')
        awslc_source = awslc_dir / 'src/lib.rs'
        original = awslc_source.read_text()
        text = replace_exactly(original, AWSLC_OLD, AWSLC_NEW, 2, f'{name}/awslc')
        text = replace_exactly(text, AWSLC_ANCHOR, AWSLC_HELPER + AWSLC_ANCHOR, 1, f'{name}/awslc')
        text = text.rstrip('\n') + '\n' + TEST_AWSLC
        awslc_source.write_text(text)
        (results / 'variants').mkdir(parents=True, exist_ok=True)
        (results / 'variants' / f'{name}-tls-crypto-awslc-lib.diff').write_text(''.join(difflib.unified_diff(
            original.splitlines(True), text.splitlines(True),
            'production/crates/tls-crypto-awslc/src/lib.rs', f'{name}/src/lib.rs')))
    else:
        awslc_dir = root / 'crates/tls-crypto-awslc'

    # tls-core: its dev-dependency on the provider follows the variant's provider copy.
    core = dst / 'tls-core'
    shutil.copytree(root / 'crates/tls-core', core, ignore=IGNORE)
    rewrite_manifest(core / 'Cargo.toml', f'{name}/core',
                     extra=[('path = "../tls-crypto-awslc"', f'path = "{awslc_dir}"')])
    shutil.copy(root / 'Cargo.lock', core / 'Cargo.lock')

    source = core / 'src/protected.rs'
    original = source.read_text()
    edits, helpers, tests = [], '', ''
    if wipe:
        edits += [(FAIL_WIPE_OLD, FAIL_WIPE_NEW, 2), (TAIL_WIPE_OLD, TAIL_WIPE_NEW, 1)]
        helpers += WIPE_HELPER
        tests += TEST_WIPE
    if scan:
        edits += [(SCAN_OLD, SCAN_NEW, 1)]
        helpers += SCAN_HELPER.format(block=block)
        tests += TEST_SCAN
    text = original
    for old, new, count in edits:
        text = replace_exactly(text, old, new, count, f'{name}/core')
    if helpers:
        text = replace_exactly(text, DECODE_ANCHOR, helpers + DECODE_ANCHOR, 1, f'{name}/core')
    if tests:
        text = text.rstrip('\n') + '\n' + TEST_HEADER + tests + '}\n'
    source.write_text(text)
    (results / 'variants').mkdir(parents=True, exist_ok=True)
    (results / 'variants' / f'{name}-protected.diff').write_text(''.join(difflib.unified_diff(
        original.splitlines(True), text.splitlines(True),
        'production/crates/tls-core/src/protected.rs', f'{name}/src/protected.rs')))
    if not edits:
        assert filecmp.cmp(source, PRODUCTION_PROTECTED, shallow=False), 'copy differs from production'
    if not awslc:
        assert filecmp.cmp(awslc_dir / 'src/lib.rs', PRODUCTION_AWSLC, shallow=False)

    exp = dst / 'experiment'
    (exp / 'src').mkdir(parents=True)
    shutil.copy(experiment / 'src/main.rs', exp / 'src/main.rs')
    toml = (experiment / 'Cargo.toml').read_text()
    for old, new in [
        ('name = "tlsed-inner-scan-audit"', f'name = "tlsed-inner-scan-audit-{name}"'),
        ('path = "../../../crates/tls-core"', f'path = "{core}"'),
        ('path = "../../../crates/tls-crypto"', f'path = "{root}/crates/tls-crypto"'),
        ('path = "../../../crates/tls-crypto-awslc"', f'path = "{awslc_dir}"'),
    ]:
        toml = replace_exactly(toml, old, new, 1, f'{name}/experiment')
    (exp / 'Cargo.toml').write_text(toml)
    shutil.copy(experiment / 'Cargo.lock', exp / 'Cargo.lock')

    variant_env = {**os.environ, 'CARGO_TARGET_DIR': str(dst / 'target')}
    tests_dir = results / 'tests'
    tests_dir.mkdir(parents=True, exist_ok=True)
    suites = {'core': core}
    if awslc:
        suites['awslc'] = awslc_dir
    counts = {}
    for suite, crate_dir in suites.items():
        test = subprocess.run(['cargo', 'test', '--offline'], cwd=crate_dir, env=variant_env,
                              capture_output=True, text=True)
        log = test.stdout + test.stderr
        log_name = f'{name}-tls-core.log' if suite == 'core' else f'{name}-tls-crypto-awslc.log'
        (tests_dir / log_name).write_text(log)
        if test.returncode != 0:
            raise SystemExit(f'{name}: {suite} tests failed (see {tests_dir / log_name})')
        counts[suite] = {
            'passed': sum(int(m.group(1)) for m in re.finditer(r'test result: ok\. (\d+) passed', log)),
            'failed': sum(int(m.group(2)) for m in re.finditer(
                r'test result: FAILED\. (\d+) passed; (\d+) failed', log)),
        }

    build = subprocess.run(['cargo', 'build', '--release', '--offline'], cwd=exp, env=variant_env,
                           capture_output=True, text=True)
    if build.returncode != 0:
        raise SystemExit(f'{name}: build failed\n{build.stderr[-2000:]}')
    binary = variant_binary(name)
    summary = {
        'block': block if scan else None,
        'wipe': wipe, 'scan': scan, 'awslc': awslc,
        'tests': counts,
        'protected_rs_sha256': sha(source),
        'awslc_lib_rs_sha256': sha(awslc_dir / 'src/lib.rs'),
        'binary': str(binary.relative_to(root)),
        'binary_sha256': sha(binary),
    }
    print(f'{name}: tests {counts}, binary built', flush=True)
    return summary


def cmd_build(args):
    variants_root.mkdir(parents=True, exist_ok=True)
    summaries = {name: build_variant(name, args.block) for name in VARIANTS}
    manifest_update('build', {'block': args.block, 'variants': summaries,
                              'production_protected_rs_sha256': sha(PRODUCTION_PROTECTED),
                              'production_awslc_lib_rs_sha256': sha(PRODUCTION_AWSLC)})


def cmd_kernels(args):
    binary = target / 'release/candidate_kernels'
    out = results / 'kernels'
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    commands = []
    for repeat in range(REPEATS):
        command = [str(binary), str(repeat)]
        before = os.getloadavg()
        with (out / f'repeat-{repeat}.csv').open('w') as stream:
            subprocess.run(command, cwd=root, stdout=stream, check=True)
        commands.append({'argv': command, 'loadavg_before': before, 'loadavg_after': os.getloadavg()})
        print(f'kernel repeat {repeat + 1}/{REPEATS} complete', flush=True)

    per = defaultdict(list)
    sizes = {}
    for repeat in range(REPEATS):
        buckets = defaultdict(list)
        with (out / f'repeat-{repeat}.csv').open() as stream:
            for row in csv.DictReader(stream):
                buckets[row['name']].append(int(row['elapsed_ns']) / int(row['iterations']))
                sizes[row['name']] = int(row['bytes_per_op'])
        for name, values in buckets.items():
            per[name].append(statistics.median(values))

    def order(n):
        return (n.split('_')[0], int(n.rsplit('_', 1)[1]), n)

    rows = []
    for name in sorted(per, key=order):
        values = per[name]
        median = statistics.median(values)
        rows.append([name, sizes[name], round(median, 3), round(min(values), 3), round(max(values), 3),
                     round(median / sizes[name], 4), *[round(v, 3) for v in values]])
    with (out / 'kernels.csv').open('w', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['name', 'bytes_per_op', 'median_ns_per_op', 'min_repeat_ns', 'max_repeat_ns',
                         'ns_per_byte', *[f'repeat_{r}_ns' for r in range(REPEATS)]])
        writer.writerows(rows)
    manifest_update('kernels', {'commands': commands, 'binary_sha256': sha(binary),
                                'source_sha256': sha(experiment / 'src/bin/candidate_kernels.rs')})
    for zeros in (0, 1023, 4095, 16383):
        line = '  '.join(f"{c}={statistics.median(per[f'scan_{c}_{zeros}']):.1f}"
                         for c in ['production', 'block8', 'block16', 'block32', 'block64'])
        print(f'scan zeros={zeros:5} ns: {line}')
    for length in (17, 16400, 16401):
        line = '  '.join(f"{c}={statistics.median(per[f'wipe_{c}_{length}']):.1f}"
                         for c in ['production', 'aligned'])
        print(f'wipe {length:6} ns: {line}')
    print(f"failed_reopen_16401 ns/call: {statistics.median(per['failed_reopen_16401']):.1f}")


def cmd_e2e(args):
    names = list(VARIANTS)
    base = results / 'e2e'
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    for name in names:
        (base / name).mkdir()
    # Interleaved: each repeat runs every variant, rotating the order, so machine drift and
    # background load fall on all variants about equally. Load average is recorded per run.
    runs = []
    for repeat in range(E2E_REPEATS):
        shift = repeat % len(names)
        for name in names[shift:] + names[:shift]:
            command = [str(variant_binary(name)), 'bench', str(repeat)]
            before = os.getloadavg()
            with (base / name / f'repeat-{repeat}.csv').open('w') as stream:
                subprocess.run(command, cwd=root, stdout=stream, check=True)
            runs.append({'variant': name, 'repeat': repeat, 'argv': command,
                         'loadavg_before': before, 'loadavg_after': os.getloadavg()})
        print(f'e2e repeat {repeat + 1}/{E2E_REPEATS} complete', flush=True)

    per = {}
    for name in names:
        for repeat in range(E2E_REPEATS):
            buckets = defaultdict(list)
            with (base / name / f'repeat-{repeat}.csv').open() as stream:
                for row in csv.DictReader(stream):
                    if row['group'] == 'case':
                        buckets[row['name']].append(int(row['elapsed_ns']) / int(row['iterations']))
            for case, values in buckets.items():
                per[(name, case, repeat)] = statistics.median(values)
    cases = sorted({case for _, case, _ in per})
    rows = []
    for name in names:
        for case in cases:
            values = [per[(name, case, r)] for r in range(E2E_REPEATS)]
            ratios = [per[(name, case, r)] / per[('production_copy', case, r)] for r in range(E2E_REPEATS)]
            deltas = [per[(name, case, r)] - per[('production_copy', case, r)] for r in range(E2E_REPEATS)]
            rows.append([name, case, round(statistics.median(values), 3), round(min(values), 3),
                         round(max(values), 3), round(statistics.median(ratios), 4),
                         round(min(ratios), 4), round(max(ratios), 4), round(statistics.median(deltas), 3)])
    with (base / 'e2e-comparison.csv').open('w', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['variant', 'case', 'median_ns_per_record', 'min_repeat_ns', 'max_repeat_ns',
                         'ratio_vs_production_median', 'ratio_min', 'ratio_max', 'delta_vs_production_ns'])
        writer.writerows(rows)
    for row in rows:
        print(f'{row[0]:16} {row[1]:14} med={row[2]:>10} ratio={row[5]:>7} [{row[6]},{row[7]}]')

    profiles = []
    for case in ['padmax', 'tag_long', 'inner_padmax']:
        out_path = results / f'profile-{FULL}-{case}.sample.txt'
        process = subprocess.Popen([str(variant_binary(FULL)), 'loop', case, '6'], cwd=root,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        time.sleep(1.0)
        sampled = subprocess.run(['/usr/bin/sample', str(process.pid), '2', '1', '-file', str(out_path)],
                                 capture_output=True, text=True)
        _, stderr = process.communicate(timeout=60)
        profiles.append({'variant': FULL, 'case': case, 'sample_exit': sampled.returncode,
                         'driver_exit': process.returncode, 'driver_stderr': stderr.strip(),
                         'file': out_path.name, 'loadavg_before': os.getloadavg()})
        print(f'profile {FULL} {case}: sample exit {sampled.returncode}', flush=True)
    manifest_update('e2e', {'repeats': E2E_REPEATS, 'runs': runs, 'profiles': profiles,
                            'variant_binary_sha256': {n: sha(variant_binary(n)) for n in names}})


def cmd_client_tests(args):
    out = results / 'client-tests'
    out.mkdir(parents=True, exist_ok=True)
    env = {**os.environ}
    results_summary = {}

    production = subprocess.run(
        ['cargo', 'test', '--offline', '-p', 'tls-client'], cwd=root,
        env={**env, 'CARGO_TARGET_DIR': str(target / 'ws-production')},
        capture_output=True, text=True)
    log = production.stdout + production.stderr
    (out / 'production.log').write_text(log)
    results_summary['production'] = {'exit': production.returncode, 'passed': sum(
        int(m.group(1)) for m in re.finditer(r'test result: ok\. (\d+) passed', log))}

    for name in [FULL]:
        wipe, scan, awslc = VARIANTS[name]
        ws = variants_root / name / 'ws'
        if ws.exists():
            shutil.rmtree(ws)
        ws.mkdir(parents=True)
        shutil.copy(root / 'Cargo.toml', ws / 'Cargo.toml')
        shutil.copy(root / 'Cargo.lock', ws / 'Cargo.lock')
        shutil.copytree(root / 'crates', ws / 'crates', ignore=IGNORE)
        shutil.copy(variants_root / name / 'tls-core/src/protected.rs', ws / 'crates/tls-core/src/protected.rs')
        if awslc:
            shutil.copy(variants_root / name / 'tls-crypto-awslc/src/lib.rs',
                        ws / 'crates/tls-crypto-awslc/src/lib.rs')
            manifest = ws / 'crates/tls-crypto-awslc/Cargo.toml'
            manifest.write_text(replace_exactly(manifest.read_text(), *AWSLC_BYTEMUCK, 1, 'ws awslc'))
        test = subprocess.run(
            ['cargo', 'test', '--offline', '-p', 'tls-client'], cwd=ws,
            env={**env, 'CARGO_TARGET_DIR': str(variants_root / name / 'ws-target')},
            capture_output=True, text=True)
        log = test.stdout + test.stderr
        (out / f'{name}.log').write_text(log)
        results_summary[name] = {'exit': test.returncode, 'passed': sum(
            int(m.group(1)) for m in re.finditer(r'test result: ok\. (\d+) passed', log))}
    for key, value in results_summary.items():
        print(f'tls-client {key}: exit={value["exit"]} passed={value["passed"]}')
    manifest_update('client_tests', results_summary)
    if any(v['exit'] != 0 for v in results_summary.values()):
        raise SystemExit('tls-client suite failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    build = sub.add_parser('build')
    build.add_argument('--block', type=int, required=True, choices=[8, 16, 32, 64])
    build.set_defaults(func=cmd_build)
    sub.add_parser('kernels').set_defaults(func=cmd_kernels)
    sub.add_parser('e2e').set_defaults(func=cmd_e2e)
    sub.add_parser('client-tests').set_defaults(func=cmd_client_tests)
    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
