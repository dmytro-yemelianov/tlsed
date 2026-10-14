#!/usr/bin/env python3
"""Time padded, long, and corrupted records through ProtectedReader::open, then sample four cases.

Assumes the release binary already exists (`cargo build --release --offline`).
Runs nothing else while timing; profiles run after all timed repeats finish.
"""
import csv
import hashlib
import json
import statistics
import subprocess
import time
from collections import defaultdict
from pathlib import Path

root = Path(__file__).resolve().parents[3]
experiment = Path(__file__).resolve().parent
binary = root / 'target/inner-scan-audit/release/tlsed-inner-scan-audit'
output = root / 'verification/results/2026-10-14-inner-scan-audit'
output.mkdir(exist_ok=False)

REPEATS = 6
PROFILE_CASES = ['long', 'padmax', 'tag_long', 'inner_padmax']
PROFILE_SECONDS = 6


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def text(command):
    return subprocess.run(command, capture_output=True, text=True, check=True).stdout.strip()


manifest = {
    'binary_sha256': sha(binary),
    'sources': {str(p.relative_to(root)): sha(p) for p in [
        experiment / 'Cargo.toml',
        experiment / 'Cargo.lock',
        experiment / 'src/main.rs',
        Path(__file__).resolve(),
        root / 'Cargo.lock',
        root / 'crates/tls-core/src/protected.rs',
        root / 'crates/tls-core/src/wire.rs',
        root / 'crates/tls-crypto-awslc/src/lib.rs',
    ]},
    'host': {
        'cpu': text(['sysctl', '-n', 'machdep.cpu.brand_string']),
        'macos': text(['sw_vers', '-productVersion']),
        'rustc': text(['rustc', '--version']),
        'power': text(['pmset', '-g', 'batt']).splitlines()[0],
    },
    'design': {
        'repeats': REPEATS, 'samples': 60, 'warmups': 5, 'records_per_batch': 512,
        'read_buffer': 'active prefix = record length - 5, as tls-client/src/lib.rs passes plain[..record.len() - 5]',
        'kernel_bytes_per_batch': 4 << 20,
        'order': 'cases and kernels rotate by repeat+sample+step',
        'controls': 'release, thin LTO, codegen-units=1; no concurrent build/test/profile during timing; no affinity or frequency lock',
    },
    'commands': [],
    'profiles': [],
}

per = {}
for repeat in range(REPEATS):
    command = [str(binary), 'bench', str(repeat)]
    path = output / f'repeat-{repeat}.csv'
    with path.open('w') as stream:
        result = subprocess.run(command, cwd=root, stdout=stream, check=True)
    manifest['commands'].append({'argv': command, 'exit_code': result.returncode})
    buckets = defaultdict(list)
    with path.open() as stream:
        for row in csv.DictReader(stream):
            key = (row['group'], row['name'])
            buckets[key].append(int(row['elapsed_ns']) / int(row['iterations']))
    for key, values in buckets.items():
        per[(key, repeat)] = statistics.median(values)
    print(f'Bench repeat {repeat + 1}/{REPEATS} complete', flush=True)

keys = sorted({key for key, _ in per})


def series(key):
    return [per[(key, r)] for r in range(REPEATS)]


long_key = ('case', 'long')
rows = []
for key in keys:
    values = series(key)
    row = [key[0], key[1], round(statistics.median(values), 3), round(min(values), 3), round(max(values), 3)]
    if key[0] == 'case':
        ratios = [per[(key, r)] / per[(long_key, r)] for r in range(REPEATS)]
        deltas = [per[(key, r)] - per[(long_key, r)] for r in range(REPEATS)]
        row += [round(statistics.median(ratios), 3), round(min(ratios), 3), round(max(ratios), 3),
                round(statistics.median(deltas), 3)]
    else:
        row += ['', '', '', '']
    rows.append(row + [round(v, 3) for v in values])

with (output / 'comparison.csv').open('w', newline='') as stream:
    writer = csv.writer(stream)
    writer.writerow(['group', 'name', 'median_ns_per_op', 'min_repeat_ns', 'max_repeat_ns',
                     'ratio_vs_long_median', 'ratio_min', 'ratio_max', 'delta_vs_long_median_ns',
                     *[f'repeat_{r}_ns_per_op' for r in range(REPEATS)]])
    writer.writerows(rows)

# Decompose padmax - long. Both records carry the same AEAD input length, so the
# only differences are the scan over 16,383 zeros and the tail wipe (16,400 B vs 17 B).
decomposition = []
for r in range(REPEATS):
    scan = per[(('kernel', 'scan_zeros_16383'), r)]
    wipe_big = per[(('kernel', 'zeroize_tail_16400'), r)]
    wipe_small = per[(('kernel', 'zeroize_tail_17'), r)]
    predicted = scan + wipe_big - wipe_small
    measured = per[(('case', 'padmax'), r)] - per[(long_key, r)]
    decomposition.append([r, round(scan, 3), round(wipe_big - wipe_small, 3), round(predicted, 3),
                          round(measured, 3), round(measured / predicted, 4)])
with (output / 'decomposition.csv').open('w', newline='') as stream:
    writer = csv.writer(stream)
    writer.writerow(['repeat', 'scan_16383_ns', 'tail_wipe_delta_ns', 'predicted_delta_ns',
                     'measured_padmax_minus_long_ns', 'measured_over_predicted'])
    writer.writerows(decomposition)

for case in PROFILE_CASES:
    out_path = output / f'profile-{case}.sample.txt'
    process = subprocess.Popen([str(binary), 'loop', case, str(PROFILE_SECONDS)], cwd=root,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    time.sleep(1.0)
    sampled = subprocess.run(['/usr/bin/sample', str(process.pid), '2', '1', '-file', str(out_path)],
                             capture_output=True, text=True)
    _, stderr = process.communicate(timeout=60)
    manifest['profiles'].append({
        'case': case,
        'argv': [str(binary), 'loop', case, str(PROFILE_SECONDS)],
        'sample_exit': sampled.returncode,
        'driver_exit': process.returncode,
        'driver_stderr': stderr.strip(),
        'file': str(out_path.relative_to(root)),
    })
    print(f'Profile {case}: sample exit {sampled.returncode}', flush=True)

manifest['raw_csv_sha256'] = {p.name: sha(p) for p in sorted(output.glob('*.csv'))}
(output / 'run.json').write_text(json.dumps(manifest, indent=2) + '\n')
print('done')
