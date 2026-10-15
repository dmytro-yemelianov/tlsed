#!/usr/bin/env python3
"""Paired TLSed / rustls / OpenSSL client comparison against one rustls server.

Fresh process per repeat; the implementation order rotates by repeat, so drift and background
load fall on every client about equally. Nothing builds or runs during timing.
"""
import csv
import hashlib
import json
import os
import statistics
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

root = Path(__file__).resolve().parents[3]
experiment = Path(__file__).resolve().parent
binary = root / 'target/openssl-compare/release/openssl-compare'
# `run.py core` (default) or `run.py extended`; each set has its own results directory.
SET = sys.argv[1] if len(sys.argv) > 1 else 'core'
output = root / {'core': 'verification/results/2026-10-14-openssl-compare',
                 'extended': 'verification/results/2026-10-14-openssl-compare-extended',
                 'p256-hrr': 'verification/results/2026-10-14-openssl-compare-p256-hrr-12'}[SET]
output.mkdir(exist_ok=False)

# The p256-hrr set takes 12 repeats: its handshake rows were noisy at 6.
REPEATS = 12 if (sys.argv[1:2] == ['p256-hrr']) else 6
SAMPLES = 100
BULK_RECORDS = 256
IMPLS = ['tlsed', 'rustls', 'openssl']
NAMES = {'tlsed': 'tlsed', 'rustls': 'rustls_strict', 'openssl': 'openssl'}
PROFILE_SETS = {
    'core': [
        ('aes128-x25519', 'aes128', 'x25519', 16645),
        ('aes128-x25519-fragment64', 'aes128', 'x25519', 64),
        ('chacha-x25519', 'chacha', 'x25519', 16645),
    ],
    'extended': [
        ('aes256-x25519', 'aes256', 'x25519', 16645),
        ('aes128-p256', 'aes128', 'p256', 16645),
        ('aes128-hrr', 'aes128', 'hrr', 16645),
    ],
    'p256-hrr': [
        ('aes128-p256', 'aes128', 'p256', 16645),
        ('aes128-hrr', 'aes128', 'hrr', 16645),
    ],
}
PROFILES = PROFILE_SETS[SET]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def text(command):
    return subprocess.run(command, capture_output=True, text=True, check=True).stdout.strip()


manifest = {
    'design': {
        'repeats': REPEATS, 'samples_per_repeat': SAMPLES, 'bulk_records_per_sample': BULK_RECORDS,
        'peer': 'one rustls 0.23.45 server (fixtures; strict-policy-independent, bench/1, TLS 1.3, no resumption)',
        'clients': {'tlsed': 'tls-client (strict tls-pki policy)',
                    'rustls': 'rustls 0.23.45 client with the same strict verifier',
                    'openssl': 'OpenSSL 3 client, X509 strict purpose SSL_SERVER, fixture CA, memory BIOs'},
        'order': 'rotates by repeat; fresh process per repeat',
        'profiles': [p[0] for p in PROFILES],
        'limits': 'OpenSSL uses its own chain checks, not tls-pki; PKI cost is not identical across clients',
    },
    'host': {
        'cpu': text(['sysctl', '-n', 'machdep.cpu.brand_string']),
        'macos': text(['sw_vers', '-productVersion']),
        'rustc': text(['rustc', '--version']),
        'openssl': text(['/opt/homebrew/opt/openssl@3/bin/openssl', 'version']),
        'power': text(['pmset', '-g', 'batt']).splitlines()[0],
    },
    'sources': {str(p.relative_to(root)): sha(p) for p in [
        experiment / 'Cargo.toml', experiment / 'Cargo.lock', experiment / 'build.rs',
        experiment / 'src/main.rs', experiment / 'src/ossl.rs', experiment / 'src/openssl_shim.c',
        experiment / 'run.py', root / 'crates/tls-bench/src/bin/client_compare.rs']},
    'binary_sha256': sha(binary),
    'runs': [],
}

raw = defaultdict(list)  # (profile, repeat) -> csv rows
for label, suite, group, fragment in PROFILES:
    directory = output / label
    directory.mkdir()
    for repeat in range(REPEATS):
        shift = repeat % len(IMPLS)
        order = IMPLS[shift:] + IMPLS[:shift]
        command = [str(binary), '--suite', suite, '--group', group, '--fragment', str(fragment),
                   '--samples', str(SAMPLES), '--bulk-records', str(BULK_RECORDS),
                   '--order', ','.join(order)]
        before = os.getloadavg()
        path = directory / f'repeat-{repeat}.csv'
        with path.open('w') as stream:
            subprocess.run(command, cwd=root, stdout=stream, check=True)
        manifest['runs'].append({'profile': label, 'repeat': repeat, 'argv': command,
                                 'loadavg_before': before, 'loadavg_after': os.getloadavg()})
        with path.open() as stream:
            raw[(label, repeat)] = list(csv.DictReader(stream))
        print(f'{label} repeat {repeat + 1}/{REPEATS} complete', flush=True)

rows = []
for label, _, _, _ in PROFILES:
    cells = defaultdict(lambda: defaultdict(list))  # (workload, direction, payload) -> impl -> [per-repeat]
    for repeat in range(REPEATS):
        per = defaultdict(list)
        for row in raw[(label, repeat)]:
            key = (row['workload'], row['direction'], row['payload_bytes'], row['implementation'])
            per[key].append(int(row['elapsed_ns']) / int(row['iterations']))
        for key, values in per.items():
            workload, direction, payload, impl = key
            cells[(workload, direction, payload)][impl].append(statistics.median(values))
    for (workload, direction, payload), impls in sorted(cells.items()):
        t, r, o = impls['tlsed'], impls['rustls_strict'], impls['openssl']
        t_o = [a / b for a, b in zip(t, o)]
        r_o = [a / b for a, b in zip(r, o)]
        t_r = [a / b for a, b in zip(t, r)]
        rows.append([label, workload, direction, int(payload),
                     round(statistics.median(t), 1), round(statistics.median(r), 1), round(statistics.median(o), 1),
                     round(statistics.median(t_o), 4), round(min(t_o), 4), round(max(t_o), 4),
                     round(statistics.median(r_o), 4), round(statistics.median(t_r), 4)])

with (output / 'comparison.csv').open('w', newline='') as stream:
    writer = csv.writer(stream)
    writer.writerow(['profile', 'workload', 'direction', 'payload_bytes',
                     'tlsed_median_ns', 'rustls_median_ns', 'openssl_median_ns',
                     'tlsed_over_openssl', 'tlsed_over_openssl_min', 'tlsed_over_openssl_max',
                     'rustls_over_openssl', 'tlsed_over_rustls'])
    writer.writerows(rows)
manifest['raw_csv_sha256'] = {str(p.relative_to(output)): sha(p) for p in sorted(output.rglob('*.csv'))}
(output / 'run.json').write_text(json.dumps(manifest, indent=2) + '\n')
print('done')
