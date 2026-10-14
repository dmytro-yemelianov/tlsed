#!/usr/bin/env python3
"""Run isolated erasure candidates without builds, profiles, or concurrent tests."""
import csv
import hashlib
import json
from pathlib import Path
import statistics
import subprocess

root = Path(__file__).resolve().parents[3]
experiment = Path(__file__).resolve().parent
binary = experiment / 'target/release/tlsed-cpu-audit'
output = root / 'verification/results/2026-10-14-cpu-audit/micro'
output.mkdir(exist_ok=False)
manifest = {'commands': [], 'repeats': 6, 'samples_per_case': 30, 'warmups': 5,
    'order': 'rotates variants by repeat+sample+step',
    'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
    'sources': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in [experiment/'Cargo.toml', experiment/'Cargo.lock', experiment/'src/main.rs', Path(__file__)]},
    'data': {'initial_byte': 165, 'initialization': 'outside timer; first wipe nonzero, subsequent batch wipes zero; all variants content independent',
        'validation': 'whole buffer compared with independent Vec::fill oracle, offsets0..31, boundary lengths; timed results and guards verified after timer'},
    'controls': 'release1.98.1 thinLTO codegen1; no concurrent build/test/profile; no CPU affinity/frequency lock'}
values = {}
for repeat in range(6):
    command = [str(binary), str(repeat)]
    path = output / f'repeat-{repeat}.csv'
    with path.open('w') as stream:
        result = subprocess.run(command, cwd=root, stdout=stream, check=True)
    manifest['commands'].append({'argv': command, 'exit_code': result.returncode})
    with path.open() as stream:
        count = 0
        for row in csv.DictReader(stream):
            key = (row['variant'], int(row['size']), int(row['offset']), repeat)
            values.setdefault(key, []).append(int(row['elapsed_ns']) / int(row['iterations']))
            count += 1
    assert count == 4860
    print(f'Micro repeat {repeat+1}/6 complete', flush=True)
rows = []
for variant, size, offset in sorted({(v,s,o) for v,s,o,_ in values}):
    medians = [statistics.median(values[(variant,size,offset,r)]) for r in range(6)]
    current_ratios = [statistics.median(values[('current_u128',size,offset,r)]) / medians[r] for r in range(6)]
    byte_ratios = [statistics.median(values[('byte_reference',size,offset,r)]) / medians[r] for r in range(6)]
    rows.append([variant,size,offset,statistics.median(medians),statistics.median(current_ratios),min(current_ratios),max(current_ratios),statistics.median(byte_ratios),*medians])
with (output/'comparison.csv').open('w',newline='') as stream:
    w=csv.writer(stream)
    w.writerow(['variant','bytes','offset','median_ns_per_call','current_over_variant_median','ratio_min','ratio_max','byte_over_variant_median',*[f'repeat_{r}_ns' for r in range(6)]])
    w.writerows(rows)
manifest['raw_csv_sha256']={str(p.name):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(output.glob('*.csv'))}
(output/'run.json').write_text(json.dumps(manifest,indent=2)+'\n')
