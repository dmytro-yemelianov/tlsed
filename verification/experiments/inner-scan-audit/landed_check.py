#!/usr/bin/env python3
"""Paired timing of the landed production build against the pre-landing build.

The pre-landing binary is the `production_copy` variant that candidates.py builds from the
pre-landing sources; the landed binary is built from the working tree. Repeats interleave the two,
rotating the order, so drift and load fall on both. Nothing builds during timing.
"""
import csv, hashlib, json, os, statistics, subprocess
from collections import defaultdict
from pathlib import Path

root = Path(__file__).resolve().parents[3]
experiment = Path(__file__).resolve().parent
target = root / 'target/inner-scan-audit'
output = root / 'verification/results/2026-10-14-landed-check'
output.mkdir(exist_ok=False)
REPEATS = 6
BINARIES = {
    'pre_landing': target / 'variants/production_copy/target/release/tlsed-inner-scan-audit-production_copy',
    'landed': target / 'release/tlsed-inner-scan-audit',
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


manifest = {'repeats': REPEATS, 'binaries_sha256': {k: sha(v) for k, v in BINARIES.items()},
            'loadavg_before_each_run': [], 'runs': []}
per = defaultdict(lambda: defaultdict(list))  # (case) -> impl -> per-repeat medians
for repeat in range(REPEATS):
    names = list(BINARIES)
    shift = repeat % len(names)
    for name in names[shift:] + names[:shift]:
        out = output / f'{name}-repeat-{repeat}.csv'
        command = [str(BINARIES[name]), 'bench', str(repeat)]
        before = os.getloadavg()
        with out.open('w') as stream:
            subprocess.run(command, cwd=root, stdout=stream, check=True)
        manifest['runs'].append({'impl': name, 'repeat': repeat, 'argv': command,
                                 'loadavg_before': before, 'loadavg_after': os.getloadavg()})
        buckets = defaultdict(list)
        for row in csv.DictReader(out.open()):
            if row['group'] == 'case':
                buckets[row['name']].append(int(row['elapsed_ns']) / int(row['iterations']))
        for case, values in buckets.items():
            per[case][name].append(statistics.median(values))
    print(f'repeat {repeat + 1}/{REPEATS} complete', flush=True)

rows = []
for case in sorted(per):
    p, l = per[case]['pre_landing'], per[case]['landed']
    ratios = [b / a for a, b in zip(p, l)]
    rows.append([case, round(statistics.median(p), 1), round(statistics.median(l), 1),
                 round(statistics.median(ratios), 3), round(min(ratios), 3), round(max(ratios), 3)])
with (output / 'comparison.csv').open('w', newline='') as stream:
    writer = csv.writer(stream)
    writer.writerow(['case', 'pre_landing_median_ns', 'landed_median_ns', 'landed_over_pre_landing',
                     'ratio_min', 'ratio_max'])
    writer.writerows(rows)
manifest['sources'] = {str(p.relative_to(root)): sha(p) for p in [
    root / 'crates/tls-core/src/protected.rs', root / 'crates/tls-crypto-awslc/src/lib.rs',
    experiment / 'landed_check.py']}
(output / 'run.json').write_text(json.dumps(manifest, indent=2) + '\n')
for row in rows:
    print(f"{row[0]:14} pre={row[1]:>10} landed={row[2]:>10} landed/pre={row[3]:.3f} [{row[4]},{row[5]}]")
print('done')
