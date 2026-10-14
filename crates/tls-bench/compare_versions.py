#!/usr/bin/env python3
"""Pair two authenticated benchmark binaries, keeping the native control in each."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--before", type=Path, required=True)
parser.add_argument("--after", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--repeats", type=int, default=6)
parser.add_argument("--samples", type=int, default=100)
parser.add_argument("--bulk-records", type=int, default=256)
args = parser.parse_args()
if min(args.repeats, args.samples, args.bulk_records) <= 0:
    parser.error("counts must be positive")
root = Path(__file__).resolve().parents[2]
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=False)
binaries = {"before": args.before.resolve(), "after": args.after.resolve()}
manifest = {"repeats": args.repeats, "samples": args.samples, "bulk_records": args.bulk_records,
            "controls": "alternating version order and client order; fresh process per version/repeat; native strict client in both",
            "binary_sha256": {label: hashlib.sha256(path.read_bytes()).hexdigest() for label, path in binaries.items()},
            "commands": []}
profiles = [("aes128-x25519", "aes128", "x25519", 16645),
            ("chacha-x25519", "chacha", "x25519", 16645),
            ("aes128-x25519-fragment64", "aes128", "x25519", 64)]
rows = []
for profile, suite, group, fragment in profiles:
    directory = output / profile
    directory.mkdir()
    observations = []
    for repeat in range(args.repeats):
        values = {}
        versions = ["before", "after"] if repeat % 2 == 0 else ["after", "before"]
        for version in versions:
            command = [str(binaries[version]), "--suite", suite, "--group", group,
                       "--fragment", str(fragment), "--samples", str(args.samples),
                       "--bulk-records", str(args.bulk_records), "--order",
                       "tlsed-first" if repeat % 2 == 0 else "rustls-first"]
            path = directory / f"{version}-{repeat}.csv"
            with path.open("w") as stream, path.with_suffix(".stderr").open("w") as log:
                result = subprocess.run(command, cwd=root, stdout=stream, stderr=log)
            manifest["commands"].append({"profile": profile, "version": version, "repeat": repeat,
                                         "argv": command, "exit_code": result.returncode})
            (output / "run.json").write_text(json.dumps(manifest, indent=2) + "\n")
            if result.returncode:
                raise SystemExit(f"failed {profile}/{version}/{repeat}: inspect stderr")
            with path.open() as stream:
                for row in csv.DictReader(stream):
                    key = tuple(row[k] for k in ["workload", "direction", "payload_bytes", "iterations"])
                    values.setdefault((version, row["implementation"], key), []).append(int(row["elapsed_ns"]))
        assert len(values) == 36 and all(len(v) == args.samples for v in values.values())
        observations.append(values)
        print(f"Completed {profile} pair {repeat + 1}/{args.repeats}", flush=True)
    for version in binaries:
        files = [directory / f"{version}-{i}.csv" for i in range(args.repeats)]
        with (directory / f"{version}-summary.csv").open("w") as stream:
            subprocess.run([sys.executable, str(root / "crates/tls-bench/summarize.py"), *map(str, files)],
                           cwd=root, stdout=stream, check=True)
    keys = sorted({key for version, implementation, key in observations[0]
                   if version == "before" and implementation == "tlsed"})
    for key in keys:
        before = [statistics.median(v[("before", "tlsed", key)]) for v in observations]
        after = [statistics.median(v[("after", "tlsed", key)]) for v in observations]
        control_before = [statistics.median(v[("before", "rustls_strict", key)]) for v in observations]
        control_after = [statistics.median(v[("after", "rustls_strict", key)]) for v in observations]
        speedups = [b / a for b, a in zip(before, after)]
        normalized = [(b / cb) / (a / ca) for b, cb, a, ca in zip(before, control_before, after, control_after)]
        after_ratios = [a / ca for a, ca in zip(after, control_after)]
        rows.append([profile, *key, statistics.median(before), statistics.median(after),
                     statistics.median(control_after), statistics.median(speedups), min(speedups), max(speedups),
                     statistics.median(normalized), statistics.median(after_ratios), *speedups])
with (output / "before-after.csv").open("w", newline="") as stream:
    writer = csv.writer(stream)
    writer.writerow(["profile", "workload", "direction", "payload_bytes", "iterations",
                     "before_tlsed_median_ns", "after_tlsed_median_ns", "after_rustls_median_ns",
                     "speedup_median", "speedup_min", "speedup_max", "control_normalized_speedup",
                     "after_time_over_rustls", *[f"pair_{i}_speedup" for i in range(args.repeats)]])
    writer.writerows(rows)
print(f"Saved paired results: {output / 'before-after.csv'}", flush=True)
