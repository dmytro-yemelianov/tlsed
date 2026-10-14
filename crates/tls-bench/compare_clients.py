#!/usr/bin/env python3
"""Run fresh-process paired repeats and retain raw measurements and ratios."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--repeats", type=int, default=5)
parser.add_argument("--samples", type=int, default=100)
parser.add_argument("--bulk-records", type=int, default=256)
parser.add_argument("--primary-only", action="store_true")
parser.add_argument("--only-profiles", help="comma-separated profile labels to run instead of the full set")
args = parser.parse_args()
if min(args.repeats, args.samples, args.bulk_records) <= 0:
    parser.error("counts must be positive")
root = Path(__file__).resolve().parents[2]
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=False)
profiles = [("aes128-x25519", "aes128", "x25519", 16645)]
if args.only_profiles:
    wanted = args.only_profiles.split(",")
    full = profiles + [
        ("aes256-x25519", "aes256", "x25519", 16645),
        ("chacha-x25519", "chacha", "x25519", 16645),
        ("aes128-p256", "aes128", "p256", 16645),
        ("aes128-hrr", "aes128", "hrr", 16645),
        ("aes128-x25519-fragment64", "aes128", "x25519", 64),
    ]
    profiles = [p for p in full if p[0] in wanted]
    assert len(profiles) == len(wanted), f"unknown profile in {wanted}"
elif not args.primary_only:
    profiles += [
        ("aes256-x25519", "aes256", "x25519", 16645),
        ("chacha-x25519", "chacha", "x25519", 16645),
        ("aes128-p256", "aes128", "p256", 16645),
        ("aes128-hrr", "aes128", "hrr", 16645),
        ("aes128-x25519-fragment64", "aes128", "x25519", 64),
    ]
binary = root / "target/release/client_compare"
pki_binary = root / "target/release/pki_compare"
assert binary.is_file() and pki_binary.is_file(), "build binaries before timing"
manifest = {
    "repeats": args.repeats,
    "samples_per_repeat": args.samples,
    "bulk_records_per_sample": args.bulk_records,
    "assurance": "authenticated client + identical rustls server pair; shared strict tls-pki policy",
    "fresh_process_per_repeat": True,
    "order": "alternates by repeat",
    "binary_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [binary, pki_binary]},
    "commands": [],
    "controls": "no concurrent agent compilation/fuzzing; affinity/frequency/scheduler isolation unavailable",
}
comparison_rows = []
for label, suite, group, fragment in profiles:
    directory = output / label
    directory.mkdir()
    files = []
    per_repeat = []
    for repeat in range(args.repeats):
        command = [str(binary), "--suite", suite, "--group", group,
                   "--fragment", str(fragment), "--samples", str(args.samples),
                   "--bulk-records", str(args.bulk_records), "--order",
                   "tlsed-first" if repeat % 2 == 0 else "rustls-first"]
        csv_path = directory / f"repeat-{repeat}.csv"
        with csv_path.open("w") as stream, (directory / f"repeat-{repeat}.stderr").open("w") as log:
            result = subprocess.run(command, cwd=root, stdout=stream, stderr=log)
        manifest["commands"].append({"profile": label, "repeat": repeat, "argv": command, "exit_code": result.returncode})
        if result.returncode:
            (output / "run.json").write_text(json.dumps(manifest, indent=2) + "\n")
            raise SystemExit(f"failed {label}/{repeat}: inspect stderr")
        files.append(csv_path)
        values = {}
        with csv_path.open() as stream:
            for row in csv.DictReader(stream):
                key = (row["workload"], row["direction"], row["payload_bytes"], row["iterations"])
                values.setdefault((row["implementation"], key), []).append(int(row["elapsed_ns"]))
        assert len(values) == 18 and all(len(v) == args.samples for v in values.values())
        per_repeat.append(values)
        print(f"Completed {label} repeat {repeat + 1}/{args.repeats}", flush=True)
    with (directory / "summary.csv").open("w") as stream:
        subprocess.run([sys.executable, str(root / "crates/tls-bench/summarize.py"), *map(str, files)], cwd=root, stdout=stream, check=True)
    keys = sorted({key for implementation, key in per_repeat[0] if implementation == "tlsed"})
    for key in keys:
        ratios = [statistics.median(v[("tlsed", key)]) / statistics.median(v[("rustls_strict", key)]) for v in per_repeat]
        tlsed_medians = [statistics.median(v[("tlsed", key)]) for v in per_repeat]
        rustls_medians = [statistics.median(v[("rustls_strict", key)]) for v in per_repeat]
        comparison_rows.append([label, *key, statistics.median(tlsed_medians), statistics.median(rustls_medians),
                                statistics.median(ratios), min(ratios), max(ratios), *ratios])
    print(f"Summary ready: {label}", flush=True)

pki_directory = output / "pki"
pki_directory.mkdir()
pki_files = []
for repeat in range(args.repeats):
    command = [str(pki_binary), "--samples", str(args.samples), "--iterations", str(args.bulk_records), "--warmup", "20"]
    path = pki_directory / f"repeat-{repeat}.csv"
    with path.open("w") as stream, (pki_directory / f"repeat-{repeat}.stderr").open("w") as log:
        result = subprocess.run(command, cwd=root, stdout=stream, stderr=log)
    manifest["commands"].append({"profile": "pki", "repeat": repeat, "argv": command, "exit_code": result.returncode})
    if result.returncode:
        raise SystemExit(f"PKI repeat{repeat} failed")
    pki_files.append(path)
    print(f"Completed PKI repeat {repeat + 1}/{args.repeats}", flush=True)
with (pki_directory / "summary.csv").open("w") as stream:
    subprocess.run([sys.executable, str(root / "crates/tls-bench/summarize.py"), *map(str, pki_files)], cwd=root, stdout=stream, check=True)
with (output / "comparison.csv").open("w", newline="") as stream:
    writer = csv.writer(stream)
    writer.writerow(["profile", "workload", "direction", "payload_bytes", "iterations", "tlsed_median_ns", "rustls_median_ns",
                     "tlsed_time_over_rustls", "repeat_ratio_min", "repeat_ratio_max", *[f"repeat_{i}_ratio" for i in range(args.repeats)]])
    writer.writerows(comparison_rows)
(output / "run.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(f"Saved comparison: {output / 'comparison.csv'}", flush=True)
