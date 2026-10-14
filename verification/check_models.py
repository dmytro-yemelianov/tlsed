#!/usr/bin/env python3
"""Deterministic Rust/Lean differential checks; not a formal refinement proof."""

from __future__ import annotations

import argparse
import json
import random
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def command(args: list[str], cwd: Path = ROOT) -> None:
    subprocess.run(args, cwd=cwd, check=True)


def output(binary: Path, args: list[str]) -> str:
    result = subprocess.run(
        [str(binary), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"{binary.name} failed: {result.stderr.strip()}")
    value = result.stdout.strip()
    if not value:
        raise RuntimeError(f"{binary.name} returned no result: {result.stderr.strip()}")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--cases", type=int, default=256)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.cases < 1:
        parser.error("--cases must be positive")
    if not args.skip_build:
        command(["cargo", "build", "--locked", "-p", "tls-core", "--example", "model_probe"])
        command(["cargo", "build", "--locked", "-p", "tls-core", "--example", "protected_probe"])
        command(["cargo", "build", "--locked", "-p", "tls-core", "--example", "key_schedule_probe"])
        command(["cargo", "build", "--locked", "-p", "tls-core", "--example", "client_policy_probe"])
        command(["lake", "build"], ROOT / "lean")

    rust = ROOT / "target/debug/examples/model_probe"
    protected = ROOT / "target/debug/examples/protected_probe"
    key_schedule = ROOT / "target/debug/examples/key_schedule_probe"
    client_policy = ROOT / "target/debug/examples/client_policy_probe"
    lean = ROOT / "lean/.lake/build/bin/tls13_model"
    native_max = (1 << (struct.calcsize("P") * 8)) - 1
    counts: set[tuple[int, int]] = set()
    for limit in (0, 1, 2, 64, 1024, 16384, 16640, native_max):
        for n in (0, 1, limit, max(0, limit - 1), native_max, native_max - 1):
            counts.add((n, limit))
        if 0 < limit < native_max:
            counts.add((limit + 1, limit))
    rng = random.Random(0x71513)
    for _ in range(args.cases):
        counts.add((rng.randrange(native_max + 1), rng.randrange(1, native_max + 1)))

    cases = [["count", str(n), str(limit)] for n, limit in sorted(counts)]
    u64_max = (1 << 64) - 1
    for mode in ("reserve", "rotate"):
        for limit in (0, 1, 2, 8, (1 << 48) - 1, u64_max):
            for value in (0, 1, max(0, limit - 1), limit, u64_max - 1, u64_max):
                cases.append([mode, str(value), str(limit)])
        for _ in range(args.cases):
            cases.append([mode, str(rng.randrange(u64_max + 1)), str(rng.randrange(u64_max + 1))])

    for state in range(7):
        for event in range(7):
            cases.append(["auth", str(state), str(event)])
        for valid in range(3):
            cases.append(["release", str(state), str(valid)])

    for mode, protocol_cap in ((0, 16384), (1, 16640)):
        for content_type in (0, 20, 21, 22, 23, 255):
            for version in (0, 0x0301, 0x0303, 0x0304, 65535):
                for length in (0, 1, 2, 3, protocol_cap, protocol_cap + 1, 65535):
                    cases.append(["header", *map(str, (mode, content_type, version, length, protocol_cap))])
        for _ in range(args.cases):
            cases.append([
                "header", *map(str, (mode, rng.randrange(256), rng.randrange(65536),
                                    rng.randrange(65536), rng.randrange(protocol_cap + 2)))
            ])
        for cap in (0, 1, 2, 16, protocol_cap + 1, native_max):
            cases.append(["header", *map(str, (mode, 22 if mode == 0 else 23, 0x0303, 2, cap))])

    cases.extend([
        ["count", "-1", "1"], ["count", "1", "nope"], ["count", str(u64_max + 1), "1"],
        ["header", "2", "22", "771", "1", "16384"],
        ["header", "0", "256", "771", "1", "16384"],
        ["header", "0", "22", "65536", "1", "16384"],
        ["header", "0", "22", "771", "65536", "16384"],
    ])
    for body in (0, 1, 2, 16, 16384, 0xffffff - 1, 0xffffff, 0x1000000, native_max):
        for cap in (0, 1, 16, 16384, 0xffffff, 0x1000000, native_max):
            cases.append(["handshake-total", str(body), str(cap)])
    for _ in range(args.cases):
        cases.append(["handshake-total", str(rng.randrange(0x2000000)), str(rng.randrange(0x2000000))])
    for kind in (0, 20, 21, 22, 23, 255):
        for content in (0, 1, 2, 16384, 16385, native_max):
            for padding in (0, 1, 16384, native_max):
                for limit in (0, 1, 2, 64, 16385, 16386, native_max):
                    cases.append(["inner-check", *map(str, (kind, content, padding, limit))])
    for _ in range(args.cases):
        values = (rng.choice((21, 22, 23)), rng.randrange(32768),
                  rng.randrange(32768), rng.randrange(16387))
        cases.append(["inner-check", *map(str, values)])
    cases.extend([
        ["handshake-total", "-1", "1"], ["inner-check", "256", "0", "0", "1"],
        ["inner-check", "23", str(u64_max + 1), "0", "1"],
    ])
    for length in (0, 1, 32, 48, 65535, 65536, native_max):
        for label in (0, 1, 6, 249, 250, native_max):
            for context in (0, 1, 32, 48, 255, 256, native_max):
                cases.append(["label-size", *map(str, (length, label, context))])
    for _ in range(args.cases):
        cases.append(["label-size", *map(str, (rng.randrange(65538),
                                              rng.randrange(252), rng.randrange(258)))])
    cases.extend([
        ["label-size", "-1", "1", "0"], ["label-size", "32", "invalid", "0"],
        ["label-size", str(u64_max + 1), "1", "0"],
    ])
    for phase in (*range(9), 254, 255):
        for message in (0, 1, 2, 4, 8, 11, 13, 15, 20, 24, 252, 253, 254, 255):
            for verified in (0, 1):
                for retried in (0, 1):
                    cases.append(["client-phase", *map(str, (phase, message, verified, retried))])
    for _ in range(args.cases):
        cases.append(["client-phase", *map(str, (rng.randrange(256), rng.randrange(256),
                                                rng.randrange(2), rng.randrange(2)))])
    cases.extend([
        ["client-phase", "256", "2", "1", "0"], ["client-phase", "0", "256", "1", "0"],
        ["client-phase", "0", "2", "2", "0"], ["client-phase", "0", "2", "1", "-1"],
    ])
    probes = {"inner-check": protected, "label-size": key_schedule, "client-phase": client_policy}
    by_operation: dict[str, int] = {}
    for case in cases:
        actual = output(probes.get(case[0], rust), case)
        expected = output(lean, case)
        if actual != expected:
            raise AssertionError(f"model disagreement for {case}: Rust={actual!r}, Lean={expected!r}")
        by_operation[case[0]] = by_operation.get(case[0], 0) + 1
    report = {
        "assurance": "tested against model",
        "operations": by_operation,
        "seed": "0x71513",
        "native_pointer_bits": struct.calcsize("P") * 8,
        "cases_passed": len(cases),
        "scope": "native usize/u64 arithmetic, record/inner/handshake/label guards, client flight policy, evidence FSM, release gate, rejection paths",
        "formal_refinement": False,
    }
    print(json.dumps(report, indent=2))
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
