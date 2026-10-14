#!/usr/bin/env python3
"""Bind the retained Aeneas artifact to production source; optionally retranslate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
EXTRACTION = ROOT / "verification/aeneas"
MANIFEST = EXTRACTION / "translation-manifest.json"
FILES = ("crates/tls-core/src/schedule.rs", "crates/tls-core/src/lib.rs",
         "crates/tls-core/src/handshake.rs", "crates/tls-core/src/protected.rs",
         "crates/tls-core/src/key_schedule.rs",
         "crates/tls-core/src/client_policy.rs",
         "verification/aeneas/generated/TlsCore.lean")
COMPONENTS = ("tls_core::schedule::record_count", "tls_core::handshake::checked_handshake_total",
              "tls_core::protected::inner_length", "tls_core::protected::valid_content_type",
              "tls_core::key_schedule::hkdf_label_encoded_len",
              "tls_core::client_policy::client_phase_next")
PINS = {"aeneas": "557eff83ecef5083b98a52a94ca7fae63d6c1dab",
        "charon": "c8f15d7d658c86a95658f71ad99cddd4be002e04"}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tool(name: str) -> str:
    binary = os.environ.get(name.upper() + "_BIN") or shutil.which(name)
    if not binary:
        raise SystemExit(f"Set {name.upper()}_BIN to the pinned {name} executable")
    version_flag = "-version" if name == "aeneas" else "version"
    version = subprocess.run([binary, version_flag], check=True, capture_output=True, text=True)
    reported = version.stdout + version.stderr
    expected_version = PINS[name][:8] if name == "aeneas" else PINS[name]
    if expected_version not in reported:
        raise SystemExit(f"{name} commit does not match required pin {PINS[name]}")
    return binary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--regenerate", action="store_true")
    args = parser.parse_args()
    if args.regenerate:
        charon, aeneas = tool("charon"), tool("aeneas")
        toolchain = subprocess.run(
            [charon, "toolchain-version"], check=True, capture_output=True, text=True,
        ).stdout.strip()
        if toolchain != "nightly-2026-09-17":
            raise SystemExit(f"Charon Rust toolchain differs from pin: {toolchain}")
        with tempfile.TemporaryDirectory(prefix="tlsed-translation-") as directory:
            temp = Path(directory)
            llbc = temp / "tls_core.llbc"
            starts = [item for component in COMPONENTS for item in ("--start-from", component)]
            subprocess.run([
                charon, "cargo", "--preset=aeneas", *starts,
                "--dest-file", str(llbc), "--", "--lib", "-p", "tls-core",
                "--target-dir", str(temp / "target")
            ], cwd=ROOT, check=True)
            subprocess.run([
                aeneas, "-backend", "lean", "-no-progress-bar", "-warnings-as-errors",
                "-dest", str(temp), str(llbc)
            ], cwd=ROOT, check=True)
            generated_source = (temp / "TlsCore.lean").read_text()
            unsupported = re.search(r"\b(axiom|sorry|admit)\b", generated_source)
            if unsupported:
                raise SystemExit("Translation introduced an unsupported definition or proof admission; "
                                 "adapt the Rust subset before retaining evidence")
            generated = EXTRACTION / "generated"
            generated.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(temp / "TlsCore.lean", generated / "TlsCore.lean")
            shutil.copyfile(llbc, generated / "tls_core.llbc")
        evidence = {
            "components": list(COMPONENTS),
            "tools": PINS,
            "extraction_rust": "nightly-2026-09-17",
            "proof_lean": "v4.31.0",
            "extraction_target": "native host (initial evidence: aarch64-apple-darwin)",
            "sha256": {name: digest(ROOT / name) for name in FILES},
        }
        MANIFEST.write_text(json.dumps(evidence, indent=2) + "\n")

    if not MANIFEST.exists():
        raise SystemExit("No translation manifest; run with --regenerate and pinned tools")
    evidence = json.loads(MANIFEST.read_text())
    if (evidence["tools"] != PINS or set(evidence["sha256"]) != set(FILES)
            or evidence["components"] != list(COMPONENTS)):
        raise SystemExit("Translation manifest pins/scope do not match this verification harness")
    for name in FILES:
        if digest(ROOT / name) != evidence["sha256"][name]:
            raise SystemExit(f"Stale translation: {name}; regenerate and rerun linked proofs")
    print("Production source and retained translation hashes match pinned extraction evidence")


if __name__ == "__main__":
    main()
