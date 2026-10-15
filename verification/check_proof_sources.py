#!/usr/bin/env python3
"""Reject proof placeholders in tracked Lean sources; Lake still checks proofs."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
required = (ROOT / "lean/Tls13.lean", ROOT / "verification/aeneas/Proof.lean",
            ROOT / "verification/aeneas/ReassemblyProof.lean",
            ROOT / "verification/aeneas/ProtectedProof.lean",
            ROOT / "verification/aeneas/KeyScheduleProof.lean",
            ROOT / "verification/aeneas/ClientProof.lean")
for path in required:
    if not path.is_file():
        raise SystemExit(f"Missing required Lean source: {path.relative_to(ROOT)}")
for source_root in (ROOT / "lean", ROOT / "verification/aeneas"):
    for path in sorted(source_root.rglob("*.lean")):
        if ".lake" in path.parts:
            continue
        source = path.read_text()
        # Conservative: forbidden tokens in comments also fail so they cannot hide
        # declarations. Proofs remain checked by Lean's kernel via `lake build`.
        match = re.search(r"\b(sorry|admit|axiom)\b", source)
        if match:
            raise SystemExit(f"Forbidden proof token {match.group()} in {path.relative_to(ROOT)}")
print("Lean source check passed: no proof placeholders or custom axioms")
