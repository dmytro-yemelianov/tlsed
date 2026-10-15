#!/usr/bin/env python3
"""Require every enumerated production theorem to use only Lean foundations."""

import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {"propext", "Classical.choice", "Quot.sound"}
AUDITS = (
    (ROOT / "lean", "AxiomAudit.lean"),
    (ROOT / "verification/aeneas", "Proof.lean"),
    (ROOT / "verification/aeneas", "ReassemblyProof.lean"),
    (ROOT / "verification/aeneas", "ProtectedProof.lean"),
    (ROOT / "verification/aeneas", "KeyScheduleProof.lean"),
    (ROOT / "verification/aeneas", "ClientProof.lean"),
)
records = {}
for directory, filename in AUDITS:
    source = (directory / filename).read_text()
    expected = set(re.findall(r"^#print\s+axioms\s+([\w.]+)\s*$", source, re.MULTILINE))
    if not expected:
        raise SystemExit(f"Missing theorem audits in {directory.name}/{filename}")
    run = subprocess.run(["lake", "env", "lean", filename], cwd=directory,
                         capture_output=True, text=True, check=True, timeout=120)
    observed = {}
    for name, dependencies in re.findall(r"'([^']+)' depends on axioms: \[([^]]*)\]", run.stdout):
        observed[name] = {item.strip() for item in dependencies.split(",") if item.strip()}
    for name in re.findall(r"'([^']+)' does not depend on any axioms", run.stdout):
        observed[name] = set()
    if not expected <= observed.keys():
        raise SystemExit(f"Missing audit results: {sorted(expected - observed.keys())}")
    for name in expected:
        unexpected = observed[name] - ALLOWED
        if unexpected:
            raise SystemExit(f"Unreviewed theorem assumptions in {name}: {sorted(unexpected)}")
        records[name] = sorted(observed[name])

report = {"theorems_audited": len(records), "allowed_foundations": sorted(ALLOWED),
          "custom_axioms_or_admissions": False, "dependencies": dict(sorted(records.items()))}
destination = ROOT / "verification/results/axiom-audit.json"
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text(json.dumps(report, indent=2) + "\n")
print(f"Axiom dependency audit passed for {len(records)} theorems; only standard Lean foundations")
