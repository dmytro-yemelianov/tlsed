#!/usr/bin/env python3
"""Fetch only the locked revisions, avoiding unnecessary full-history clones."""

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
manifest = json.loads((ROOT / "lake-manifest.json").read_text())
for package in manifest["packages"]:
    if package["type"] != "git":
        raise SystemExit(f"Unpinned dependency type: {package['name']}")
    folder = ROOT / manifest["packagesDir"] / package["name"]
    if (folder / ".git").exists():
        actual = subprocess.run(
            ["git", "-C", str(folder), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        if actual == package["rev"]:
            continue
        raise SystemExit(f"Existing {package['name']} checkout differs from lock; resolve it explicitly")
    print(f"Fetching {package['name']} at {package['rev']}", flush=True)
    folder.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(folder)], check=True)
    subprocess.run(["git", "-C", str(folder), "remote", "add", "origin", package["url"]], check=True)
    subprocess.run([
        "git", "-C", str(folder), "fetch", "--depth=1", "--no-tags", "origin", package["rev"]
    ], check=True)
    subprocess.run(["git", "-C", str(folder), "checkout", "--detach", "FETCH_HEAD"], check=True)
