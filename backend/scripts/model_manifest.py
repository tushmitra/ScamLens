#!/usr/bin/env python3
"""Write models/MANIFEST.json: file names, sizes, sha256 and key metadata for every artifact.

Phase 0 of the plan asks for artifact filenames and hashes to be recorded so the backup
(`targeted_model.joblib`) can be shown to be unchanged. Re-run after exporting a new model;
compare the old and new manifest to confirm the backup's hash did not move.

Usage (from backend/):  python scripts/model_manifest.py [--dir models]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(directory: Path) -> dict:
    files = []
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.name in {"MANIFEST.json", ".gitkeep", "README.md"}:
            continue
        entry = {"name": path.name, "bytes": path.stat().st_size, "sha256": sha256_file(path)}
        if path.suffix == ".json":
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                entry["metadata"] = {k: data[k] for k in ("selected_model", "model_type", "artifact", "sklearn_version") if k in data}
            except (OSError, ValueError):
                entry["metadata"] = "unreadable"
        files.append(entry)
    return {"generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "files": files}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dir", default=str(Path(__file__).resolve().parent.parent / "models"))
    args = parser.parse_args(argv)
    directory = Path(args.dir)
    if not directory.is_dir():
        raise SystemExit(f"Model directory not found: {directory}")
    manifest = build_manifest(directory)
    (directory / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    for entry in manifest["files"]:
        print(f"{entry['sha256'][:16]}  {entry['bytes']:>10,}  {entry['name']}")
    if not manifest["files"]:
        print("No artifacts found in", directory)
    return 0


if __name__ == "__main__":
    sys.exit(main())
