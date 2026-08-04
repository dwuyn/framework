#!/usr/bin/env python3
"""Download hashed wheels into the external artifact cache and manifest them."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT_ROOT = ROOT.parent / "veriplanpt-artifacts"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download(lock: Path, destination: Path, *, cpu: bool) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    command = [
        "python3", "-m", "pip", "download", "--dest", str(destination),
        "--require-hashes", "--only-binary=:all:",
        "--platform", "manylinux_2_17_x86_64", "--python-version", "3.11",
        "--implementation", "cp", "--abi", "cp311", "-r", str(lock),
    ]
    if cpu:
        command.extend(["--extra-index-url", "https://download.pytorch.org/whl/cpu"])
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[-4_000:]
        raise RuntimeError(f"wheelhouse download failed for {lock}: {detail}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", default=str(ROOT / "build/dependency-envelopes/envelopes.json"))
    parser.add_argument("--artifact-root", default=str(DEFAULT_ARTIFACT_ROOT))
    args = parser.parse_args()
    metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
    artifact_root = Path(args.artifact_root).resolve()
    wheelhouses: dict[str, Any] = {}
    for envelope in metadata["envelopes"]:
        name = str(envelope["name"])
        lock = ROOT / str(envelope["dependency_lock"]["path"])
        destination = artifact_root / "wheelhouses" / name
        if destination.exists():
            for child in destination.iterdir():
                if child.is_file() or child.is_symlink():
                    child.unlink()
                elif child.is_dir():
                    shutil.rmtree(child)
        download(lock, destination, cpu=name == "HackSynth")
        files = []
        for path in sorted(destination.iterdir()):
            if not path.is_file():
                continue
            files.append({
                "filename": path.name,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            })
        wheelhouses[name] = {
            "path": str(destination),
            "dependency_lock_sha256": str(envelope["dependency_lock"]["sha256"]),
            "files": files,
        }
    manifest = {
        "schema_version": "1.0.0",
        "target": metadata["target"],
        "wheelhouses": wheelhouses,
    }
    output = artifact_root / "wheelhouse-manifest.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "envelopes": len(wheelhouses)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
