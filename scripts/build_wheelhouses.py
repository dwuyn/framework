#!/usr/bin/env python3
"""Download hashed wheels into the external artifact cache and manifest them."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import time
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


def target_python() -> str:
    result = subprocess.run(["uv", "python", "find", "3.11"], capture_output=True, text=True, check=False)
    if result.returncode or not result.stdout.strip():
        raise RuntimeError(f"CPython 3.11 is unavailable: {result.stderr.strip()}")
    return result.stdout.strip().splitlines()[-1]


def download(
    lock: Path,
    destination: Path,
    *,
    cpu: bool,
    python: str,
    attempts: int,
    network_timeout: int,
) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    command = [
        python, "-m", "pip", "download", "--dest", str(destination),
        "--require-hashes", "--prefer-binary",
        "--timeout", str(network_timeout), "--retries", "0",
        "-r", str(lock),
    ]
    if cpu:
        command.extend(["--extra-index-url", "https://download.pytorch.org/whl/cpu"])
    last_detail = ""
    for attempt in range(1, attempts + 1):
        try:
            result = subprocess.run(
                command, cwd=ROOT, capture_output=True, text=True, check=False,
                timeout=max(300, network_timeout * 20),
            )
        except subprocess.TimeoutExpired as exc:
            last_detail = f"attempt {attempt} timed out after {max(300, network_timeout * 20)}s: {exc}"
            result = None
        if result is not None and result.returncode == 0:
            return
        if result is not None:
            last_detail = (result.stderr or result.stdout).strip()[-4_000:]
        if attempt < attempts:
            time.sleep(min(2 ** (attempt - 1), 8))
    raise RuntimeError(f"wheelhouse download failed for {lock} after {attempts} attempts: {last_detail}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", default=str(ROOT / "build/dependency-envelopes/envelopes.json"))
    parser.add_argument("--artifact-root", default=str(DEFAULT_ARTIFACT_ROOT))
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--network-timeout", type=int, default=30)
    args = parser.parse_args()
    if args.attempts < 1 or args.network_timeout < 1:
        raise SystemExit("--attempts and --network-timeout must be positive")
    metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
    artifact_root = Path(args.artifact_root).resolve()
    manifest_path = artifact_root / "wheelhouse-manifest.json"
    previous_manifest = {}
    if manifest_path.is_file():
        previous_manifest = json.loads(manifest_path.read_text(encoding="utf-8")).get("wheelhouses", {})
    python = target_python()
    wheelhouses: dict[str, Any] = {}
    for envelope in metadata["envelopes"]:
        name = str(envelope["name"])
        lock = ROOT / str(envelope["dependency_lock"]["path"])
        destination = artifact_root / "wheelhouses" / name
        previous = previous_manifest.get(name, {})
        reusable = (
            destination.is_dir()
            and previous.get("dependency_lock_sha256") == envelope["dependency_lock"]["sha256"]
            and any(destination.iterdir())
        )
        if destination.exists() and not reusable:
            for child in destination.iterdir():
                if child.is_file() or child.is_symlink():
                    child.unlink()
                elif child.is_dir():
                    shutil.rmtree(child)
        download(
            lock, destination, cpu=name == "HackSynth", python=python,
            attempts=args.attempts, network_timeout=args.network_timeout,
        )
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
