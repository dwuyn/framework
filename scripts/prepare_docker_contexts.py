#!/usr/bin/env python3
"""Stage source, adapter, lock and wheelhouse inputs outside Git."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT_ROOT = ROOT.parent / "veriplanpt-artifacts"
IGNORE = shutil.ignore_patterns(
    ".git", ".venv", "venv", "env", "cyber_venv", "__pycache__", ".pytest_cache",
    ".ruff_cache", ".mypy_cache", ".tox", "logs", "data", "Data", "data_test", "results",
    "cases", "hidden", "target", "node_modules", "references", "architecture", "build",
)


def copy_clean(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, ignore=IGNORE, dirs_exist_ok=True)


def link_or_copy(source: Path, destination: Path) -> None:
    try:
        os.link(source, destination)
    except OSError:
        shutil.copyfile(source, destination)


def materialize_lock(lock: Path, wheelhouse: Path, destination: Path) -> None:
    text = lock.read_text(encoding="utf-8")
    for url in sorted(set(re.findall(r"https?://[^\s\\]+", text))):
        filename = url.split("#", 1)[0].rsplit("/", 1)[-1]
        if (wheelhouse / filename).is_file():
            text = text.replace(url, f"file:///opt/wheelhouse/{filename}")
    destination.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", default=str(ROOT / "build/dependency-envelopes/envelopes.json"))
    parser.add_argument("--artifact-root", default=str(DEFAULT_ARTIFACT_ROOT))
    args = parser.parse_args()
    metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
    artifact_root = Path(args.artifact_root).resolve()
    manifest: dict[str, Any] = {"schema_version": "1.0.0", "contexts": {}}
    for envelope in metadata["envelopes"]:
        name = str(envelope["name"])
        context = artifact_root / "baseline-build-contexts" / name
        if context.exists():
            shutil.rmtree(context)
        for directory in (context / "source", context / "envelope", context / "adapter", context / "wheelhouse"):
            directory.mkdir(parents=True, exist_ok=True)
        copy_clean(Path(str(envelope["source"]["path"])), context / "source")
        lock = ROOT / str(envelope["dependency_lock"]["path"])
        wheelhouse = artifact_root / "wheelhouses" / name
        if not wheelhouse.is_dir():
            raise SystemExit(f"wheelhouse missing for {name}: {wheelhouse}")
        materialize_lock(lock, wheelhouse, context / "envelope" / lock.name)
        for wheel in wheelhouse.iterdir():
            if wheel.is_file():
                link_or_copy(wheel, context / "wheelhouse" / wheel.name)
        for role, source_path in dict(envelope["adapter_paths"]).items():
            source = Path(str(source_path))
            shutil.copyfile(source, context / "adapter" / f"{role}-{source.name}")
        shutil.copyfile(ROOT / "docker/adapter/provider_shim.py", context / "adapter/provider_shim.py")
        shutil.copyfile(ROOT / "docker/adapter/entrypoint.sh", context / "adapter/entrypoint.sh")
        manifest["contexts"][name] = {
            "path": str(context),
            "source_commit": envelope["source"]["commit"],
            "source_tree_hash": envelope["source"]["tree_hash"],
            "dependency_lock": str(context / "envelope" / lock.name),
            "wheelhouse": str(context / "wheelhouse"),
        }
    output = artifact_root / "baseline-build-contexts" / "context-manifest.json"
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "contexts": len(manifest["contexts"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
