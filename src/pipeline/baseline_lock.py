"""Generate baseline locks from detached Git trees and Docker inspection."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _git(path: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True, check=False)
    if result.returncode:
        raise ValueError(f"git {' '.join(args)} failed for {path}")
    return result.stdout.strip()


def generate_baseline_lock(
    specs: Sequence[Mapping[str, Any]], *, output: str | Path | None = None,
) -> dict[str, Any]:
    """Read Git HEAD/tree/remote and Docker image digest for each baseline."""
    if len(specs) != 4:
        raise ValueError("baseline lock requires exactly four baseline specs")
    entries: list[dict[str, Any]] = []
    for spec in specs:
        name = str(spec.get("name", ""))
        root = Path(str(spec.get("path", ""))).resolve()
        if not name or not root.is_dir():
            raise ValueError("baseline spec requires an existing path and name")
        if _git(root, "status", "--porcelain"):
            raise ValueError(f"baseline {name} worktree is dirty")
        commit = _git(root, "rev-parse", "HEAD")
        remotes = _git(root, "remote", "-v").splitlines()
        remote = next((line.split()[1] for line in remotes if "(fetch)" in line), "")
        expected_remote = str(spec.get("repo_url", ""))
        if expected_remote and remote and remote != expected_remote:
            raise ValueError(f"baseline {name} remote mismatch")
        image = str(spec.get("image", ""))
        inspect = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True, text=True, check=False,
        )
        if inspect.returncode or not inspect.stdout.strip().startswith("sha256:"):
            raise ValueError(f"baseline {name} image is unavailable or unpinned")
        adapter = Path(str(spec.get("adapter_path", ""))).resolve()
        if not adapter.is_file():
            raise ValueError(f"baseline {name} adapter is missing")
        entries.append({
            "name": name,
            "repo_url": expected_remote or remote,
            "commit": commit,
            "tree_hash": _tree_hash(root),
            "image": image,
            "image_digest": inspect.stdout.strip(),
            "adapter_version": str(spec.get("adapter_version", "")),
            "adapter_hash": hashlib.sha256(adapter.read_bytes()).hexdigest(),
        })
    lock = {"schema_version": "2.0.0", "baselines": entries}
    if output is not None:
        Path(output).write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return lock
