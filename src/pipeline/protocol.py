"""One-way experiment-lock graph and fail-closed repository checks."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Mapping

from src.pipeline.dataset_lock import canonical_hash
from src.pipeline.framework_adapter import ModelProfile


def file_hash(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def write_json_atomically(path: str | Path, value: Mapping[str, Any], *, refuse_existing: bool = False) -> None:
    destination = Path(path)
    if refuse_existing and destination.exists():
        raise FileExistsError(f"refusing to overwrite frozen lock: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=destination.parent, delete=False) as handle:
        json.dump(value, handle, sort_keys=True, indent=2)
        handle.write("\n")
        temporary = Path(handle.name)
    os.replace(temporary, destination)


def git_state(repo: str | Path = ".") -> dict[str, Any]:
    root = str(Path(repo).resolve())
    commit = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], check=False,
                            capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "-C", root, "status", "--porcelain"], check=False,
                                capture_output=True, text=True).stdout.strip())
    return {"commit": commit, "dirty": dirty}


def require_clean_commit(repo: str | Path = ".") -> str:
    state = git_state(repo)
    if not state["commit"]:
        raise ValueError(f"repository has no commit: {Path(repo).resolve()}")
    if state["dirty"]:
        raise ValueError(f"repository is dirty: {Path(repo).resolve()}")
    return str(state["commit"])


def validate_baseline_lock(lock: Mapping[str, Any]) -> None:
    entries = lock.get("baselines")
    if str(lock.get("schema_version")) != "2.0.0" or not isinstance(entries, list) or len(entries) != 4:
        raise ValueError("baseline lock must be v2 with exactly four baselines")
    expected = {"PentestAgent", "PentestGPT", "VulnBot", "HackSynth"}
    names = {str(entry.get("name")) for entry in entries if isinstance(entry, Mapping)}
    if names != expected:
        raise ValueError("baseline lock must pin PentestAgent, PentestGPT, VulnBot, and HackSynth")
    for entry in entries:
        required = {"repo_url", "commit", "image_digest", "adapter_version"}
        if not required.issubset(entry) or any(not str(entry[key]).strip() for key in required):
            raise ValueError("baseline entry missing immutable source or adapter data")


def validate_training_protocol(
    protocol: Mapping[str, Any], *, dataset_hash: str, framework_commit: str, evaluator_commit: str,
) -> None:
    required = {
        "schema_version", "dataset_lock_hash", "framework_commit", "evaluator_commit", "model_profiles",
        "feature_schema", "budget", "cv", "baseline_lock_hash",
    }
    missing = sorted(required.difference(protocol))
    if missing:
        raise ValueError(f"training protocol missing required field(s): {', '.join(missing)}")
    if str(protocol["schema_version"]) != "2.0.0":
        raise ValueError("training protocol schema_version must be 2.0.0")
    if str(protocol["dataset_lock_hash"]) != dataset_hash:
        raise ValueError("training protocol dataset hash mismatch")
    if str(protocol["framework_commit"]) != framework_commit or str(protocol["evaluator_commit"]) != evaluator_commit:
        raise ValueError("training protocol code commit mismatch")
    profiles = protocol["model_profiles"]
    if not isinstance(profiles, list) or len(profiles) != 3:
        raise ValueError("training protocol must contain exactly three model profiles")
    labels: set[str] = set()
    for item in profiles:
        profile = ModelProfile.from_dict(item)
        if item.get("profile_hash") != profile.profile_hash:
            raise ValueError("training protocol model profile hash mismatch")
        labels.add(profile.logical_label)
    if labels != ModelProfile.ALLOWED_MODELS:
        raise ValueError("training protocol does not contain the locked model labels")
    cv = protocol["cv"]
    if cv != {"seed": 20260801, "folds": 5, "cases_per_fold": 8, "track": "blind", "budget_tier": "medium"}:
        raise ValueError("training protocol CV contract mismatch")


def validate_experiment_lock(lock: Mapping[str, Any], *, dataset_hash: str, baseline_hash: str,
                             training_hash: str, policy_hash: str, matrix_hash: str) -> None:
    required = {"schema_version", "dataset_lock_hash", "baseline_lock_hash", "training_protocol_hash",
                "policy_lock_hash", "matrix_hash", "framework_commit", "evaluator_commit"}
    if required.difference(lock):
        raise ValueError("experiment lock missing upstream hashes")
    expected = {
        "dataset_lock_hash": dataset_hash, "baseline_lock_hash": baseline_hash,
        "training_protocol_hash": training_hash, "policy_lock_hash": policy_hash, "matrix_hash": matrix_hash,
    }
    if any(str(lock[key]) != value for key, value in expected.items()):
        raise ValueError("experiment lock upstream hash mismatch")


def hash_lock_file(path: str | Path) -> str:
    return canonical_hash(load_json(path))
