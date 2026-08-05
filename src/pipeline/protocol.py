"""One-way experiment-lock graph and fail-closed repository checks."""

from __future__ import annotations

import hashlib
import json
import os
import re
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


EXPECTED_BASELINE_COMMITS = {
    "PentestAgent": "97ac5be7ba47377b235a7eebe64d53539084d229",
    "PentestGPT": "8650718334ec97b3eba5fa55ec6c87153a21eb34",
    "VulnBot": "951cbcc456e6ab972fe5015230e8ebf1bd9e32af",
    "HackSynth": "48a41f795dda186df66561c4fd2b58ae84e3e4f8",
}


def validate_baseline_lock(
    lock: Mapping[str, Any], *, strict: bool = False, baseline_root: str | Path | None = None,
) -> None:
    entries = lock.get("baselines")
    if str(lock.get("schema_version")) != "2.0.0" or not isinstance(entries, list) or len(entries) != 4:
        raise ValueError("baseline lock must be v2 with exactly four baselines")
    expected_names = {"PentestAgent", "PentestGPT", "VulnBot", "HackSynth"}
    names = {str(entry.get("name")) for entry in entries if isinstance(entry, Mapping)}
    if names != expected_names:
        raise ValueError("baseline lock must pin PentestAgent, PentestGPT, VulnBot, and HackSynth")
    commits: set[str] = set()
    for entry in entries:
        required = {"repo_url", "commit", "image_digest", "adapter_version"}
        if not required.issubset(entry) or any(not str(entry[key]).strip() for key in required):
            raise ValueError("baseline entry missing immutable source or adapter data")
        if strict:
            name = str(entry.get("name"))
            repo_url = str(entry["repo_url"])
            commit = str(entry["commit"])
            if not repo_url.startswith(("https://", "git@")) or "example.com" in repo_url:
                raise ValueError(f"baseline {name} has an invalid upstream URL")
            if not re.fullmatch(r"[0-9a-f]{40}", commit) or commit in commits:
                raise ValueError("baseline commits must be unique full Git SHAs")
            expected_commit = EXPECTED_BASELINE_COMMITS.get(name)
            if expected_commit and commit != expected_commit:
                raise ValueError(f"baseline {name} is not pinned to the recovery commit")
            commits.add(commit)
            image_digest = str(entry["image_digest"])
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest):
                raise ValueError(f"baseline {name} requires a real image digest")
            adapter_hash = str(entry.get("adapter_bundle_hash") or entry.get("adapter_hash") or "")
            if not re.fullmatch(r"[0-9a-f]{64}", adapter_hash):
                raise ValueError(f"baseline {name} requires an adapter-bundle SHA-256")
            if not str(entry.get("adapter_contract_version") or entry.get("adapter_version") or "").strip():
                raise ValueError(f"baseline {name} requires an adapter contract version")
            for field in ("docker_recipe_hash", "build_context_tree_hash"):
                if not re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{40}", str(entry.get(field, ""))):
                    raise ValueError(f"baseline {name} requires a pinned {field}")
            dependency_hash = str(entry.get("dependency_lock_hash", ""))
            if not re.fullmatch(r"[0-9a-f]{64}", dependency_hash):
                raise ValueError(f"baseline {name} requires a hashed dependency lock")
            input_hashes = entry.get("input_hashes")
            if not isinstance(input_hashes, Mapping) or not input_hashes:
                raise ValueError(f"baseline {name} requires hashed dependency inputs")
            if any(not re.fullmatch(r"[0-9a-f]{64}", str(value)) for value in input_hashes.values()):
                raise ValueError(f"baseline {name} contains an invalid input hash")
            if not isinstance(entry.get("os_package_requirements"), list):
                raise ValueError(f"baseline {name} requires OS-package metadata")
            if baseline_root is not None:
                tree = Path(baseline_root) / name
                state = git_state(tree)
                if state["dirty"] or state["commit"] != commit:
                    raise ValueError(f"baseline {name} detached worktree is not clean at the locked commit")
                if entry.get("tree_hash"):
                    actual_tree = subprocess.run(
                        ["git", "-C", str(tree), "rev-parse", "HEAD^{tree}"],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if actual_tree.returncode or actual_tree.stdout.strip() != str(entry["tree_hash"]):
                        raise ValueError(f"baseline {name} Git tree hash mismatch")
                image = str(entry.get("image", ""))
                if image:
                    inspected = subprocess.run(
                        ["docker", "image", "inspect", "--format", "{{.Id}}", image],
                        capture_output=True, text=True, check=False,
                    )
                    if inspected.returncode or not inspected.stdout.strip().startswith("sha256:"):
                        raise ValueError(f"baseline {name} Docker image is unavailable")
                    if inspected.stdout.strip() != str(entry["image_digest"]):
                        raise ValueError(f"baseline {name} Docker image digest mismatch")


def validate_run_artifact(value: Mapping[str, Any], *, official: bool = True) -> None:
    """Validate a serialized artifact without trusting self-reported outcomes."""
    from src.pipeline.framework_adapter import RunArtifact

    artifact = RunArtifact.from_dict(value)
    if official:
        artifact.validate_official()


def validate_training_protocol(
    protocol: Mapping[str, Any], *, dataset_hash: str, framework_commit: str, evaluator_commit: str,
) -> None:
    required = {
        "schema_version", "dataset_repository_commit", "dataset_lock_hash", "framework_commit",
        "evaluator_source_hash", "evaluator_image_digest", "model_profiles", "feature_schema_hash",
        "budget_tiers", "cv", "baseline_lock_hash", "selection_rules", "expected_training_cells",
        "snapshot_mode", "cost_estimate_usd", "pricing_snapshot",
    }
    missing = sorted(required.difference(protocol))
    if missing:
        raise ValueError(f"training protocol missing required field(s): {', '.join(missing)}")
    if str(protocol["schema_version"]) != "3.0.0":
        raise ValueError("training protocol schema_version must be 3.0.0")
    if str(protocol["dataset_lock_hash"]) != dataset_hash:
        raise ValueError("training protocol dataset hash mismatch")
    if not str(protocol["dataset_repository_commit"]).strip():
        raise ValueError("training protocol requires the downstream dataset repository commit")
    if str(protocol["framework_commit"]) != framework_commit or str(protocol["evaluator_source_hash"]) != evaluator_commit:
        raise ValueError("training protocol code commit mismatch")
    if not str(protocol["evaluator_image_digest"]).startswith("sha256:"):
        raise ValueError("training protocol requires an evaluator image digest")
    if not isinstance(protocol["feature_schema_hash"], str) or len(protocol["feature_schema_hash"]) != 64:
        raise ValueError("training protocol requires a feature schema SHA-256")
    if protocol["budget_tiers"] != ["low", "medium", "high"]:
        raise ValueError("training protocol budget tiers mismatch")
    if protocol["expected_training_cells"] != {"sweep": 4200, "confirmation": 360, "total": 4560}:
        raise ValueError("training protocol cell-count contract mismatch")
    if protocol["snapshot_mode"] != "frozen":
        raise ValueError("training protocol must use frozen snapshots")
    profiles = protocol["model_profiles"]
    if not isinstance(profiles, list) or len(profiles) != 3:
        raise ValueError("training protocol must contain exactly three model profiles")
    labels: set[str] = set()
    for item in profiles:
        profile = ModelProfile.from_dict(item)
        if item.get("profile_hash") != profile.profile_hash:
            raise ValueError("training protocol model profile hash mismatch")
        labels.add(profile.logical_label)
        if profile.resolution_mode == "provider_alias":
            resolution = protocol.get("model_resolution_lock")
            if not isinstance(resolution, Mapping):
                raise ValueError("provider alias profiles require model_resolution_lock")
            if not isinstance(resolution.get("artifact_path"), str) or not re.fullmatch(
                r"[0-9a-f]{64}", str(resolution.get("sha256", ""))
            ):
                raise ValueError("model_resolution_lock requires an artifact path and SHA-256")
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
