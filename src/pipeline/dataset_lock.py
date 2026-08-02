"""Immutable dataset-lock validation and content hashing.

The dataset lock is deliberately the root of the experiment dependency graph.
It never references a policy or benchmark matrix; those artifacts reference it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


def canonical_hash(value: Any) -> str:
    """Hash JSON data in one canonical representation."""
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def lock_hash(lock: Mapping[str, Any]) -> str:
    """Hash a lock excluding its optional self-reported hash."""
    payload = {key: value for key, value in lock.items() if key != "lock_hash"}
    return canonical_hash(payload)


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


_EXCLUDED_PARTS = frozenset({".git", "results", "readiness", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"})
_EXCLUDED_NAMES = frozenset({"dataset.lock.json"})


def tree_file_hashes(root: str | Path) -> dict[str, str]:
    """Hash only immutable dataset content, never locks or runtime output."""
    root_path = Path(root).resolve()
    hashes: dict[str, str] = {}
    for path in sorted(root_path.rglob("*")):
        relative = path.relative_to(root_path)
        if (
            not path.is_file()
            or path.name in _EXCLUDED_NAMES
            or _EXCLUDED_PARTS.intersection(relative.parts)
            or path.suffix in {".log", ".pyc"}
        ):
            continue
        hashes[relative.as_posix()] = sha256_file(path)
    return hashes


def tree_hash(root: str | Path) -> str:
    return canonical_hash(tree_file_hashes(root))


def load_dataset_lock(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("dataset lock must contain a JSON object")
    return data


def _opaque_ids(values: Any, name: str, expected: int, split: str) -> list[str]:
    if not isinstance(values, list) or len(values) != expected:
        raise ValueError(f"dataset lock must list exactly {expected} {name}")
    ids = [str(value) for value in values]
    if len(set(ids)) != len(ids) or any(not value.startswith(f"vp-{split}-") for value in ids):
        raise ValueError(f"dataset lock {name} must contain unique opaque vp-{split}-* IDs")
    return ids


def validate_dataset_lock(lock: Mapping[str, Any], *, dataset_root: str | Path | None = None) -> None:
    """Validate the v3 root lock without permitting downstream references."""
    required = {
        "schema_version", "frozen_at", "source_snapshot_at", "content_tree_hash", "file_hashes",
        "train_cases", "validation_cases", "test_cases", "robustness_variants", "snapshot_manifest_hash",
        "migration_report_hash", "replacement_fidelity_summary",
    }
    missing = sorted(required.difference(lock))
    if missing:
        raise ValueError(f"dataset lock missing required field(s): {', '.join(missing)}")
    unexpected = set(lock).difference(required)
    if unexpected:
        raise ValueError(f"dataset lock contains non-root field(s): {', '.join(sorted(unexpected))}")
    if str(lock["schema_version"]) != "3.0.0":
        raise ValueError("dataset lock schema_version must be 3.0.0")
    forbidden = {"policy_hash", "matrix_hash", "training_protocol_hash", "dataset_commit", "lock_hash"}.intersection(lock)
    if forbidden:
        raise ValueError(f"dataset lock must not reference downstream artifact(s): {', '.join(sorted(forbidden))}")
    _opaque_ids(lock["train_cases"], "train_cases", 40, "train")
    _opaque_ids(lock["validation_cases"], "validation_cases", 27, "validation")
    _opaque_ids(lock["test_cases"], "test_cases", 27, "test")
    variants = lock["robustness_variants"]
    if not isinstance(variants, list) or len(variants) != 9:
        raise ValueError("dataset lock must list exactly 9 robustness variants")
    types = {str(item.get("kind")) for item in variants if isinstance(item, Mapping)}
    expected_types = {"decoy_service", "ambiguous_banner", "transient_failure"}
    if types != expected_types or any(sum(1 for item in variants if item.get("kind") == kind) != 3 for kind in expected_types):
        raise ValueError("robustness variants must contain three cases for each required kind")
    hashes = lock["file_hashes"]
    if not isinstance(hashes, Mapping) or not hashes:
        raise ValueError("dataset lock file_hashes must be a non-empty mapping")
    if any(len(str(value)) != 64 for value in hashes.values()):
        raise ValueError("dataset lock file_hashes must contain SHA-256 values")
    if dataset_root is not None:
        actual = tree_file_hashes(dataset_root)
        expected = {str(key): str(value) for key, value in hashes.items()}
        if actual != expected:
            raise ValueError("dataset tree file hashes do not match dataset lock")
        if str(lock["content_tree_hash"]) != canonical_hash(expected):
            raise ValueError("dataset tree hash does not match file hashes")
