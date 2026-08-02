"""Dataset lock validation for freeze/readiness gates."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

REQUIRED_REPLACEMENTS = {
    "marimo": ("0.20.4", "0.23.0"),
    "quarkus": ("3.34.6", "3.34.7"),
    "kirby": ("5.4.0", "5.4.1"),
    "fuxa": ("1.3.0", "1.3.1"),
}


def lock_hash(lock: Mapping[str, Any]) -> str:
    blob = json.dumps(lock, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def load_dataset_lock(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def validate_dataset_lock(lock: Mapping[str, Any], *, require_policy: bool = True) -> None:
    required = {
        "schema_version",
        "locked_at",
        "snapshot_cutoff",
        "constructed_before_freeze",
        "tree_hash",
        "file_hashes",
        "train_cases",
        "test_cases",
        "model_profiles",
        "policy_hash",
        "matrix_hash",
    }
    missing = [key for key in sorted(required) if key not in lock]
    if missing:
        raise ValueError(f"dataset lock missing required field(s): {', '.join(missing)}")
    if lock.get("constructed_before_freeze") is not True:
        raise ValueError("dataset lock must declare constructed_before_freeze=true")
    train_cases = list(lock.get("train_cases") or [])
    test_cases = list(lock.get("test_cases") or [])
    if len(train_cases) != 40:
        raise ValueError(f"dataset lock must list exactly 40 train cases, got {len(train_cases)}")
    if len(test_cases) != 27:
        raise ValueError(f"dataset lock must list exactly 27 test cases, got {len(test_cases)}")
    for case_id in train_cases + test_cases:
        if str(case_id).startswith("CVE-"):
            raise ValueError("dataset lock public case lists must use opaque IDs")
    profiles = list(lock.get("model_profiles") or [])
    if len(profiles) != 3:
        raise ValueError("dataset lock must contain exactly three model profiles")
    for profile in profiles:
        if profile.get("resource_revision") in {"", "benchmark-pinned", None}:
            raise ValueError("dataset lock model profile contains placeholder revision")
    if require_policy and not lock.get("policy_hash"):
        raise ValueError("dataset lock missing policy_hash")
    replacements = lock.get("replacement_cases") or lock.get("new_cases_replacing_emulator_cves") or []
    by_product = {str(item.get("product", "")).lower(): item for item in replacements}
    for product, (vulnerable, fixed) in REQUIRED_REPLACEMENTS.items():
        match = next((item for key, item in by_product.items() if product in key), None)
        if not match:
            raise ValueError(f"dataset lock missing replacement case for {product}")
        if str(match.get("vulnerable_version")) != vulnerable or str(match.get("fixed_version")) != fixed:
            raise ValueError(f"dataset lock replacement versions are wrong for {product}")
