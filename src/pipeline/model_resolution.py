"""Hash-pinned model-resolution evidence for Vertex benchmark profiles."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.vertex_runtime import VertexContractError, validate_resolution_fields


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relative(value: Any, name: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{name} must stay below the artifact root")
    return path


def validate_resolution_lock(
    lock: Mapping[str, Any], *, profiles: Sequence[ModelProfile], artifact_root: str | Path,
) -> None:
    """Rehash each selected provider catalog record and bind it to its profile."""
    if lock.get("schema_version") != "1.0.0" or not str(lock.get("generated_at", "")).endswith("Z"):
        raise ValueError("model resolution lock schema or timestamp is invalid")
    entries = lock.get("models")
    if not isinstance(entries, list) or len(entries) != len(profiles):
        raise ValueError("model resolution lock must contain one record per profile")
    by_label = {str(entry.get("logical_label", "")): entry for entry in entries if isinstance(entry, Mapping)}
    if len(by_label) != len(entries) or set(by_label) != {profile.logical_label for profile in profiles}:
        raise ValueError("model resolution lock labels do not match profiles")
    root = Path(artifact_root).resolve()
    for profile in profiles:
        entry = by_label[profile.logical_label]
        for key, expected in (
            ("resource_id", profile.resource_id),
            ("resource_revision", profile.resource_revision),
            ("resolution_mode", profile.resolution_mode),
            ("resolution_evidence_hash", profile.resolution_evidence_hash),
            ("resolution_resolved_at", profile.resolution_resolved_at),
        ):
            if str(entry.get(key, "")) != expected:
                raise ValueError(f"model resolution lock {profile.logical_label}.{key} mismatch")
        try:
            validate_resolution_fields(
                profile.logical_label, profile.resource_revision, profile.resolution_mode,
                profile.resolution_evidence_hash, profile.resolution_resolved_at,
            )
        except VertexContractError as exc:
            raise ValueError(str(exc)) from exc
        evidence_path = root / _relative(entry.get("metadata_path"), "metadata_path")
        if not evidence_path.is_file():
            raise ValueError(f"model resolution metadata is missing for {profile.logical_label}")
        if _hash_file(evidence_path) != profile.resolution_evidence_hash:
            raise ValueError(f"model resolution metadata hash mismatch for {profile.logical_label}")
