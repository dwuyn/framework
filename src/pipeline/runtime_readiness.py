"""Offline construction and hash validation for runtime readiness evidence."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.protocol import write_json_atomically
from src.pipeline.readiness_evidence import FRAMEWORKS, validate_smoke_evidence


def _canonical_hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def worst_case_cost_usd(
    profile: ModelProfile, *, max_input_tokens: int, max_output_tokens: int, max_attempts: int,
) -> float:
    """Return the conservative reservation from the pinned profile price."""
    if max_input_tokens <= 0 or max_output_tokens <= 0 or not 1 <= max_attempts <= 3:
        raise ValueError("runtime cost requires positive token caps and one to three attempts")
    per_attempt = (
        max_input_tokens * float(profile.pricing["input_per_million"])
        + max_output_tokens * float(profile.pricing["output_per_million"])
    ) / 1_000_000
    return per_attempt * max_attempts


def build_canary_smoke_plan(
    *, profiles: Sequence[ModelProfile], framework_costs: Mapping[str, float] | None = None,
    canary_cost: float | None = None,
    dataset_lock_hash: str = "", baseline_identity_hash: str = "",
    model_resolution_lock_hash: str = "", evaluator_hash: str = "", oracle_hash: str = "",
    image_digests: Mapping[str, str] | None = None, native_identity_hash: str = "",
    max_input_tokens: int = 0, max_output_tokens: int = 0,
    retry_policy: Mapping[str, Any] | None = None, strict: bool = False,
) -> dict[str, Any]:
    """Make exactly 3 canaries plus the 15 required framework/model smokes."""
    labels = sorted(profile.logical_label for profile in profiles)
    if len(labels) != 3 or len(set(labels)) != 3:
        raise ValueError("runtime readiness requires exactly three model profiles")
    if framework_costs is not None and set(framework_costs) != FRAMEWORKS:
        raise ValueError("runtime readiness requires all five framework costs")
    if strict:
        required_digests = {
            "dataset_lock_hash": dataset_lock_hash,
            "baseline_identity_hash": baseline_identity_hash,
            "model_resolution_lock_hash": model_resolution_lock_hash,
            "evaluator_hash": evaluator_hash,
            "oracle_hash": oracle_hash,
            "native_identity_hash": native_identity_hash,
        }
        if any(len(str(value)) != 64 for value in required_digests.values()):
            raise ValueError("strict runtime plan requires all upstream SHA-256 identities")
        if max_input_tokens <= 0 or max_output_tokens <= 0:
            raise ValueError("strict runtime plan requires positive token caps")
        if not retry_policy or not 1 <= int(retry_policy.get("max_attempts", 0)) <= 3:
            raise ValueError("strict runtime plan requires a retry policy")
        if framework_costs is not None or canary_cost is not None:
            raise ValueError("strict runtime plan derives reservation from pinned pricing and token caps")
        if not image_digests or any(
            not re.fullmatch(r"sha256:[0-9a-f]{64}", str(image_digests.get(name, "")))
            for name in FRAMEWORKS
        ):
            raise ValueError("strict runtime plan requires immutable framework image digests")
    retry = dict(retry_policy or {"max_attempts": 1, "retryable": ["infrastructure_failure"]})
    attempts = int(retry["max_attempts"])
    if not strict and (framework_costs is None or canary_cost is None):
        raise ValueError("non-strict runtime plan requires explicit legacy costs")
    legacy_framework_costs = framework_costs or {}
    legacy_canary_cost = float(canary_cost or 0.0)
    images = dict(image_digests or {})
    cells: list[dict[str, Any]] = []

    def identity(*, kind: str, label: str, framework: str = "") -> dict[str, Any]:
        profile = next(profile for profile in profiles if profile.logical_label == label)
        cost = (
            worst_case_cost_usd(profile, max_input_tokens=max_input_tokens,
                                max_output_tokens=max_output_tokens, max_attempts=attempts)
            if strict else (legacy_canary_cost if not framework else float(legacy_framework_costs[framework]))
        )
        record: dict[str, Any] = {
            "kind": kind, "model_label": label,
            "model_profile_hash": profile.profile_hash,
            "model_resource_id": profile.resource_id,
            "model_revision": profile.resource_revision,
            "dataset_lock_hash": dataset_lock_hash,
            "baseline_identity_hash": baseline_identity_hash,
            "native_identity_hash": native_identity_hash,
            "model_resolution_lock_hash": model_resolution_lock_hash,
            "evaluator_hash": evaluator_hash,
            "oracle_hash": oracle_hash,
            "image_digest": images.get(framework, "") if framework else images.get("VeriPlanPT", ""),
            "max_input_tokens": max_input_tokens,
            "max_output_tokens": max_output_tokens,
            "retry_policy": retry,
            "cell_worst_case_cost_usd": float(cost),
        }
        return record

    for label in labels:
        cell = identity(kind="vertex_canary", label=label)
        cell.update({"run_id": f"canary-{label}"})
        cells.append(cell)
    for framework in sorted(FRAMEWORKS):
        for label in labels:
            cell = identity(kind="framework_model_smoke", label=label, framework=framework)
            cell.update({"run_id": f"smoke-{framework.lower()}-{label}", "framework": framework})
            cells.append(cell)
    plan = {"schema_version": "1.0.0", "stage": "canary_smoke", "cell_count": len(cells), "cells": cells}
    plan["plan_hash"] = _canonical_hash(plan)
    if strict:
        validate_canary_smoke_plan(plan, profiles=profiles, strict=True)
    return plan


def validate_canary_smoke_plan(
    plan: Mapping[str, Any], *, profiles: Sequence[ModelProfile], strict: bool = False,
) -> None:
    """Validate the exact 3+15 cell shape and, in runtime mode, every pin."""
    if plan.get("stage") != "canary_smoke" or int(plan.get("cell_count", 0)) != 18:
        raise ValueError("canary smoke plan must contain exactly 18 cells")
    supplied_hash = str(plan.get("plan_hash", ""))
    unsigned_plan = {key: value for key, value in plan.items() if key != "plan_hash"}
    if strict and not supplied_hash:
        raise ValueError("strict canary smoke plan requires plan_hash")
    if supplied_hash and supplied_hash != _canonical_hash(unsigned_plan):
        raise ValueError("canary smoke plan hash does not match its contents")
    cells = plan.get("cells")
    if not isinstance(cells, list) or len(cells) != 18:
        raise ValueError("canary smoke plan cells must contain exactly 18 records")
    labels = {profile.logical_label for profile in profiles}
    if len(labels) != 3:
        raise ValueError("canary smoke plan requires exactly three model profiles")
    canaries = [cell for cell in cells if isinstance(cell, Mapping) and cell.get("kind") == "vertex_canary"]
    smokes = [cell for cell in cells if isinstance(cell, Mapping) and cell.get("kind") == "framework_model_smoke"]
    if {str(cell.get("model_label")) for cell in canaries} != labels or len(canaries) != 3:
        raise ValueError("canary plan must cover each model exactly once")
    pairs = {(str(cell.get("framework")), str(cell.get("model_label"))) for cell in smokes}
    expected = {(framework, label) for framework in FRAMEWORKS for label in labels}
    if len(smokes) != 15 or pairs != expected:
        raise ValueError("canary plan must cover every framework/model pair")
    if len({str(cell.get("run_id", "")) for cell in cells}) != 18:
        raise ValueError("canary smoke run IDs must be unique")
    if strict:
        required = {
            "model_profile_hash", "model_resource_id", "model_revision", "dataset_lock_hash",
            "baseline_identity_hash", "native_identity_hash", "model_resolution_lock_hash",
            "evaluator_hash", "oracle_hash", "image_digest", "max_input_tokens",
            "max_output_tokens", "retry_policy", "cell_worst_case_cost_usd",
        }
        for cell in cells:
            if not required.issubset(cell):
                raise ValueError("strict canary smoke cell is missing an immutable pin")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(cell["image_digest"])):
                raise ValueError("strict canary smoke cell requires an immutable image digest")
            for key in ("dataset_lock_hash", "baseline_identity_hash", "native_identity_hash",
                        "model_resolution_lock_hash", "evaluator_hash", "oracle_hash", "model_profile_hash"):
                if len(str(cell[key])) != 64:
                    raise ValueError(f"strict canary smoke cell {key} must be SHA-256")
            if int(cell["max_input_tokens"]) <= 0 or int(cell["max_output_tokens"]) <= 0:
                raise ValueError("strict canary smoke cell token caps must be positive")
            policy = cell["retry_policy"]
            if not isinstance(policy, Mapping) or not 1 <= int(policy.get("max_attempts", 0)) <= 3:
                raise ValueError("strict canary smoke cell retry policy is invalid")
            label = str(cell["model_label"])
            profile = next(profile for profile in profiles if profile.logical_label == label)
            if str(cell["model_profile_hash"]) != profile.profile_hash:
                raise ValueError(f"strict canary smoke profile hash mismatch for {label}")
            if str(cell["model_resource_id"]) != profile.resource_id:
                raise ValueError(f"strict canary smoke resource mismatch for {label}")
            if str(cell["model_revision"]) != profile.resource_revision:
                raise ValueError(f"strict canary smoke revision mismatch for {label}")
            cost = float(cell["cell_worst_case_cost_usd"])
            if not math.isfinite(cost) or cost <= 0:
                raise ValueError("strict canary smoke cell cost must be positive and finite")
            expected_cost = worst_case_cost_usd(
                profile, max_input_tokens=int(cell["max_input_tokens"]),
                max_output_tokens=int(cell["max_output_tokens"]),
                max_attempts=int(policy["max_attempts"]),
            )
            if abs(cost - expected_cost) > 1e-12:
                raise ValueError("strict canary smoke cell reservation does not match pinned pricing")


def write_runtime_smoke_evidence(
    *, artifact_root: str | Path, dataset_lock_hash: str, dataset_evidence_hash: str,
    canaries: Sequence[Mapping[str, Any]], smokes: Sequence[Mapping[str, Any]], output: str = "readiness/runtime-smoke-evidence.json",
    plan_hash: str = "", training_protocol_hash: str = "", baseline_lock_hash: str = "",
    model_resolution_lock_hash: str = "", pricing_snapshot_hash: str = "", approval_hash: str = "",
) -> Path:
    """Write only source-backed readiness evidence, then rehash it immediately."""
    root = Path(artifact_root).resolve()
    strict = bool(plan_hash or training_protocol_hash or baseline_lock_hash or model_resolution_lock_hash or pricing_snapshot_hash or approval_hash)
    evidence = {
        "schema_version": "2.1.0" if strict else "2.0.0",
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "dataset_lock_hash": dataset_lock_hash,
        "dataset_evidence_hash": dataset_evidence_hash,
        "vertex_canaries": [dict(record) for record in canaries],
        "framework_model_smokes": [dict(record) for record in smokes],
    }
    if strict:
        evidence.update({
            "plan_hash": plan_hash, "training_protocol_hash": training_protocol_hash,
            "baseline_lock_hash": baseline_lock_hash,
            "model_resolution_lock_hash": model_resolution_lock_hash,
            "pricing_snapshot_hash": pricing_snapshot_hash, "approval_hash": approval_hash,
        })
    validate_smoke_evidence(evidence, base_case_ids=[], model_labels=[
        str(record.get("model_label", "")) for record in canaries
    ], mode="runtime-smoke", artifact_root=root)
    destination = root / output
    write_json_atomically(destination, evidence)
    return destination
