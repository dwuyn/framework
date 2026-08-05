"""Offline construction and hash validation for runtime readiness evidence."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.protocol import write_json_atomically
from src.pipeline.readiness_evidence import FRAMEWORKS, validate_smoke_evidence


def _canonical_hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def build_canary_smoke_plan(
    *, profiles: Sequence[ModelProfile], framework_costs: Mapping[str, float], canary_cost: float,
) -> dict[str, Any]:
    """Make exactly 3 canaries plus the 15 required framework/model smokes."""
    labels = sorted(profile.logical_label for profile in profiles)
    if len(labels) != 3 or len(set(labels)) != 3 or set(framework_costs) != FRAMEWORKS:
        raise ValueError("runtime readiness requires three profiles and all five frameworks")
    if canary_cost <= 0 or any(float(value) <= 0 for value in framework_costs.values()):
        raise ValueError("runtime readiness costs must be positive")
    cells: list[dict[str, Any]] = []
    for label in labels:
        cells.append({"run_id": f"canary-{label}", "kind": "vertex_canary", "model_label": label,
                      "cell_worst_case_cost_usd": canary_cost})
    for framework in sorted(FRAMEWORKS):
        for label in labels:
            cells.append({"run_id": f"smoke-{framework.lower()}-{label}", "kind": "framework_model_smoke",
                          "framework": framework, "model_label": label,
                          "cell_worst_case_cost_usd": float(framework_costs[framework])})
    plan = {"schema_version": "1.0.0", "stage": "canary_smoke", "cell_count": len(cells), "cells": cells}
    plan["plan_hash"] = _canonical_hash(plan)
    return plan


def write_runtime_smoke_evidence(
    *, artifact_root: str | Path, dataset_lock_hash: str, dataset_evidence_hash: str,
    canaries: Sequence[Mapping[str, Any]], smokes: Sequence[Mapping[str, Any]], output: str = "readiness/runtime-smoke-evidence.json",
) -> Path:
    """Write only source-backed readiness evidence, then rehash it immediately."""
    root = Path(artifact_root).resolve()
    evidence = {
        "schema_version": "2.0.0",
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "dataset_lock_hash": dataset_lock_hash,
        "dataset_evidence_hash": dataset_evidence_hash,
        "vertex_canaries": [dict(record) for record in canaries],
        "framework_model_smokes": [dict(record) for record in smokes],
    }
    validate_smoke_evidence(evidence, base_case_ids=[], model_labels=[
        str(record.get("model_label", "")) for record in canaries
    ], mode="runtime-smoke", artifact_root=root)
    destination = root / output
    write_json_atomically(destination, evidence)
    return destination
