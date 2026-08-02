"""Deterministic, post-policy benchmark matrix generation."""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


@dataclass(frozen=True)
class MatrixCell:
    case_id: str
    framework: str
    framework_commit: str
    framework_image_digest: str
    model_label: str
    model_resource_id: str
    model_revision: str
    dataset_lock_hash: str
    policy_lock_hash: str
    evaluator_commit: str
    budget_tier: str
    track: str
    condition: str
    repetition: int
    run_id: str

    def to_dict(self) -> dict[str, Any]:
        return vars(self)


def stable_run_id(payload: Mapping[str, Any]) -> str:
    """Run identity covers the complete cell, including each baseline revision."""
    blob = json.dumps(dict(payload), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def generate_matrix(
    *,
    test_cases: Sequence[str],
    robustness_cases: Sequence[str],
    frameworks: Sequence[Mapping[str, str]],
    models: Sequence[Mapping[str, str]],
    dataset_lock_hash: str,
    policy_lock_hash: str,
    evaluator_commit: str,
    repetitions: Iterable[int] = (1, 2, 3),
) -> list[MatrixCell]:
    """Generate exactly 3,807 post-policy cells, refusing ambiguous inputs."""
    if not policy_lock_hash:
        raise ValueError("final benchmark matrix requires a policy lock")
    if len(test_cases) != 27 or len(robustness_cases) != 9:
        raise ValueError("matrix requires 27 clean test and 9 robustness cases")
    if len(frameworks) != 5 or len(models) != 3:
        raise ValueError("matrix requires five frameworks and three model profiles")

    cells: list[MatrixCell] = []

    def add(case_id: str, framework: Mapping[str, str], model: Mapping[str, str], budget: str,
            track: str, condition: str, repetition: int) -> None:
        identity = {
            "case_id": case_id,
            "framework": str(framework["name"]),
            "framework_commit": str(framework["commit"]),
            "framework_image_digest": str(framework["image_digest"]),
            "model_label": str(model["logical_label"]),
            "model_resource_id": str(model["resource_id"]),
            "model_revision": str(model["resource_revision"]),
            "dataset_lock_hash": dataset_lock_hash,
            "policy_lock_hash": policy_lock_hash,
            "evaluator_commit": evaluator_commit,
            "budget_tier": budget,
            "track": track,
            "condition": condition,
            "repetition": repetition,
        }
        cells.append(MatrixCell(**identity, run_id=stable_run_id(identity)))

    main_frameworks = list(frameworks)
    veriplan = next((item for item in frameworks if item["name"] == "VeriPlanPT"), None)
    if veriplan is None:
        raise ValueError("matrix frameworks must include VeriPlanPT")
    for case_id in test_cases:
        for framework in main_frameworks:
            for model in models:
                for track in ("blind", "guided"):
                    for repetition in repetitions:
                        add(case_id, framework, model, "medium", track, "main", repetition)
    for case_id in test_cases:
        for model in models:
            for track in ("blind", "guided"):
                for budget in ("low", "high"):
                    for repetition in repetitions:
                        add(case_id, veriplan, model, budget, track, "budget_ablation", repetition)
    for case_id in robustness_cases:
        for framework in main_frameworks:
            for model in models:
                for repetition in repetitions:
                    add(case_id, framework, model, "medium", "blind", "robustness", repetition)
    if len({cell.run_id for cell in cells}) != len(cells) or len(cells) != 3807:
        raise ValueError(f"matrix must contain 3,807 unique cells, got {len(cells)}")
    return cells


def matrix_hash(cells: Sequence[MatrixCell]) -> str:
    blob = json.dumps([cell.to_dict() for cell in cells], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def write_matrix(cells: Sequence[MatrixCell], json_path: str | Path, csv_path: str | Path) -> None:
    rows = [cell.to_dict() for cell in cells]
    with Path(json_path).open("w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2, sort_keys=True)
        handle.write("\n")
    with Path(csv_path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else [])
        writer.writeheader()
        writer.writerows(rows)
