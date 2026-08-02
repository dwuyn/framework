"""Deterministic benchmark matrix generation."""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence


@dataclass(frozen=True)
class MatrixCell:
    case_id: str
    framework: str
    model_revision: str
    budget_tier: str
    track: str
    condition: str
    repetition: int
    run_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "framework": self.framework,
            "model_revision": self.model_revision,
            "budget_tier": self.budget_tier,
            "track": self.track,
            "condition": self.condition,
            "repetition": self.repetition,
            "run_id": self.run_id,
        }


def stable_run_id(dataset_lock_hash: str, framework_sha: str, payload: Mapping[str, Any]) -> str:
    blob = json.dumps({
        "dataset_lock_hash": dataset_lock_hash,
        "framework_sha": framework_sha,
        **dict(payload),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def generate_matrix(
    *,
    test_cases: Sequence[str],
    robustness_cases: Sequence[str],
    frameworks: Sequence[str],
    models: Sequence[Mapping[str, str]],
    dataset_lock_hash: str,
    framework_sha: str,
    repetitions: Iterable[int] = (1, 2, 3),
) -> list[MatrixCell]:
    cells: list[MatrixCell] = []
    model_revisions = [str(model["resource_revision"]) for model in models]

    def add(case_id: str, framework: str, revision: str, budget: str, track: str, condition: str, rep: int) -> None:
        payload = {
            "case_id": case_id,
            "framework": framework,
            "model_revision": revision,
            "budget_tier": budget,
            "track": track,
            "condition": condition,
            "repetition": rep,
        }
        cells.append(MatrixCell(
            case_id=case_id,
            framework=framework,
            model_revision=revision,
            budget_tier=budget,
            track=track,
            condition=condition,
            repetition=rep,
            run_id=stable_run_id(dataset_lock_hash, framework_sha, payload),
        ))

    for case_id in test_cases:
        for framework in frameworks:
            for revision in model_revisions:
                for track in ("blind", "guided"):
                    for rep in repetitions:
                        add(case_id, framework, revision, "medium", track, "main", rep)

    for case_id in test_cases:
        for revision in model_revisions:
            for track in ("blind", "guided"):
                for budget in ("low", "high"):
                    for rep in repetitions:
                        add(case_id, "VeriPlanPT", revision, budget, track, "budget_ablation", rep)

    for case_id in robustness_cases:
        for framework in frameworks:
            for revision in model_revisions:
                for rep in repetitions:
                    add(case_id, framework, revision, "medium", "blind", "robustness", rep)

    seen = set()
    for cell in cells:
        key = (
            cell.case_id, cell.framework, cell.model_revision, cell.budget_tier,
            cell.track, cell.condition, cell.repetition,
        )
        if key in seen:
            raise ValueError(f"duplicate matrix cell: {key}")
        seen.add(key)
    if len(cells) != 3807:
        raise ValueError(f"matrix must contain 3807 cells, got {len(cells)}")
    return cells


def matrix_hash(cells: Sequence[MatrixCell]) -> str:
    blob = json.dumps([cell.to_dict() for cell in cells], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def write_matrix(cells: Sequence[MatrixCell], json_path: str, csv_path: str) -> None:
    rows = [cell.to_dict() for cell in cells]
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2, sort_keys=True)
    with open(csv_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else [])
        writer.writeheader()
        writer.writerows(rows)
