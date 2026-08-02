"""Fail-closed training planner for the 4,560-cell policy protocol.

Dry run is the default.  The module intentionally does not contain a Vertex
client: execution is injected by the experiment service after explicit cost
approval and canary validation.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.pipeline.dataset_lock import load_dataset_lock, lock_hash, validate_dataset_lock
from src.pipeline.protocol import git_state, hash_lock_file, load_json, validate_training_protocol
from src.planning.policy_lock import POLICY_SEED, stratified_folds, weight_grid


@dataclass(frozen=True)
class TrainingCell:
    phase: str
    case_id: str
    fold: int
    model_label: str
    model_profile_hash: str
    budget_tier: str
    track: str
    repetition: int
    weights: dict[str, float] | None
    run_id: str


def _run_id(payload: Mapping[str, Any]) -> str:
    import hashlib

    return hashlib.sha256(json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def training_cells(cases: Sequence[Mapping[str, Any]], profiles: Sequence[Mapping[str, Any]]) -> list[TrainingCell]:
    """Create 4,200 sweep and 360 confirmation cells without touching test data."""
    folds = stratified_folds(cases)
    fold_index = {case_id: index for index, fold in enumerate(folds) for case_id in fold}
    if len(fold_index) != 40 or len(profiles) != 3:
        raise ValueError("training protocol requires 40 cases and 3 model profiles")
    cells: list[TrainingCell] = []
    for weights in weight_grid():
        weight_data = weights.to_dict()
        for case in cases:
            for profile in profiles:
                payload = {
                    "phase": "sweep", "case_id": case["case_id"], "fold": fold_index[case["case_id"]],
                    "model_label": profile["logical_label"], "model_profile_hash": profile["profile_hash"],
                    "budget_tier": "medium", "track": "blind", "repetition": 1, "weights": weight_data,
                }
                cells.append(TrainingCell(**payload, run_id=_run_id(payload)))
    # Confirmation can only use the selected weight at execution time.  Its
    # stable placeholder makes the dry-run count auditable without pretending a
    # winner was already selected.
    for case in cases:
        for profile in profiles:
            for repetition in (1, 2, 3):
                payload = {
                    "phase": "confirmation", "case_id": case["case_id"], "fold": fold_index[case["case_id"]],
                    "model_label": profile["logical_label"], "model_profile_hash": profile["profile_hash"],
                    "budget_tier": "medium", "track": "blind", "repetition": repetition, "weights": None,
                }
                cells.append(TrainingCell(**payload, run_id=_run_id(payload)))
    if len(cells) != 4560 or len({cell.run_id for cell in cells}) != 4560:
        raise ValueError("training plan must contain 4,560 unique cells")
    return cells


def _read_train_cases(dataset_root: Path, lock: Mapping[str, Any]) -> list[dict[str, str]]:
    metadata = dataset_root / "hidden" / "train_case_metadata.json"
    if not metadata.exists():
        raise ValueError("sealed train metadata is missing")
    data = load_json(metadata)
    cases = data.get("cases")
    if not isinstance(cases, list):
        raise ValueError("sealed train metadata cases is invalid")
    expected = set(str(value) for value in lock["train_cases"])
    selected = [dict(case) for case in cases if str(case.get("case_id")) in expected]
    if {str(case.get("case_id")) for case in selected} != expected:
        raise ValueError("sealed train metadata does not match dataset train split")
    if any("test" in str(case) for case in selected):
        raise ValueError("training metadata contains a test path")
    return selected


def plan_training(*, dataset_root: str | Path, protocol_path: str | Path, output_path: str | Path) -> dict[str, Any]:
    root = Path(dataset_root).resolve()
    parts = tuple(part.lower() for part in root.parts)
    is_test_split = root.name.lower() == "test" or any(
        parts[index:index + 2] == ("cases", "test") for index in range(len(parts) - 1)
    )
    if is_test_split or not root.exists():
        raise ValueError("training requires an explicit dataset root, never a test path")
    lock_path = root / "dataset.lock.json"
    lock = load_dataset_lock(lock_path)
    validate_dataset_lock(lock, dataset_root=root)
    protocol = load_json(protocol_path)
    state = git_state(Path(__file__).resolve().parents[2])
    if state["dirty"]:
        raise ValueError("training refuses a dirty framework repository")
    evaluator_commit = str(protocol.get("evaluator_commit") or "")
    validate_training_protocol(protocol, dataset_hash=lock_hash(lock), framework_commit=str(state["commit"]),
                               evaluator_commit=evaluator_commit)
    cases = _read_train_cases(root, lock)
    cells = training_cells(cases, protocol["model_profiles"])
    plan = {
        "schema_version": "2.0.0",
        "seed": POLICY_SEED,
        "dataset_lock_hash": lock_hash(lock),
        "training_protocol_hash": hash_lock_file(protocol_path),
        "cell_count": len(cells),
        "sweep_cell_count": 4200,
        "confirmation_cell_count": 360,
        "estimated_cost_usd": protocol.get("cost_estimate_usd"),
        "cells": [asdict(cell) for cell in cells],
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return plan


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Plan or execute VeriPlanPT policy training.")
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--training-protocol", required=True)
    parser.add_argument("--output", default="training_plan.json")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--approve-cost", action="store_true")
    args = parser.parse_args(argv)
    plan = plan_training(dataset_root=args.dataset_root, protocol_path=args.training_protocol, output_path=args.output)
    if args.execute and not args.approve_cost:
        raise SystemExit("--execute requires --approve-cost before any Vertex call")
    if args.execute:
        raise SystemExit("execution service is intentionally external; use the approved runner with this plan")
    print(json.dumps({key: plan[key] for key in ("cell_count", "sweep_cell_count", "confirmation_cell_count", "estimated_cost_usd")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
