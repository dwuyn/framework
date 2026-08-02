"""Public-task bridge for the external benchmark harness.

The bridge accepts only ``public_task.yml`` and writes framework artifacts;
the harness owns evaluator upload and completion.
"""

from __future__ import annotations

import argparse
import json
import os

import yaml

from src.pipeline.budget import BudgetTier
from src.pipeline.framework_adapter import FrameworkAdapter, ModelProfile, PublicTask


def _load_model_profile(value: str) -> ModelProfile:
    if not value:
        raise ValueError("--model-profile is required and must point to a pinned model profile JSON/YAML file")
    if os.path.exists(value):
        with open(value, encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        if not isinstance(data, dict):
            raise ValueError("model profile file must contain an object")
        return ModelProfile.from_dict(data)
    try:
        data = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("--model-profile must be a profile file path or JSON object, not a logical label") from exc
    if not isinstance(data, dict):
        raise ValueError("--model-profile JSON must be an object")
    return ModelProfile.from_dict(data)


def run_public_task(public_task_path: str, run_dir: str, *, model_profile: str = "",
                    budget_tier: str = "medium", repetition: int = 1,
                    track: str = "", condition: str = "") -> dict:
    with open(public_task_path, encoding="utf-8") as handle:
        task = yaml.safe_load(handle) or {}
    public = PublicTask.from_dict(task)
    if track and track != public.track:
        raise ValueError("CLI track does not match public task track")
    os.makedirs(run_dir, exist_ok=True)

    profile = _load_model_profile(model_profile)
    artifact = FrameworkAdapter(
        results_root=os.path.dirname(os.path.abspath(run_dir)),
        snapshot_dir=os.environ.get("VERIPLANPT_DATASET_ROOT") or os.environ.get("PENTEST_SOURCE_SNAPSHOT", ""),
    ).run(
        public,
        model_profile=profile,
        budget_tier=BudgetTier.from_str(budget_tier),
        repetition=repetition,
        run_dir=run_dir,
        condition=condition,
    )
    artifact_dict = artifact.to_dict()
    run_artifact_path = os.path.join(run_dir, "run_artifact.json")
    summary = {
        "schema_version": "compat-1",
        "run_artifact_path": run_artifact_path,
        "case_id": artifact.case_id,
        "track": artifact.track,
        "condition": artifact.condition,
        "repetition": artifact.repetition,
        "outcome": artifact.internal_outcome,
        "termination_status": artifact_dict["termination_status"],
        "proofs_path": os.path.join(run_dir, "proofs.json"),
        "transcript": os.path.join(run_dir, "events.jsonl"),
        "run_dir": artifact.run_dir,
    }
    with open(os.path.join(run_dir, "framework_result.json"), "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-task", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--model-profile", required=True)
    parser.add_argument("--budget-tier", choices=[tier.value for tier in BudgetTier], default="medium")
    parser.add_argument("--repetition", type=int, default=1)
    parser.add_argument("--track", choices=["blind", "guided"], default="")
    parser.add_argument("--condition", default="")
    args = parser.parse_args()
    print(json.dumps(run_public_task(args.public_task, args.run_dir, model_profile=args.model_profile,
                                     budget_tier=args.budget_tier, repetition=args.repetition,
                                     track=args.track, condition=args.condition), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
