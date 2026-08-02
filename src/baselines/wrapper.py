"""Common RunArtifact v2 wrapper for external baseline frameworks."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from typing import Any, Sequence

from src.pipeline.budget import BudgetTier
from src.pipeline.data_bridge import _load_model_profile
from src.pipeline.framework_adapter import PublicTask, RunArtifact


def run_baseline_command(
    *,
    framework: str,
    command: Sequence[str],
    public_task: PublicTask,
    run_dir: str,
    model_profile_path: str,
    budget_tier: BudgetTier,
    repetition: int,
    condition: str,
    automation_wrapper: bool = False,
) -> RunArtifact:
    """Run one pinned baseline command and normalize its output.

    The command may produce its own files, but success/failure is represented
    only by the returned RunArtifact.  This helper does not alter baseline
    planner, memory, retry, or repository state.
    """
    os.makedirs(run_dir, exist_ok=True)
    profile = _load_model_profile(model_profile_path)
    started = time.time()
    proc = subprocess.run(
        list(command),
        cwd=run_dir,
        capture_output=True,
        text=True,
        check=False,
        timeout=budget_tier.to_limits().max_runtime_seconds,
    )
    transcript = [{
        "role": "baseline_wrapper",
        "event": {
            "event_type": "command",
            "framework": framework,
            "argv": list(command),
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "automation_wrapper": automation_wrapper,
        },
    }]
    run_id_payload = {
        "framework": framework,
        "case_id": public_task.case_id,
        "model_revision": profile.resource_revision,
        "budget": budget_tier.value,
        "track": public_task.track,
        "condition": condition,
        "repetition": repetition,
    }
    import hashlib

    run_id = hashlib.sha256(json.dumps(run_id_payload, sort_keys=True).encode()).hexdigest()[:32]
    artifact = RunArtifact(
        case_id=public_task.case_id,
        repetition=repetition,
        track=public_task.track,
        condition=condition,
        model_profile=profile,
        budget_tier=budget_tier,
        run_id=run_id,
        run_dir=run_dir,
        termination_status="completed" if proc.returncode == 0 else "infrastructure_failure",
        internal_outcome="completed" if proc.returncode == 0 else "infrastructure_failure",
        transcript=transcript,
        usage={"wall_seconds": round(time.time() - started, 3)},
    )
    artifact.save(os.path.join(run_dir, "run_artifact.json"))
    with open(os.path.join(run_dir, "framework_result.json"), "w", encoding="utf-8") as handle:
        json.dump({
            "schema_version": "compat-1",
            "run_artifact_path": os.path.join(run_dir, "run_artifact.json"),
            "case_id": public_task.case_id,
            "framework": framework,
            "track": public_task.track,
            "condition": condition,
            "repetition": repetition,
            "termination_status": artifact.termination_status,
            "automation_wrapper": automation_wrapper,
        }, handle, indent=2, sort_keys=True)
    return artifact


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--framework", required=True)
    parser.add_argument("--public-task", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--model-profile", required=True)
    parser.add_argument("--budget-tier", choices=[tier.value for tier in BudgetTier], default="medium")
    parser.add_argument("--repetition", type=int, default=1)
    parser.add_argument("--condition", default="main")
    parser.add_argument("--automation-wrapper", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if not args.command:
        raise SystemExit("baseline command is required after --")
    with open(args.public_task, encoding="utf-8") as handle:
        task_data: dict[str, Any] = json.load(handle)
    run_baseline_command(
        framework=args.framework,
        command=args.command,
        public_task=PublicTask.from_dict(task_data),
        run_dir=args.run_dir,
        model_profile_path=args.model_profile,
        budget_tier=BudgetTier.from_str(args.budget_tier),
        repetition=args.repetition,
        condition=args.condition,
        automation_wrapper=args.automation_wrapper,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
