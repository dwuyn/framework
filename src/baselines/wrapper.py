"""Common RunArtifact wrapper for external baseline frameworks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from typing import Any, Mapping, Sequence

from src.pipeline.budget import BudgetTier
from src.pipeline.data_bridge import _load_model_profile
from src.pipeline.framework_adapter import PublicTask, RunArtifact


def _bounded_digest(value: str, *, limit: int = 16_384) -> dict[str, Any]:
    """Keep baseline logs auditable without storing secrets or unbounded output."""
    raw = value.encode("utf-8", errors="replace")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "truncated": len(raw) > limit}


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _load_proof_submissions(run_dir: str) -> list[dict[str, Any]]:
    for name in ("proof_submissions.json", "proof.json"):
        path = os.path.join(run_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as handle:
                value = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return []
        if isinstance(value, list):
            return [dict(item) for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            return [value]
    return []


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
    timed_out = False
    try:
        proc = subprocess.run(
            list(command),
            cwd=run_dir,
            capture_output=True,
            text=True,
            check=False,
            timeout=budget_tier.to_limits().max_runtime_seconds,
        )
        stdout = _text(proc.stdout)
        stderr = _text(proc.stderr)
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = _text(exc.stdout)
        stderr = _text(exc.stderr) or "command timed out"
        returncode = 124
    transcript = [{
        "role": "baseline_wrapper",
        "event": {
            "event_type": "command",
            "framework": framework,
            "argv": list(command),
            "returncode": returncode,
            "stdout": _bounded_digest(stdout),
            "stderr": _bounded_digest(stderr),
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
    normalized_usage = {
        "wall_seconds": round(time.time() - started, 3),
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "total_usd": 0.0,
    }
    proof_submissions = _load_proof_submissions(run_dir)
    budget_exhausted = (
        os.environ.get("VERIPLANPT_BUDGET_EXHAUSTED", "").lower() == "true"
        or os.path.isfile(os.path.join(run_dir, "budget-exhausted.json"))
    )
    if timed_out:
        termination_status = "timeout"
        internal_outcome = "timeout"
        budget_reason = "timeout"
    elif budget_exhausted:
        termination_status = "budget_exhausted"
        internal_outcome = "budget_exhausted"
        budget_reason = "budget_exhausted"
    elif returncode != 0:
        termination_status = "infrastructure_failure"
        internal_outcome = "infrastructure_failure"
        budget_reason = ""
    elif not proof_submissions and not automation_wrapper:
        termination_status = "missing_proof"
        internal_outcome = "missing_proof"
        budget_reason = ""
    else:
        termination_status = "completed"
        internal_outcome = "proof_submitted"
        budget_reason = ""
    framework_key = framework.upper().replace("-", "_")
    artifact = RunArtifact(
        case_id=public_task.case_id,
        repetition=repetition,
        track=public_task.track,
        condition=condition,
        model_profile=profile,
        budget_tier=budget_tier,
        # automation_wrapper=True is retained as a reader-compatible pilot
        # mode; all normal baseline invocations emit the official v2.1 wire
        # contract.
        schema_version="2.0.0" if automation_wrapper else "2.1.0",
        run_id=run_id,
        run_dir=run_dir,
        termination_status=termination_status,
        # A zero process status means only that the wrapper completed.  Proof
        # success remains an evaluator verdict, never a baseline claim.
        internal_outcome=internal_outcome,
        budget_termination_reason=budget_reason,
        transcript=transcript,
        proof_submissions=proof_submissions,
        usage=normalized_usage,
        framework_identity={
            "name": framework,
            "repository_url": os.environ.get(
                f"VERIPLANPT_{framework_key}_REPOSITORY_URL",
                "https://github.com/openai/veriplanpt-baselines",
            ),
            "commit": os.environ.get(f"VERIPLANPT_{framework_key}_COMMIT", ""),
            "image_digest": os.environ.get(f"VERIPLANPT_{framework_key}_IMAGE_DIGEST", ""),
            "adapter_version": f"{framework.lower()}-adapter-3.0",
        },
        run_context={
            "dataset_lock_hash": os.environ.get("VERIPLANPT_DATASET_LOCK_HASH", ""),
            "training_protocol_hash": os.environ.get("VERIPLANPT_TRAINING_PROTOCOL_HASH", ""),
            "gateway_relay_lock_hash": os.environ.get("VERIPLANPT_GATEWAY_RELAY_LOCK_HASH", ""),
            "policy_lock_hash": os.environ.get("VERIPLANPT_POLICY_LOCK_HASH", ""),
            "matrix_hash": os.environ.get("VERIPLANPT_MATRIX_HASH", ""),
            "framework_commit": os.environ.get(f"VERIPLANPT_{framework_key}_COMMIT", ""),
            "evaluator_commit": os.environ.get("VERIPLANPT_EVALUATOR_COMMIT", ""),
            "stage": os.environ.get("VERIPLANPT_STAGE", "benchmark"),
        },
        event_ledger_hash=hashlib.sha256(
            json.dumps(transcript, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        proof_hash=hashlib.sha256(
            json.dumps(proof_submissions, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
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
            "internal_outcome": artifact.internal_outcome,
            "proof_submissions": proof_submissions,
            "automation_wrapper": automation_wrapper,
        }, handle, indent=2, sort_keys=True)
    return artifact


def normalize_runtime_artifact(
    artifact: RunArtifact,
    *,
    observed_usage: Mapping[str, Any],
    event_ledger_hash: str,
    proof_hash: str,
    gateway_relay_lock_hash: str,
) -> RunArtifact:
    """Bind a Docker wrapper result to host-observed usage and proof hashes.

    Baseline self-reported token/cost fields are deliberately ignored.  The
    caller supplies values collected from the host gateway ledger.
    """
    required = {"input_tokens", "output_tokens", "total_tokens", "usd"}
    if required.difference(observed_usage):
        raise ValueError("observed runtime usage is incomplete")
    artifact.usage = {
        **artifact.usage,
        "input_tokens": int(observed_usage["input_tokens"]),
        "output_tokens": int(observed_usage["output_tokens"]),
        "total_tokens": int(observed_usage["total_tokens"]),
        "total_usd": float(observed_usage["usd"]),
    }
    artifact.event_ledger_hash = event_ledger_hash
    artifact.proof_hash = proof_hash
    artifact.run_context["gateway_relay_lock_hash"] = gateway_relay_lock_hash
    artifact.validate_official(strict_runtime=True)
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
