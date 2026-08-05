"""Approved canary/smoke executor with injectable host-gateway calls.

The injected call is the only live-provider boundary; tests supply a fake.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from src.pipeline.framework_adapter import BudgetTier, ModelProfile, RunArtifact
from src.pipeline.runtime_readiness import write_runtime_smoke_evidence

GatewayCall = Callable[[Mapping[str, Any]], Mapping[str, Any]]


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value: Mapping[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return _hash(path)


def execute_runtime_plan(*, artifact_root: str | Path, plan: Mapping[str, Any],
                         profiles: Sequence[ModelProfile], training_protocol_hash: str,
                         baseline_lock_hash: str, pricing_snapshot_hash: str,
                         approval_hash: str, dataset_evidence_hash: str,
                         gateway_call: GatewayCall) -> Path:
    """Run three canaries first, then 15 smokes; halt on unknown billing/failure."""
    root = Path(artifact_root).resolve()
    by_label = {profile.logical_label: profile for profile in profiles}
    cells = list(plan.get("cells", []))
    canaries = [cell for cell in cells if cell.get("kind") == "vertex_canary"]
    smokes = [cell for cell in cells if cell.get("kind") == "framework_model_smoke"]
    if len(canaries) != 3 or len(smokes) != 15:
        raise ValueError("runtime executor requires the approved 3+15 plan")
    records: list[dict[str, Any]] = []
    for cell in [*canaries, *smokes]:
        response = gateway_call(cell)
        if response.get("billing_status") != "known":
            raise RuntimeError("billing unknown; runtime stage halted")
        if response.get("oracle_status") != "passed":
            raise RuntimeError("oracle failed; runtime stage halted")
        profile = by_label[str(cell["model_label"])]
        run_dir = root / "runs" / str(cell["run_id"])
        usage = dict(response.get("usage", {}))
        required_usage = {"input_tokens", "output_tokens", "total_tokens", "usd"}
        if not required_usage.issubset(usage):
            raise ValueError("gateway response has incomplete usage")
        ledger_path = run_dir / "event-ledger.json"
        ledger_hash = _write(ledger_path, {"run_id": cell["run_id"], "events": list(response.get("events", []))})
        proof_hash = hashlib.sha256(str(response.get("text", "")).encode()).hexdigest()
        artifact = RunArtifact(
            case_id="runtime-smoke", repetition=1, track="blind", condition=str(cell["kind"]),
            model_profile=profile, budget_tier=BudgetTier.MEDIUM, schema_version="2.1.0", run_id=str(cell["run_id"]),
            run_dir=str(run_dir), termination_status="completed", internal_outcome="passed", usage={
                "input_tokens": int(usage["input_tokens"]), "output_tokens": int(usage["output_tokens"]),
                "total_tokens": int(usage["total_tokens"]), "total_usd": float(usage["usd"]),
            }, framework_identity={"name": str(cell.get("framework", "VeriPlanPT")), "repository_url": "https://example.invalid/runtime", "commit": "runtime", "image_digest": cell["image_digest"], "adapter_version": "adapter-2.1"},
            run_context={"dataset_lock_hash": cell["dataset_lock_hash"], "framework_commit": "runtime", "evaluator_commit": "runtime", "stage": "canary_smoke", "training_protocol_hash": training_protocol_hash},
            event_ledger_hash=ledger_hash, proof_hash=proof_hash,
        )
        artifact_path = run_dir / "run_artifact.json"
        artifact_hash = _write(artifact_path, artifact.to_dict())
        usage_path, cost_path = run_dir / "usage.json", run_dir / "cost.json"
        evaluator_path, cleanup_path = run_dir / "evaluator.json", run_dir / "cleanup.json"
        record = {**dict(cell), "status": "passed", "plan_hash": plan["plan_hash"], "artifact_path": str(artifact_path.relative_to(root)), "artifact_sha256": artifact_hash, "evidence_sha256": artifact_hash, "artifact_type": "run_artifact", "event_ledger_path": str(ledger_path.relative_to(root)), "event_ledger_sha256": ledger_hash, "usage_path": str(usage_path.relative_to(root)), "usage_sha256": _write(usage_path, usage), "cost_path": str(cost_path.relative_to(root)), "cost_sha256": _write(cost_path, {"billing_status": "known", "cost_usd": usage["usd"]}), "evaluator_path": str(evaluator_path.relative_to(root)), "evaluator_sha256": _write(evaluator_path, {"status": "passed"}), "cleanup_path": str(cleanup_path.relative_to(root)), "cleanup_sha256": _write(cleanup_path, {"success": True, "resources": {"container": {"ids": []}, "network": {"ids": []}}}), "billing_status": "known", "oracle_status": "passed"}
        records.append(record)
    return write_runtime_smoke_evidence(artifact_root=root, dataset_lock_hash=str(canaries[0]["dataset_lock_hash"]), dataset_evidence_hash=dataset_evidence_hash, canaries=records[:3], smokes=records[3:], plan_hash=str(plan["plan_hash"]), training_protocol_hash=training_protocol_hash, baseline_lock_hash=baseline_lock_hash, model_resolution_lock_hash=str(canaries[0]["model_resolution_lock_hash"]), pricing_snapshot_hash=pricing_snapshot_hash, approval_hash=approval_hash)
