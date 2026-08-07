from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from src.pipeline.framework_adapter import BudgetTier, ModelProfile, RunArtifact
from src.pipeline.readiness_evidence import validate_smoke_evidence
from src.pipeline.runtime_executor import RuntimeCellResult, execute_runtime_plan
from src.pipeline.runtime_readiness import build_canary_smoke_plan


def _profile(label: str) -> ModelProfile:
    gemma = label == "gemma-4-26b-a4b-it"
    return ModelProfile.from_dict({"logical_label": label, "location": "global", "resource_id": f"projects/p/locations/global/publishers/google/models/{label}", "resource_revision": "001" if gemma else "default", "resolution_mode": "immutable" if gemma else "provider_alias", "resolution_evidence_hash": "a" * 64, "resolution_resolved_at": "2026-08-05T00:00:00Z", "endpoint_url": "https://global-aiplatform.googleapis.com/v1" if gemma else "", "pricing": {"input_per_million": 1.0, "cached_input_per_million": .1, "output_per_million": 2.0}, "pricing_effective_at": "2026-08-05T00:00:00Z", "usage_semantics": {"input_includes_cached": "true", "total_formula": "input+output", "output_includes_reasoning": "true"}})


def test_fake_executor_produces_all_runtime_evidence(tmp_path: Path) -> None:
    profiles = [_profile(label) for label in sorted(ModelProfile.ALLOWED_MODELS)]
    by_label = {profile.logical_label: profile for profile in profiles}
    images = {name: "sha256:" + "2" * 64 for name in ("VeriPlanPT", "PentestGPT", "VulnBot", "HackSynth", "PentestAgent")}
    plan = build_canary_smoke_plan(profiles=profiles, dataset_lock_hash="a" * 64, baseline_identity_hash="b" * 64, native_identity_hash="c" * 64, model_resolution_lock_hash="d" * 64, evaluator_hash="e" * 64, oracle_hash="f" * 64, image_digests=images, target_runtime_lock_hash="9" * 64, max_input_tokens=10, max_output_tokens=5, retry_policy={"max_attempts": 2}, strict=True)
    def cleanup(run_id: str): return {"success": True, "resources": {"container": {"ids": []}, "network": {"ids": []}}, "run_id": run_id}
    def execute(cell, run_dir):
        profile = by_label[cell["model_label"]]
        ledger, proof = {"events": []}, {"text": "proof"}
        def digest(value: object) -> str:
            return hashlib.sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            ).hexdigest()
        artifact = RunArtifact(case_id="runtime", repetition=1, track="blind", condition=cell["kind"], model_profile=profile, budget_tier=BudgetTier.MEDIUM, schema_version="2.1.0", run_id=cell["run_id"], run_dir=str(run_dir), usage={"input_tokens": 1, "output_tokens": 1, "total_tokens": 2, "total_usd": .01}, framework_identity={"name": cell.get("framework", "VeriPlanPT"), "repository_url": "https://example.test/repo", "commit": "a" * 40, "image_digest": cell["image_digest"], "adapter_version": "adapter-3.0"}, run_context={"dataset_lock_hash": cell["dataset_lock_hash"], "framework_commit": "b" * 40, "evaluator_commit": "c" * 40, "stage": "canary_smoke", "training_protocol_hash": "1" * 64, "target_runtime_lock_hash": cell["target_runtime_lock_hash"]}, event_ledger_hash="2" * 64, proof_hash="3" * 64)
        artifact.event_ledger_hash, artifact.proof_hash = digest(ledger), digest(proof)
        clean = cleanup(cell["run_id"])
        return RuntimeCellResult(artifact.to_dict(), ledger, proof, {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2, "usd": .01}, {"billing_status": "known", "cost_usd": .01}, {"status": "passed"}, clean, "known", "passed")
    evidence = execute_runtime_plan(artifact_root=tmp_path, plan=plan, profiles=profiles, training_protocol_hash="1" * 64, baseline_lock_hash="b" * 64, pricing_snapshot_hash="c" * 64, approval_hash="d" * 64, dataset_evidence_hash="e" * 64, framework_commit="b" * 40, evaluator_commit="c" * 40, cell_executor=execute, cleanup=cleanup)
    validate_smoke_evidence(json.loads(evidence.read_text()), base_case_ids=[], model_labels=[p.logical_label for p in profiles], mode="runtime-smoke", artifact_root=tmp_path)
    proof = next((tmp_path / "runs").rglob("proof.json"))
    proof.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="does not match artifact contents"):
        validate_smoke_evidence(json.loads(evidence.read_text()), base_case_ids=[], model_labels=[p.logical_label for p in profiles], mode="runtime-smoke", artifact_root=tmp_path)
