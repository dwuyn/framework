from __future__ import annotations

import json
import subprocess

from src.baselines.wrapper import run_baseline_command
from src.pipeline.budget import BudgetTier
from src.pipeline.framework_adapter import PublicTask


def test_baseline_wrapper_emits_run_artifact_v2(tmp_path) -> None:
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({
        "logical_label": "gemini-3.5-flash",
        "project": "p",
        "location": "us-central1",
        "resource_id": "projects/p/locations/us-central1/endpoints/123",
        "resource_revision": "endpoints/123/deployedModels/456",
        "pricing": {
            "input_per_million": 1,
            "cached_input_per_million": 0.25,
            "output_per_million": 2,
            "thinking_per_million": 3,
        },
        "generation_parameters": {"temperature": 0},
        "usage_semantics": {"input_includes_cached": "true", "total_formula": "input+output+thinking"},
        "pricing_effective_at": "2026-08-02T00:00:00Z",
    }))
    artifact = run_baseline_command(
        framework="PentestGPT",
        command=["python", "-c", "print('baseline')"],
        public_task=PublicTask.from_dict({
            "case_id": "vp-test-0001",
            "track": "blind",
            "objective": "proof",
            "target": {"host": "lab.local", "exposed_ports": [80]},
        }),
        run_dir=str(tmp_path / "run"),
        model_profile_path=str(profile),
        budget_tier=BudgetTier.LOW,
        repetition=1,
        condition="main",
        automation_wrapper=True,
    )
    data = json.loads((tmp_path / "run" / "run_artifact.json").read_text())
    assert data["schema_version"] == "2.0.0"
    assert data["run_identity"]["case_id"] == "vp-test-0001"
    assert data["model_revision"] == "endpoints/123/deployedModels/456"
    assert data["termination_status"] == "completed"
    assert artifact.transcript[0]["event"]["automation_wrapper"] is True


def _profile_path(tmp_path):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({
        "logical_label": "gemini-3.5-flash",
        "project": "p",
        "location": "us-central1",
        "resource_id": "projects/p/locations/us-central1/endpoints/123",
        "resource_revision": "endpoints/123/deployedModels/456",
        "pricing": {"input_per_million": 1, "cached_input_per_million": 0.25,
                    "output_per_million": 2, "thinking_per_million": 3},
        "generation_parameters": {"temperature": 0},
        "usage_semantics": {"input_includes_cached": "true", "total_formula": "input+output+thinking"},
        "pricing_effective_at": "2026-08-02T00:00:00Z",
    }))
    return path


def _task():
    return PublicTask.from_dict({"case_id": "vp-test-0001", "track": "blind", "objective": "proof",
                                 "target": {"host": "lab.local", "exposed_ports": [80]}})


def test_wrapper_normalizes_success_nonzero_and_missing_proof(tmp_path) -> None:
    profile = _profile_path(tmp_path)
    success = run_baseline_command(
        framework="PentestGPT", command=["python", "-c",
        "import json; json.dump({'kind': 'proof'}, open('proof.json', 'w'))"],
        public_task=_task(), run_dir=str(tmp_path / "success"), model_profile_path=str(profile),
        budget_tier=BudgetTier.LOW, repetition=1, condition="main",
    )
    assert success.termination_status == "completed"
    assert success.proof_submissions == [{"kind": "proof"}]

    failed = run_baseline_command(
        framework="PentestGPT", command=["python", "-c", "raise SystemExit(3)"],
        public_task=_task(), run_dir=str(tmp_path / "failed"), model_profile_path=str(profile),
        budget_tier=BudgetTier.LOW, repetition=1, condition="main",
    )
    assert failed.termination_status == "infrastructure_failure"

    missing = run_baseline_command(
        framework="PentestGPT", command=["python", "-c", "print('no proof')"],
        public_task=_task(), run_dir=str(tmp_path / "missing"), model_profile_path=str(profile),
        budget_tier=BudgetTier.LOW, repetition=1, condition="main",
    )
    assert missing.termination_status == "missing_proof"


def test_wrapper_normalizes_timeout_and_budget_exhaustion(tmp_path, monkeypatch) -> None:
    profile = _profile_path(tmp_path)

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="fake", timeout=1)

    monkeypatch.setattr("src.baselines.wrapper.subprocess.run", timeout)
    timed_out = run_baseline_command(
        framework="PentestGPT", command=["fake"], public_task=_task(),
        run_dir=str(tmp_path / "timeout"), model_profile_path=str(profile),
        budget_tier=BudgetTier.LOW, repetition=1, condition="main",
    )
    assert timed_out.termination_status == "timeout"

    monkeypatch.undo()
    monkeypatch.setenv("VERIPLANPT_BUDGET_EXHAUSTED", "true")
    exhausted = run_baseline_command(
        framework="PentestGPT", command=["python", "-c", "pass"], public_task=_task(),
        run_dir=str(tmp_path / "budget"), model_profile_path=str(profile),
        budget_tier=BudgetTier.LOW, repetition=1, condition="main",
    )
    assert exhausted.termination_status == "budget_exhausted"
