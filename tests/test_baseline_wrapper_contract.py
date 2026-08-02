from __future__ import annotations

import json

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
