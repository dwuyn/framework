from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.runtime_container import ReadinessContainerExecutor


def _profile() -> ModelProfile:
    return ModelProfile.from_dict({
        "logical_label": "gemini-3.5-flash",
        "location": "global",
        "resource_id": "projects/p/locations/global/publishers/google/models/gemini-3.5-flash",
        "resource_revision": "default",
        "resolution_mode": "provider_alias",
        "resolution_evidence_hash": "a" * 64,
        "resolution_resolved_at": "2026-08-05T00:00:00Z",
        "pricing": {"input_per_million": 1.5, "cached_input_per_million": 0.15, "output_per_million": 7.5},
        "pricing_effective_at": "2026-08-05T00:00:00Z",
        "usage_semantics": {
            "input_includes_cached": "true", "total_formula": "input+output",
            "output_includes_reasoning": "true",
        },
    })


def test_readiness_binds_framework_run_dir_to_output_mount(tmp_path) -> None:
    captured: dict[str, str] = {}

    class StopAfterCapture(RuntimeError):
        pass

    class Topology:
        def runtime_environment(self, _handle, *, run_id, model_label, profile_hash):
            return {
                "VERIPLANPT_RUN_ID": run_id,
                "VERIPLANPT_MODEL_LABEL": model_label,
                "VERIPLANPT_PROFILE_HASH": profile_hash,
                "VERIPLANPT_PROVIDER_TOKEN": "token",
                "VERIPLANPT_PROVIDER_TOKEN_EXPIRES_AT": "2026-08-10T13:00:00Z",
                "VERIPLANPT_PROVIDER_URL": "http://gateway-relay:8080/v1/generate",
            }

        def run_baseline(self, _handle, **kwargs):
            captured.update(kwargs["environment"])
            raise StopAfterCapture

    executor = ReadinessContainerExecutor(
        profiles=[_profile()], topology=Topology(),
        public_task={"case_id": "vp-validation-0001"},
        framework_identities={"VeriPlanPT": {"commit": "b" * 40, "repository_url": "https://example.test"}},
        evaluator_commit="c" * 40, training_protocol_hash="d" * 64,
        gateway_relay_lock_hash="e" * 64,
    )
    cell = {
        "run_id": "run-1", "framework": "VeriPlanPT", "model_label": "gemini-3.5-flash",
        "target_runtime_lock_hash": "f" * 64, "dataset_lock_hash": "a" * 64,
        "image_digest": "sha256:" + "1" * 64, "kind": "vertex_canary",
    }
    with pytest.raises(StopAfterCapture):
        executor(cell, tmp_path, {}, "canary", SimpleNamespace(), SimpleNamespace())

    assert captured["VERIPLANPT_RUN_DIR"] == "/run/veriplanpt/output"
