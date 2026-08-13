from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.source_snapshot import (
    CANONICAL_CVE_COUNT,
    CANONICAL_INDEX_SHA256,
    CANONICAL_RECORD_COUNT,
)
from src.pipeline.vertex_gateway import GatewayError, VertexGateway


def _profile() -> ModelProfile:
    return ModelProfile.from_dict({
        "logical_label": "gemini-3.5-flash",
        "location": "global",
        "resource_id": "projects/p/locations/global/publishers/google/models/gemini-3.5-flash",
        "resource_revision": "default",
        "resolution_mode": "provider_alias",
        "resolution_evidence_hash": "a" * 64,
        "resolution_resolved_at": "2026-08-05T00:00:00Z",
        "pricing": {"input_per_million": 1.0, "cached_input_per_million": 0.5, "output_per_million": 2.0},
        "pricing_effective_at": "2026-08-05T00:00:00Z",
        "usage_semantics": {
            "input_includes_cached": "true", "total_formula": "input+output",
            "output_includes_reasoning": "true",
        },
    })


def test_bearer_binding_uses_tilde_and_allows_dotted_run_id() -> None:
    profile = _profile()
    gateway = VertexGateway(
        profiles=[profile], allowed_run_ids={"gemini-3.5-flash"},
        token="phase", gemini=object(), gemma=object(),
    )
    bound = f"phase~gemini-3.5-flash~{profile.profile_hash}"
    assert gateway.token_context(bound) == {
        "run_id": "gemini-3.5-flash", "profile_hash": profile.profile_hash,
    }
    for legacy in (
        f"phase.gemini-3.5-flash.{profile.profile_hash}",
        bound + "~extra",
        "phase~gemini-3.5-flash",
    ):
        with pytest.raises(GatewayError):
            gateway.authorize(legacy)


def test_runtime_entrypoint_rejects_fake_provider_in_production(tmp_path, monkeypatch) -> None:
    module_path = Path(__file__).parents[1] / "docker/adapter/runtime_entrypoint.py"
    spec = importlib.util.spec_from_file_location("r10_3_runtime_entrypoint", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    invocation = {
        "schema_version": "2.0.0", "run_id": "smoke-gemini-3.5-flash",
        "framework": "VeriPlanPT", "model_label": "gemini-3.5-flash",
        "case_id": "vp-validation-0001", "track": "blind",
        "condition": "framework_model_smoke",
        "task": {"case_id": "vp-validation-0001", "objective": "probe", "target": {}},
        "provenance": {
            "dataset_lock_hash": "a" * 64, "framework_commit": "b" * 40,
            "framework_image_digest": "sha256:" + "c" * 64,
            "evaluator_commit": "d" * 40, "target_runtime_lock_hash": "e" * 64,
        },
        "model_profile": {"profile_hash": "f" * 64},
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(invocation)))
    for key, value in {
        "VERIPLANPT_STAGE": "canary_smoke", "VERIPLANPT_RUN_ID": invocation["run_id"],
        "VERIPLANPT_MODEL_LABEL": invocation["model_label"],
        "VERIPLANPT_PROFILE_HASH": "f" * 64,
        "VERIPLANPT_FRAMEWORK_NAME": "VeriPlanPT",
        "VERIPLANPT_TARGET_RUNTIME_LOCK_HASH": "e" * 64,
        "VERIPLANPT_OUTPUT_DIR": str(tmp_path),
        "VERIPLANPT_FAKE_PROVIDER": "true",
    }.items():
        monkeypatch.setenv(key, str(value))
    with pytest.raises(module.RuntimeBoundaryError, match="test-only"):
        module.main()


def test_successor_contract_constants_are_pinned() -> None:
    assert CANONICAL_INDEX_SHA256 == "31421ea39ed809a34e3bdbfeda5fa34b26ff5ed194247309c60f015b710811bd"
    assert (CANONICAL_RECORD_COUNT, CANONICAL_CVE_COUNT) == (542975, 354521)


def test_baseline_driver_has_no_interactive_entrypoint() -> None:
    source = (Path(__file__).parents[1] / "docker/adapter/baseline_driver.py").read_text()
    assert "pentestgpt.main" not in source
    assert "lab.local" not in source
