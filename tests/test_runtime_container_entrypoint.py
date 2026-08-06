from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "docker/adapter/runtime_entrypoint.py"


def _module():
    spec = importlib.util.spec_from_file_location("runtime_entrypoint", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _invocation() -> dict[str, object]:
    return {
        "run_id": "smoke-veriplanpt-model",
        "framework": "VeriPlanPT",
        "model_label": "gemini-3.5-flash",
        "case_id": "vp-validation-0001",
        "track": "blind",
        "condition": "framework_model_smoke",
        "task": {"case_id": "vp-validation-0001", "objective": "probe", "target": {}},
        "provenance": {
            "dataset_lock_hash": "a" * 64,
            "protocol_hash": "b" * 64,
            "framework_commit": "c" * 40,
            "framework_image_digest": "sha256:" + "d" * 64,
            "framework_repository_url": "https://example.test/veriplanpt",
            "evaluator_commit": "e" * 40,
        },
        "labels": {},
        "model_profile": {"logical_label": "gemini-3.5-flash", "profile_hash": "f" * 64},
        "budget_tier": "medium",
        "repetition": 1,
        "parameters": {},
    }


def test_readiness_entrypoint_binds_run_and_writes_artifact(tmp_path, monkeypatch) -> None:
    module = _module()
    monkeypatch.setitem(sys.modules, "provider_shim", SimpleNamespace(request=lambda _payload: {
        "usage": {"input_tokens": 2, "output_tokens": 1, "total_tokens": 3, "usd": 0.01},
        "response_hash": "1" * 64,
    }))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(_invocation())))
    for key, value in {
        "VERIPLANPT_STAGE": "canary_smoke",
        "VERIPLANPT_RUN_ID": "smoke-veriplanpt-model",
        "VERIPLANPT_MODEL_LABEL": "gemini-3.5-flash",
        "VERIPLANPT_PROFILE_HASH": "f" * 64,
        "VERIPLANPT_FRAMEWORK_NAME": "VeriPlanPT",
        "VERIPLANPT_GATEWAY_RELAY_LOCK_HASH": "2" * 64,
        "VERIPLANPT_OUTPUT_DIR": str(tmp_path),
    }.items():
        monkeypatch.setenv(key, value)

    assert module.main() == 0
    artifact = json.loads((tmp_path / "run_artifact.json").read_text())
    assert artifact["run_id"] == "smoke-veriplanpt-model"
    assert artifact["usage"]["total_usd"] == 0.01
    assert artifact["run_context"]["stage"] == "canary_smoke"


def test_paid_stage_fails_closed_before_reading_invocation(monkeypatch) -> None:
    module = _module()
    monkeypatch.setenv("VERIPLANPT_STAGE", "benchmark")
    with pytest.raises(module.RuntimeBoundaryError, match="framework-specific"):
        module.main()
