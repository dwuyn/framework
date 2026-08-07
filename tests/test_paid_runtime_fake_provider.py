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
    spec = importlib.util.spec_from_file_location("runtime_entrypoint_paid", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _invocation(framework: str) -> dict[str, object]:
    return {
        "schema_version": "2.0.0",
        "run_id": f"paid-{framework.lower()}-fake",
        "framework": framework,
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
            "target_runtime_lock_hash": "9" * 64,
        },
        "labels": {},
        "model_profile": {"logical_label": "gemini-3.5-flash", "profile_hash": "f" * 64},
        "budget_tier": "medium",
        "repetition": 1,
        "parameters": {},
    }


@pytest.mark.parametrize("framework", ["VeriPlanPT", "PentestAgent", "PentestGPT", "VulnBot", "HackSynth"])
def test_paid_adapter_uses_same_fake_provider_path(tmp_path, monkeypatch, framework: str) -> None:
    module = _module()
    calls: list[dict[str, object]] = []

    def request(payload: dict[str, object]) -> dict[str, object]:
        calls.append(payload)
        return {
            "usage": {"input_tokens": 2, "output_tokens": 1, "total_tokens": 3, "usd": 0.01},
            "response_hash": "1" * 64,
        }

    monkeypatch.setitem(sys.modules, "provider_shim", SimpleNamespace(request=request))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(_invocation(framework))))
    for key, value in {
        "VERIPLANPT_STAGE": "benchmark",
        "VERIPLANPT_ADAPTER_PRODUCTION": "true",
        "VERIPLANPT_FAKE_PROVIDER": "true",
        "VERIPLANPT_RUN_ID": f"paid-{framework.lower()}-fake",
        "VERIPLANPT_MODEL_LABEL": "gemini-3.5-flash",
        "VERIPLANPT_PROFILE_HASH": "f" * 64,
        "VERIPLANPT_FRAMEWORK_NAME": framework,
        "VERIPLANPT_GATEWAY_RELAY_LOCK_HASH": "2" * 64,
        "VERIPLANPT_TARGET_RUNTIME_LOCK_HASH": "9" * 64,
        "VERIPLANPT_OUTPUT_DIR": str(tmp_path / framework),
    }.items():
        monkeypatch.setenv(key, value)
    output = tmp_path / framework
    output.mkdir()

    assert module.main() == 0
    artifact = json.loads((output / "run_artifact.json").read_text(encoding="utf-8"))
    assert artifact["framework_identity"]["adapter_version"] == "adapter-3.0"
    assert [item["event"]["phase"] for item in artifact["transcript"]] == ["recon", "planning", "execution"]
    assert len(calls) == 3
    assert artifact["run_context"]["target_runtime_lock_hash"] == "9" * 64
