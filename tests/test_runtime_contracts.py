from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from src.pipeline.experiment_runner import validate_runtime_preflight
from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.llm_budget import NormalizedUsage
from src.pipeline.runtime_contract import (
    LOCKED_MODEL_LABELS,
    validate_runtime_profile,
    verify_alias_exception,
)
from src.pipeline.runtime_ledger import InvocationLedger
from src.pipeline.runtime_readiness import build_canary_smoke_plan, validate_canary_smoke_plan
from src.pipeline.vertex_gateway import GatewayError, VertexGateway
from src.pipeline.vertex_runtime import GEMMA_ENDPOINT_URL, InvocationResult


def _profile(label: str) -> ModelProfile:
    gemma = label == "gemma-4-26b-a4b-it"
    return ModelProfile.from_dict({
        "logical_label": label,
        "location": "global",
        "resource_id": f"projects/runtime/locations/global/publishers/google/models/{label}",
        "resource_revision": "001" if gemma else "default",
        "resolution_mode": "immutable" if gemma else "provider_alias",
        "resolution_evidence_hash": "a" * 64,
        "resolution_resolved_at": "2026-08-05T00:00:00Z",
        "endpoint_url": GEMMA_ENDPOINT_URL if gemma else "",
        "pricing": {"input_per_million": 1.0, "cached_input_per_million": 0.5, "output_per_million": 2.0},
        "pricing_effective_at": "2026-08-05T00:00:00Z",
        "generation_parameters": {"temperature": 0.0},
        "usage_semantics": {
            "input_includes_cached": "true", "total_formula": "input+output",
            "output_includes_reasoning": "true",
        },
    })


def test_alias_exception_is_exactly_scoped_and_signed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    signature = tmp_path / "alias-exception.json.minisig"
    signature.write_text("signature", encoding="utf-8")
    monkeypatch.setattr(
        "src.pipeline.runtime_contract._verify_detached_minisign",
        lambda payload, signature_path, public_key: None,
    )
    now = datetime.now(UTC)
    value = {
        "schema_version": "1.0.0",
        "project": "runtime-project",
        "dataset_lock_hash": "b" * 64,
        "model_labels": list(LOCKED_MODEL_LABELS),
        "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "reason": "Gemini @default provider alias is the approved Model Garden surface.",
    }
    verified = verify_alias_exception(
        value, signature_path=signature, public_key="RWR-public-key",
        project="runtime-project", dataset_lock_hash="b" * 64, now=now,
    )
    assert verified["project"] == "runtime-project"
    with pytest.raises(ValueError, match="unexpected"):
        verify_alias_exception(
            {**value, "extra": "nope"}, signature_path=signature, public_key="RWR-public-key",
            project="runtime-project", dataset_lock_hash="b" * 64, now=now,
        )


def test_strict_profiles_and_plan_pin_runtime_identities() -> None:
    profiles = [_profile(label) for label in LOCKED_MODEL_LABELS]
    for profile in profiles:
        validate_runtime_profile(profile, strict=True)
    plan = build_canary_smoke_plan(
        profiles=profiles,
        dataset_lock_hash="b" * 64, baseline_identity_hash="c" * 64,
        model_resolution_lock_hash="d" * 64, evaluator_hash="e" * 64,
        oracle_hash="f" * 64, native_identity_hash="1" * 64,
        target_runtime_lock_hash="2" * 64, source_snapshot_hash="3" * 64,
        image_digests={name: "sha256:" + "2" * 64 for name in ("VeriPlanPT", "PentestGPT", "VulnBot", "HackSynth", "PentestAgent")},
        max_input_tokens=1024, max_output_tokens=256, max_llm_calls=40,
        retry_policy={"max_attempts": 2, "retryable": ["429"]}, strict=True,
    )
    assert plan["cell_count"] == 18
    assert all(cell["model_profile_hash"] for cell in plan["cells"])


def test_r10_4_separates_transport_kind_from_readiness_condition() -> None:
    profiles = [_profile(label) for label in LOCKED_MODEL_LABELS]
    for profile in profiles:
        profile.generation_parameters["max_output_tokens"] = 2048
        if profile.logical_label == "gemma-4-26b-a4b-it":
            profile.generation_parameters["thinking_enabled"] = False
        else:
            profile.generation_parameters["thinking_config"] = {"thinking_level": "MEDIUM"}
    plan = build_canary_smoke_plan(
        profiles=profiles,
        dataset_lock_hash="b" * 64, baseline_identity_hash="c" * 64,
        model_resolution_lock_hash="d" * 64, evaluator_hash="e" * 64,
        oracle_hash="f" * 64, native_identity_hash="1" * 64,
        target_runtime_lock_hash="2" * 64, source_snapshot_hash="3" * 64,
        image_digests={name: "sha256:" + "2" * 64 for name in (
            "VeriPlanPT", "PentestGPT", "VulnBot", "HackSynth", "PentestAgent",
        )},
        max_input_tokens=4096, max_output_tokens=2048, max_llm_calls=1,
        retry_policy={"max_attempts": 2, "retryable": ["429"]}, strict=True,
        runtime_contract="veriplanpt-runtime-v0.4.0-r10.4",
    )
    validate_canary_smoke_plan(plan, profiles=profiles, strict=True)
    assert {cell["execution_kind"] for cell in plan["cells"]} == {
        "vertex_canary", "framework_model_smoke",
    }
    assert {cell["condition"] for cell in plan["cells"]} == {"not_applicable"}
    assert {cell["evaluation_scope"] for cell in plan["cells"]} == {"readiness_transport"}
    assert all(cell["metric_eligible"] is False for cell in plan["cells"])
    assert all(cell["execution_kind"] != cell["condition"] for cell in plan["cells"])


def test_runtime_preflight_blocks_profile_drift_and_overreservation() -> None:
    plan = {"cells": [{"run_id": "r", "model_label": "gemini-3.5-flash", "cell_worst_case_cost_usd": 2.0,
                       "model_profile_hash": "expected"}]}
    with pytest.raises(ValueError, match="profile hash"):
        validate_runtime_preflight(plan, profile_hashes={"gemini-3.5-flash": "actual"})
    with pytest.raises(ValueError, match="reservation"):
        validate_runtime_preflight(plan, reservation_ceiling_usd=1.0)


def test_strict_plan_rejects_profile_drift() -> None:
    profiles = [_profile(label) for label in LOCKED_MODEL_LABELS]
    plan = build_canary_smoke_plan(
        profiles=profiles,
        dataset_lock_hash="b" * 64, baseline_identity_hash="c" * 64,
        model_resolution_lock_hash="d" * 64, evaluator_hash="e" * 64,
        oracle_hash="f" * 64, native_identity_hash="1" * 64,
        target_runtime_lock_hash="2" * 64, source_snapshot_hash="3" * 64,
        image_digests={name: "sha256:" + "2" * 64 for name in ("VeriPlanPT", "PentestGPT", "VulnBot", "HackSynth", "PentestAgent")},
        max_input_tokens=1024, max_output_tokens=256, max_llm_calls=40,
        retry_policy={"max_attempts": 2, "retryable": ["429"]}, strict=True,
    )
    tampered_cells = [dict(plan["cells"][0], model_profile_hash="0" * 64), *plan["cells"][1:]]
    tampered = {**plan, "cells": tampered_cells}
    unsigned = {key: value for key, value in tampered.items() if key != "plan_hash"}
    import hashlib
    import json
    tampered["plan_hash"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(ValueError, match="profile hash mismatch"):
        validate_canary_smoke_plan(tampered, profiles=profiles, strict=True)


def test_gateway_blocks_call_41_before_provider() -> None:
    profile = _profile("gemini-3.5-flash")

    class FakeGemini:
        calls = 0

        def invoke(self, selected: ModelProfile, _contents: object) -> InvocationResult:
            self.calls += 1
            return InvocationResult(
                text="ok", usage=NormalizedUsage(
                    input_tokens=1, output_tokens=1, total_tokens=2, usd=0.01,
                ), response_hash="a" * 64, model_id=selected.logical_label,
                resource_revision=selected.resource_revision,
            )

    gemini = FakeGemini()
    ledger = InvocationLedger(phase="smoke", gateway_relay_lock_hash="b" * 64)
    gateway = VertexGateway(
        profiles=[profile], allowed_run_ids={"medium-cell"}, token="token",
        gemini=gemini, gemma=object(), invocation_ledger=ledger,
        max_llm_calls_by_run={"medium-cell": 40},
    )
    request = {
        "run_id": "medium-cell", "model_label": profile.logical_label,
        "profile_hash": profile.profile_hash, "contents": "probe",
    }
    for _ in range(40):
        gateway.invoke(request, token="token")
    with pytest.raises(GatewayError, match="max_llm_calls exceeded before provider call"):
        gateway.invoke(request, token="token")
    assert gemini.calls == 40


def test_gateway_replays_durable_response_without_a_second_provider_call() -> None:
    profile = _profile("gemini-3.5-flash")

    class FakeGemini:
        calls = 0

        def invoke(self, selected: ModelProfile, _contents: object) -> InvocationResult:
            self.calls += 1
            return InvocationResult(
                text="ok", usage=NormalizedUsage(
                    input_tokens=1, output_tokens=1, total_tokens=2, usd=0.01,
                ), response_hash="c" * 64, model_id=selected.logical_label,
                resource_revision=selected.resource_revision,
            )

    gemini = FakeGemini()
    ledger = InvocationLedger(
        phase="smoke", gateway_relay_lock_hash="b" * 64, epoch="epoch-1",
    )
    gateway = VertexGateway(
        profiles=[profile], allowed_run_ids={"run-1"}, token="token",
        gemini=gemini, gemma=object(), invocation_ledger=ledger, epoch="epoch-1",
    )
    request = {
        "run_id": "run-1", "model_label": profile.logical_label,
        "profile_hash": profile.profile_hash, "contents": "probe",
        "epoch": "epoch-1", "call_index": 0,
    }

    first = gateway.invoke(request, token="token")
    replay = gateway.invoke(request, token="token")
    assert replay == first
    assert gemini.calls == 1
    assert ledger.provider_call_count("run-1") == 1
    assert ledger.snapshot()[0]["replay_count"] == 1

    with pytest.raises(GatewayError, match="different request hash"):
        gateway.invoke({**request, "contents": "tampered"}, token="token")
    assert gemini.calls == 1
