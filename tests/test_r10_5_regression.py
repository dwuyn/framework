from __future__ import annotations

import json
import threading
import time
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

import pytest

from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.llm_budget import NormalizedUsage
from src.pipeline.runtime_ledger import InvocationLedger
from src.pipeline.runtime_readiness import (
    R10_5_RUNTIME_CONTRACT,
    build_canary_smoke_plan,
    validate_canary_smoke_plan,
)
from src.pipeline.vertex_gateway import GatewayError, VertexGateway, gateway_handler
from src.pipeline.vertex_runtime import GEMMA_ENDPOINT_URL, InvocationResult


def _profiles() -> list[ModelProfile]:
    return [
        ModelProfile.from_dict({
            "logical_label": label,
            "location": "global",
            "resource_id": f"projects/runtime/locations/global/publishers/google/models/{label}",
            "resource_revision": "001" if label.startswith("gemma") else "default",
            "resolution_mode": "immutable" if label.startswith("gemma") else "provider_alias",
            "resolution_evidence_hash": "a" * 64,
            "resolution_resolved_at": "2026-08-05T00:00:00Z",
            "endpoint_url": GEMMA_ENDPOINT_URL if label.startswith("gemma") else "",
            "pricing": {"input_per_million": 1.0, "cached_input_per_million": 0.5, "output_per_million": 2.0},
            "pricing_effective_at": "2026-08-05T00:00:00Z",
            "generation_parameters": {
                "temperature": 0.0, "max_output_tokens": 2048,
                **({"thinking_enabled": False} if label.startswith("gemma") else {"thinking_config": {"thinking_level": "MEDIUM"}}),
            },
            "usage_semantics": {"input_includes_cached": "true", "total_formula": "input+output", "output_includes_reasoning": "true"},
        })
        for label in ("gemini-3.5-flash", "gemini-3.6-flash", "gemma-4-26b-a4b-it")
    ]


def _plan(*, epoch: str = "2026-08-14T00:00:00Z") -> dict[str, object]:
    return build_canary_smoke_plan(
        profiles=_profiles(), dataset_lock_hash="b" * 64, baseline_identity_hash="c" * 64,
        model_resolution_lock_hash="d" * 64, evaluator_hash="e" * 64, oracle_hash="f" * 64,
        native_identity_hash="1" * 64, target_runtime_lock_hash="2" * 64,
        source_snapshot_hash="3" * 64,
        image_digests={name: "sha256:" + "4" * 64 for name in (
            "VeriPlanPT", "PentestGPT", "VulnBot", "HackSynth", "PentestAgent",
        )}, gateway_relay_lock_hash="5" * 64, max_input_tokens=4096,
        max_output_tokens=2048, max_llm_calls=40,
        retry_policy={"max_attempts": 2, "retryable": ["429"]}, epoch=epoch,
        strict=True, runtime_contract=R10_5_RUNTIME_CONTRACT,
    )


def test_r10_5_readiness_requires_epoch_and_one_response_per_cell() -> None:
    with pytest.raises(ValueError, match="UTC epoch"):
        _plan(epoch="")
    plan = _plan()
    assert {int(cell["max_llm_calls"]) for cell in plan["cells"]} == {1}
    validate_canary_smoke_plan(plan, profiles=_profiles(), strict=True)
    tampered = {**plan, "cells": [dict(plan["cells"][0], max_llm_calls=2), *plan["cells"][1:]]}
    import hashlib
    import json
    unsigned = {key: value for key, value in tampered.items() if key != "plan_hash"}
    tampered["plan_hash"] = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with pytest.raises(ValueError, match="call cap"):
        validate_canary_smoke_plan(tampered, profiles=_profiles(), strict=True)


def test_r30_gateway_rejects_missing_signed_caps_before_provider() -> None:
    profile = _profiles()[0]
    with pytest.raises(GatewayError, match="token caps"):
        VertexGateway(
            profiles=[profile], allowed_run_ids={"run-1"}, token="token", gemini=object(), gemma=object(),
            invocation_ledger=InvocationLedger(phase="canary", gateway_relay_lock_hash="a" * 64, epoch="epoch"),
            max_llm_calls_by_run={"run-1": 1}, epoch="epoch",
            max_output_tokens_by_run={"run-1": 2048}, require_signed_plan=True,
        )


def test_r30_gateway_serializes_exact_replay_and_blocks_conflict() -> None:
    profile = _profiles()[0]

    class FakeGemini:
        def __init__(self) -> None:
            self.calls = 0
            self.lock = threading.Lock()

        def invoke(self, selected: ModelProfile, _contents: object) -> InvocationResult:
            with self.lock:
                self.calls += 1
            time.sleep(0.02)
            return InvocationResult(
                text="ok", usage=NormalizedUsage(input_tokens=1, output_tokens=1, total_tokens=2, usd=0.01),
                response_hash="a" * 64, model_id=selected.logical_label,
                resource_revision=selected.resource_revision,
            )

    provider = FakeGemini()
    ledger = InvocationLedger(phase="canary", gateway_relay_lock_hash="b" * 64, epoch="epoch")
    gateway = VertexGateway(
        profiles=[profile], allowed_run_ids={"run-1"}, token="token", gemini=provider, gemma=object(),
        invocation_ledger=ledger, max_llm_calls_by_run={"run-1": 1}, epoch="epoch",
        max_input_tokens_by_run={"run-1": 4096}, max_output_tokens_by_run={"run-1": 2048},
        require_signed_plan=True,
    )
    request = {
        "run_id": "run-1", "model_label": profile.logical_label, "profile_hash": profile.profile_hash,
        "contents": "probe", "epoch": "epoch", "call_index": 0,
    }
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: gateway.invoke(request, token="token"), range(2)))
    assert results[0] == results[1]
    assert provider.calls == 1
    assert ledger.snapshot()[0]["replay_count"] == 1
    with pytest.raises(GatewayError, match="different request hash"):
        gateway.invoke({**request, "contents": "conflict"}, token="token")
    assert provider.calls == 1


def test_r30_gateway_rejects_missing_call_index_before_provider() -> None:
    profile = _profiles()[0]
    provider = type("Provider", (), {"invoke": lambda *_args: pytest.fail("provider called")})()
    gateway = VertexGateway(
        profiles=[profile], allowed_run_ids={"run-1"}, token="token", gemini=provider, gemma=object(),
        invocation_ledger=InvocationLedger(phase="canary", gateway_relay_lock_hash="b" * 64, epoch="epoch"),
        max_llm_calls_by_run={"run-1": 1}, epoch="epoch",
        max_input_tokens_by_run={"run-1": 4096}, max_output_tokens_by_run={"run-1": 2048},
        require_signed_plan=True,
    )
    with pytest.raises(GatewayError, match="call_index"):
        gateway.invoke({
            "run_id": "run-1", "model_label": profile.logical_label,
            "profile_hash": profile.profile_hash, "contents": "probe", "epoch": "epoch",
        }, token="token")


def test_r10_6_openai_chat_boundary_binds_signed_identity() -> None:
    profile = next(item for item in _profiles() if item.logical_label == "gemini-3.5-flash")

    class FakeGemini:
        def __init__(self) -> None:
            self.calls = 0

        def invoke(self, selected: ModelProfile, _contents: object) -> InvocationResult:
            self.calls += 1
            return InvocationResult(
                text="ok", usage=NormalizedUsage(input_tokens=1, output_tokens=1, total_tokens=2, usd=0.01),
                response_hash="d" * 64, model_id=selected.logical_label,
                resource_revision=selected.resource_revision,
            )

    provider = FakeGemini()
    ledger = InvocationLedger(phase="smoke", gateway_relay_lock_hash="a" * 64, epoch="epoch")
    gateway = VertexGateway(
        profiles=[profile], allowed_run_ids={"run-1"}, token="phase-token",
        gemini=provider, gemma=object(), invocation_ledger=ledger,
        max_llm_calls_by_run={"run-1": 1}, epoch="epoch",
        max_input_tokens_by_run={"run-1": 4096}, max_output_tokens_by_run={"run-1": 2048},
        require_signed_plan=True,
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), gateway_handler(gateway))
    thread = threading.Thread(target=server.handle_request)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    connection.request(
        "POST", "/v1/chat/completions",
        body=json.dumps({
            "model": profile.logical_label,
            "messages": [{"role": "user", "content": "probe"}],
            "max_tokens": 2048,
        }),
        headers={
            "Authorization": f"Bearer phase-token~run-1~{profile.profile_hash}",
            "Content-Type": "application/json",
        },
    )
    response = connection.getresponse()
    body = json.loads(response.read())
    thread.join(timeout=5)
    server.server_close()

    assert response.status == 200
    assert body["choices"][0]["message"]["content"] == "ok"
    assert provider.calls == 1
    assert ledger.snapshot()[0]["call_index"] == 0
