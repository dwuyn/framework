from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.collect_modelgarden_metadata import _gemma_endpoint_snapshot
from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.runtime_ledger import InvocationLedger
from src.pipeline.vertex_gateway import GatewayError, build_host_gateway
from src.pipeline.vertex_runtime import (
    GEMMA_ENDPOINT_URL,
    RetryExhausted,
    invoke_with_retry,
)


def _profile(label: str, *, endpoint: str = "") -> ModelProfile:
    gemma = label == "gemma-4-26b-a4b-it"
    return ModelProfile.from_dict({
        "logical_label": label,
        "location": "global",
        "resource_id": f"projects/p/locations/global/publishers/google/models/{label}",
        "resource_revision": "001" if gemma else "default",
        "resolution_mode": "immutable" if gemma else "provider_alias",
        "resolution_evidence_hash": "a" * 64,
        "resolution_resolved_at": "2026-08-14T00:00:00Z",
        "endpoint_url": endpoint if gemma else "",
        "pricing": {"input_per_million": 1.0, "cached_input_per_million": 0.5, "output_per_million": 2.0},
        "pricing_effective_at": "2026-08-14T00:00:00Z",
        "generation_parameters": {"max_output_tokens": 2048, "thinking_enabled": False},
        "usage_semantics": {
            "input_includes_cached": "true",
            "total_formula": "input+output",
            "output_includes_reasoning": "true",
        },
    })


def test_stale_endpoint_is_rejected_before_any_client_factory() -> None:
    calls: list[str] = []
    profiles = [
        _profile("gemini-3.5-flash"),
        _profile("gemini-3.6-flash"),
        _profile("gemma-4-26b-a4b-it", endpoint=GEMMA_ENDPOINT_URL + "/chat/completions"),
    ]
    with pytest.raises(GatewayError):
        build_host_gateway(
            profiles=profiles,
            allowed_run_ids={"run-1"},
            token="token",
            token_expires_at="2099-01-01T00:00:00Z",
            project="school-projects-501110",
            gemini_client_factory=lambda *_args: calls.append("gemini") or object(),
            gemma_client_factory=lambda *_args: calls.append("gemma") or object(),
        )
    assert calls == []


def test_gemma_endpoint_snapshot_requires_schema_and_exact_base_url(tmp_path: Path) -> None:
    source = tmp_path / "endpoint.source"
    source.write_text("official endpoint evidence", encoding="utf-8")
    snapshot = tmp_path / "endpoint.json"
    snapshot.write_text(json.dumps({
        "schema_version": "1.1.0",
        "model_id": "gemma-4-26b-a4b-it-maas",
        "endpoint_url": GEMMA_ENDPOINT_URL,
        "source_url": "https://docs.cloud.google.com/example",
        "retrieved_at": "2026-08-14T00:00:00Z",
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }), encoding="utf-8")
    assert _gemma_endpoint_snapshot(snapshot, source)["endpoint_url"] == GEMMA_ENDPOINT_URL

    stale = json.loads(snapshot.read_text(encoding="utf-8"))
    stale["endpoint_url"] = GEMMA_ENDPOINT_URL + "?stale=true"
    snapshot.write_text(json.dumps(stale), encoding="utf-8")
    with pytest.raises(RuntimeError):
        _gemma_endpoint_snapshot(snapshot, source)


@pytest.mark.parametrize("status", [403, 404])
def test_non_retryable_upstream_status_stops_immediately(status: int) -> None:
    calls = 0

    def operation() -> None:
        nonlocal calls
        calls += 1
        error = RuntimeError(str(status))
        error.status_code = status  # type: ignore[attr-defined]
        raise error

    with pytest.raises(RuntimeError):
        invoke_with_retry(operation, max_attempts=2)
    assert calls == 1


def test_503_retries_once_and_failure_evidence_is_redacted(tmp_path: Path) -> None:
    calls = 0

    def operation() -> None:
        nonlocal calls
        calls += 1
        error = RuntimeError("503")
        error.status_code = 503  # type: ignore[attr-defined]
        raise error

    with pytest.raises(RetryExhausted):
        invoke_with_retry(operation, max_attempts=2)
    assert calls == 2

    path = tmp_path / "invocation-ledger.json"
    ledger = InvocationLedger(
        phase="canary", gateway_relay_lock_hash="b" * 64, path=path, epoch="epoch-1",
    )
    ledger.record_failure(
        failure_id="failure-test-1", run_id="run-1", model_label="gemma-4-26b-a4b-it",
        model_profile_hash="a" * 64, request={"prompt": "do not persist me"},
        upstream_status=503, exception_class="APIStatusError", google_request_id="req-1",
        error_body_hash="c" * 64, retryable=True, epoch="epoch-1", call_index=0,
    )
    text = path.read_text(encoding="utf-8")
    assert "do not persist me" not in text
    assert "APIStatusError" in text
    assert "failure-test-1" in text
    assert '"model_response_received": false' in text
