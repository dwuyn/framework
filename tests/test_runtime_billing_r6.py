from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from enum import Enum

import pytest
from pydantic import BaseModel

from src.pipeline.experiment_runner import ExperimentRunner
from src.pipeline.runtime_ledger import (
    BillableInvocationError,
    BillingUnknownError,
    InvocationLedger,
)
from src.pipeline.vertex_gateway import (
    ProviderGatewayError,
    VertexGateway,
    serve_gateway,
)
from src.pipeline.vertex_runtime import (
    GeminiExecutor,
    PostResponseFailure,
    VertexContractError,
    semantic_response_hash,
)
from tests.test_vertex_runtime import _profile


class _Color(Enum):
    BLUE = "blue"


class _JsonResponse:
    def __init__(self, value: dict) -> None:
        self.value = value

    def to_json_dict(self) -> dict:
        return self.value

    def model_dump(self, **_kwargs: object) -> dict:
        raise AssertionError("to_json_dict must have precedence")


class _ResponseTransport:
    def __init__(self, response: object) -> None:
        self.response = response

    def generate(self, **_kwargs):
        return self.response


class _PydanticResponse(BaseModel):
    text: str | None = None
    usage: dict[str, int]
    sdk_http_response: dict[str, str] | None = None
    parsed: dict[str, str] | None = None


def _request(profile, run_id: str = "run-1") -> dict:
    return {
        "run_id": run_id,
        "model_label": profile.logical_label,
        "profile_hash": profile.profile_hash,
        "contents": "ping",
    }


def _gateway(profile, transport, tmp_path, *, ledger: InvocationLedger | None = None):
    return VertexGateway(
        profiles=[profile], allowed_run_ids={"run-1"}, token="test-token",
        gemini=GeminiExecutor(transport), gemma=GeminiExecutor(transport),
        invocation_ledger=ledger,
    )


def test_semantic_response_hash_normalizes_nested_bytes_enum_datetime_and_excludes_transport() -> None:
    payload = {
        "text": "pong",
        "usage": {"input_tokens": 4, "output_tokens": 2},
        "nested": {
            "bytes": b"\x00\xff",
            "enum": _Color.BLUE,
            "when": datetime(2026, 8, 9, 12, 0, tzinfo=timezone.utc),
        },
        "sdk_http_response": {"status": "200", "request_id": "one"},
        "parsed": {"transport": "one"},
    }
    equivalent = {
        "parsed": {"transport": "two"},
        "sdk_http_response": {"status": "500", "request_id": "two"},
        "nested": {"when": "2026-08-09T12:00:00+00:00", "enum": "blue", "bytes": "AP8="},
        "usage": {"output_tokens": 2, "input_tokens": 4},
        "text": "pong",
    }
    assert semantic_response_hash(payload) == semantic_response_hash(equivalent)


def test_generate_content_response_with_nested_bytes_has_stable_hash() -> None:
    types = pytest.importorskip("google.genai.types")
    response = types.GenerateContentResponse(
        candidates=[
            types.Candidate(
                content=types.Content(
                    parts=[
                        types.Part(text="pong"),
                        types.Part(inline_data=types.Blob(mime_type="application/octet-stream", data=b"\x00\xff")),
                    ]
                )
            )
        ],
        usageMetadata=types.GenerateContentResponseUsageMetadata(
            promptTokenCount=4, candidatesTokenCount=2, totalTokenCount=6
        ),
    )
    profile = _profile("gemini-3.5-flash")
    first = GeminiExecutor(_ResponseTransport(response)).invoke(profile, "ping")
    second = GeminiExecutor(_ResponseTransport(response)).invoke(profile, "ping")
    assert first.text == "pong"
    assert first.usage.total_tokens == 6
    assert first.response_hash == second.response_hash


def test_pydantic_openai_response_uses_json_dump_and_excludes_transport_fields() -> None:
    response = _PydanticResponse(
        text="pong", usage={"prompt_tokens": 5, "completion_tokens": 3},
        sdk_http_response={"request_id": "one"}, parsed={"state": "one"},
    )
    profile = _profile("gemma-4-26b-a4b-it")
    from src.pipeline.vertex_runtime import GemmaMaaSExecutor

    first = GemmaMaaSExecutor(_ResponseTransport(response)).invoke(
        profile, [{"role": "user", "content": "ping"}]
    )
    response.sdk_http_response = {"request_id": "two"}
    response.parsed = {"state": "two"}
    second = GemmaMaaSExecutor(_ResponseTransport(response)).invoke(
        profile, [{"role": "user", "content": "ping"}]
    )
    assert first.text == second.text == "pong"
    assert first.response_hash == second.response_hash


def test_unsupported_provider_response_fails_closed() -> None:
    with pytest.raises(VertexContractError, match="unsupported"):
        semantic_response_hash({"bad": object()})


def test_post_response_failure_with_usage_is_known_and_not_retryable(tmp_path) -> None:
    profile = _profile("gemini-3.5-flash")
    ledger = InvocationLedger(
        phase="canary", gateway_relay_lock_hash="a" * 64,
        path=tmp_path / "ledger.json",
    )
    gateway = _gateway(profile, _ResponseTransport({"usage": {"input_tokens": 1, "output_tokens": 1}}), tmp_path, ledger=ledger)
    with pytest.raises(ProviderGatewayError, match="post-response"):
        gateway.invoke(_request(profile), token="test-token")
    state = ledger.lookup("run-1")
    assert state["billing_status"] == "known"
    assert state["records"][0]["outcome"] == "post_response_failure"
    assert json.loads((tmp_path / "ledger.json").read_text())["schema_version"] == "1.1.0"


def test_post_response_failure_without_usage_is_billing_unknown(tmp_path) -> None:
    profile = _profile("gemini-3.5-flash")
    ledger = InvocationLedger(
        phase="canary", gateway_relay_lock_hash="a" * 64,
        path=tmp_path / "ledger.json",
    )
    response = {"text": "pong", "bad": object()}
    gateway = _gateway(profile, _ResponseTransport(response), tmp_path, ledger=ledger)
    with pytest.raises(BillingUnknownError):
        gateway.invoke(_request(profile), token="test-token")
    assert ledger.lookup("run-1")["billing_status"] == "unknown"
    record = ledger.lookup("run-1")["records"][0]
    assert record["usage"] is None and record["cost_usd"] is None


def test_pre_response_failure_creates_no_invocation(tmp_path) -> None:
    class Transport:
        def generate(self, **_kwargs):
            raise RuntimeError("connection failed")

    profile = _profile("gemini-3.5-flash")
    ledger = InvocationLedger(
        phase="canary", gateway_relay_lock_hash="a" * 64,
        path=tmp_path / "ledger.json",
    )
    gateway = _gateway(profile, Transport(), tmp_path, ledger=ledger)
    with pytest.raises(RuntimeError, match="connection"):
        gateway.invoke(_request(profile), token="test-token")
    assert ledger.lookup("run-1")["billing_status"] == "none"
    assert not (tmp_path / "ledger.json").exists()


def test_atomic_ledger_persistence_failure_halts_unknown(tmp_path, monkeypatch) -> None:
    profile = _profile("gemini-3.5-flash")
    ledger = InvocationLedger(
        phase="canary", gateway_relay_lock_hash="a" * 64,
        path=tmp_path / "ledger.json",
    )

    def fail(_destination):
        raise OSError("disk failure")

    monkeypatch.setattr(ledger, "_write_locked", fail)
    gateway = _gateway(
        profile,
        _ResponseTransport({"text": "pong", "usage": {"input_tokens": 1, "output_tokens": 1}}),
        tmp_path,
        ledger=ledger,
    )
    with pytest.raises(BillingUnknownError):
        gateway.invoke(_request(profile), token="test-token")
    assert ledger.lookup("run-1")["billing_status"] == "none"


def test_ledger_reads_r5_schema_without_rewriting_it(tmp_path) -> None:
    path = tmp_path / "r5-ledger.json"
    path.write_text(json.dumps({
        "schema_version": "1.0.0",
        "phase": "canary",
        "gateway_relay_lock_hash": "a" * 64,
        "invocations": [{
            "run_id": "run-1", "model_label": "gemini-3.5-flash",
            "request_sha256": "b" * 64, "response_sha256": "c" * 64,
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            "cost_usd": 0.01, "billing_status": "known", "observed_at": "2026-08-09T00:00:00Z",
            "gateway_relay_lock_hash": "a" * 64,
        }],
    }) + "\n")
    original = path.read_bytes()
    ledger = InvocationLedger.from_file(path)
    assert ledger.lookup("run-1")["billing_status"] == "known"
    assert ledger.snapshot()[0]["outcome"] == "completed"
    assert path.read_bytes() == original


def test_known_billed_container_failure_is_failed_and_not_retried(tmp_path, monkeypatch) -> None:
    runner = ExperimentRunner(artifact_root=tmp_path)
    runner.register_plan({"cells": [{"run_id": "run-1", "cell_worst_case_cost_usd": 0.1}]})
    monkeypatch.setattr(
        runner, "cleanup_labeled_docker_resources",
        lambda run_id, *, stage="": {"run_id": run_id, "stage": stage, "success": True},
    )
    claimed = runner._claim("worker", 1.0)
    assert claimed is not None
    runner._execute_claim(
        claimed=claimed,
        executor=lambda _cell, _path, _labels: (_ for _ in ()).throw(
            BillableInvocationError("container failed after response", cost_usd=0.01)
        ),
        labels={}, stage="canary", connection=runner.db,
    )
    assert runner.status()["states"] == {"failed": 1}
    assert runner.status()["accumulated_cost_usd"] == pytest.approx(0.01)
    assert runner._claim("worker-2", 1.0) is None
    runner.close()


def test_http_boundary_returns_403_for_auth_and_502_for_provider(tmp_path) -> None:
    profile = _profile("gemini-3.5-flash")
    class Transport:
        def generate(self, **_kwargs):
            raise RuntimeError("provider detail must be sanitized")

    gateway = _gateway(profile, Transport(), tmp_path)
    server = serve_gateway(gateway, host="127.0.0.1", port=8765)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        body = json.dumps(_request(profile)).encode()
        for token, expected in (("wrong-token", 403), ("test-token", 502)):
            request = urllib.request.Request(
                "http://127.0.0.1:8765/v1/generate", data=body,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request)
            assert error.value.code == expected
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_post_response_failure_exception_marks_response_received() -> None:
    error = PostResponseFailure("failed")
    assert error.model_response_received is True
    assert error.billing_unknown is True
