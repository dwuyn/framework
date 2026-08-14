from __future__ import annotations

import httpx
import pytest
from openai import OpenAI

from src.pipeline.runtime_ledger import InvocationLedger
from src.pipeline.vertex_gateway import ProviderGatewayError, VertexGateway
from src.pipeline.vertex_runtime import GeminiExecutor
from tests.test_vertex_runtime import _profile


def test_openai_mock_transport_emits_one_chat_completion_request() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "pong"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            },
        )

    client = OpenAI(
        api_key="test-token",
        base_url="https://gateway.test/v1",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    client.chat.completions.create(
        model="gemini-3.5-flash", messages=[{"role": "user", "content": "ping"}],
    )
    assert [request.url.path for request in requests] == ["/v1/chat/completions"]


def test_openai_mock_transport_does_not_retry_502() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(502, json={"failure_id": "failure-test"})

    client = OpenAI(
        api_key="test-token",
        base_url="https://gateway.test/v1",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(Exception):
        client.chat.completions.create(
            model="gemini-3.5-flash", messages=[{"role": "user", "content": "ping"}],
        )
    assert len(requests) == 1


def test_gateway_attempt_cap_counts_pre_response_failure(tmp_path) -> None:
    profile = _profile("gemini-3.5-flash")
    ledger = InvocationLedger(
        phase="smoke", gateway_relay_lock_hash="a" * 64,
        path=tmp_path / "ledger.json", epoch="epoch-1",
    )

    class FailingTransport:
        def generate(self, **_kwargs: object) -> object:
            error = RuntimeError("local validation")
            error.status_code = 502  # type: ignore[attr-defined]
            raise error

    gateway = VertexGateway(
        profiles=[profile], allowed_run_ids={"run-1"}, token="token",
        gemini=GeminiExecutor(FailingTransport()), gemma=GeminiExecutor(FailingTransport()),
        invocation_ledger=ledger, max_llm_calls_by_run={"run-1": 1}, epoch="epoch-1",
    )
    request = {
        "run_id": "run-1", "model_label": profile.logical_label,
        "profile_hash": profile.profile_hash, "contents": "ping",
        "epoch": "epoch-1", "call_index": 0,
    }
    with pytest.raises(ProviderGatewayError):
        gateway.invoke(request, token="token")
    with pytest.raises(Exception, match="max_llm_calls"):
        gateway.invoke(request, token="token")
    assert ledger.counter_snapshot("run-1", epoch="epoch-1") == {
        "gateway_request_count": 1,
        "provider_attempt_count": 1,
        "provider_response_count": 0,
    }


def test_post_response_replay_does_not_call_provider_again(tmp_path) -> None:
    profile = _profile("gemini-3.5-flash")
    ledger = InvocationLedger(
        phase="smoke", gateway_relay_lock_hash="a" * 64,
        path=tmp_path / "ledger.json", epoch="epoch-1",
    )
    calls = 0

    class Transport:
        def generate(self, **_kwargs: object) -> dict[str, object]:
            nonlocal calls
            calls += 1
            return {"text": "pong", "usage": {"input_tokens": 1, "output_tokens": 1}}

    gateway = VertexGateway(
        profiles=[profile], allowed_run_ids={"run-1"}, token="token",
        gemini=GeminiExecutor(Transport()), gemma=GeminiExecutor(Transport()),
        invocation_ledger=ledger, max_llm_calls_by_run={"run-1": 1}, epoch="epoch-1",
    )
    request = {
        "run_id": "run-1", "model_label": profile.logical_label,
        "profile_hash": profile.profile_hash, "contents": "ping",
        "epoch": "epoch-1", "call_index": 0,
    }
    first = gateway.invoke(request, token="token")
    replay = gateway.invoke(request, token="token")
    assert replay.response_hash == first.response_hash
    assert calls == 1
    assert ledger.counter_snapshot("run-1", epoch="epoch-1")["provider_response_count"] == 1
