from __future__ import annotations

import sys
import types

from langchain_core.messages import HumanMessage, SystemMessage

from utils.llm_factory import GatewayLLM


def test_gateway_llm_uses_provider_shim_and_preserves_usage(monkeypatch) -> None:
    captured: list[dict[str, object]] = []

    def request(payload: dict[str, object]) -> dict[str, object]:
        captured.append(payload)
        return {
            "text": '{"tool":"run_shell","args":{"command":"nmap -sT target"}}',
            "usage": {"input_tokens": 7, "output_tokens": 11, "total_tokens": 18, "usd": 0.1},
        }

    monkeypatch.setitem(sys.modules, "provider_shim", types.SimpleNamespace(request=request))
    llm = GatewayLLM({"model": "locked-model"}).bind_tools([])
    response = llm.invoke([SystemMessage(content="system"), HumanMessage(content="user")])

    assert captured == [{"contents": "[system]\nsystem\n\n[human]\nuser"}]
    assert response.content.startswith('{"tool"')
    assert response.usage_metadata == {"input_tokens": 7, "output_tokens": 11, "total_tokens": 18}


def test_gateway_llm_adds_bound_tool_contract(monkeypatch) -> None:
    captured: list[dict[str, object]] = []

    def request(payload: dict[str, object]) -> dict[str, object]:
        captured.append(payload)
        return {"text": "done", "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}

    monkeypatch.setitem(sys.modules, "provider_shim", types.SimpleNamespace(request=request))

    class Tool:
        name = "run_shell"

        class args_schema:
            @staticmethod
            def model_json_schema() -> dict[str, object]:
                return {"type": "object"}

    GatewayLLM({"model": "locked-model"}).bind_tools([Tool()]).invoke("prompt")
    assert "Available tools" in str(captured[0]["contents"])
    assert '"name": "run_shell"' in str(captured[0]["contents"])
