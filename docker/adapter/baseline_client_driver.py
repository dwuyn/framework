#!/usr/bin/env python3
"""One-response, non-interactive adapters for the four baseline clients."""

from __future__ import annotations

import hashlib
import json
import os
from importlib.metadata import version
from pathlib import Path
from typing import Any, Mapping


def _load() -> tuple[str, dict[str, Any], Path]:
    framework = os.environ["VERIPLANPT_FRAMEWORK_NAME"]
    invocation_path = Path(os.environ["VERIPLANPT_PUBLIC_INVOCATION_FILE"])
    invocation = json.loads(invocation_path.read_text(encoding="utf-8"))
    output = Path(os.environ["VERIPLANPT_RUN_DIR"])
    return framework, dict(invocation), output


def _prompt(invocation: Mapping[str, Any]) -> str:
    task = invocation["task"]
    return json.dumps({
        "objective": task.get("objective", ""),
        "target": task.get("target", {}),
        "scope": task.get("scope", {}),
        "budget": int(os.environ.get("VERIPLANPT_MAX_LLM_CALLS", "1")),
    }, sort_keys=True)


def _call(framework: str, prompt: str) -> str:
    if framework == "PentestAgent":
        # The upstream model manager reads OpenAI's standard base-url
        # environment variable.  Keep the actual LangChain/OpenAI client on
        # the locked relay rather than allowing its default public endpoint.
        os.environ["OPENAI_BASE_URL"] = os.environ["OPENAI_BASEURL"]
        from utils.model_manager import get_model  # type: ignore[import-not-found]

        model = get_model("openai")
        if model is None:
            raise RuntimeError("PentestAgent model manager returned no model")
        result = model.invoke(prompt)
        return str(getattr(result, "content", result))
    if framework == "PentestGPT":
        from pentestgpt.config.chat_config import ChatGPTConfig  # type: ignore[import-not-found]
        from pentestgpt.utils.APIs.chatgpt_api import ChatGPTAPI  # type: ignore[import-not-found]

        # Use PentestGPT's public API client class directly; do not enter its
        # interactive main loop or depend on browser-cookie authentication.
        config = ChatGPTConfig()
        config.api_base = os.environ["OPENAI_BASEURL"]
        config.openai_key = os.environ["OPENAI_API_KEY"]
        config.cookie = "local-relay"
        config.log_dir = os.environ["VERIPLANPT_RUN_DIR"]
        client = ChatGPTAPI(config)
        return str(client.send_new_message(prompt)[0])
    if framework == "VulnBot":
        import paramiko  # type: ignore[import-not-found]  # noqa: F401

        if version("paramiko") != "3.4.0":
            raise RuntimeError("VulnBot requires paramiko==3.4.0")
    if framework == "HackSynth":
        if version("openai") != "1.53.0":
            raise RuntimeError("HackSynth requires openai==1.53.0")
    if framework in {"VulnBot", "HackSynth"}:
        if framework == "HackSynth":
            # openai==1.53.0 passes the removed ``proxies`` keyword to
            # httpx==0.28.1.  This adapter-only compatibility seam preserves
            # both pinned dependencies while still using the real SDK.
            import httpx

            original_init = httpx.Client.__init__

            def compatible_init(self: Any, *args: Any, **kwargs: Any) -> None:
                if "proxies" in kwargs and "proxy" not in kwargs:
                    kwargs["proxy"] = kwargs.pop("proxies")
                original_init(self, *args, **kwargs)

            httpx.Client.__init__ = compatible_init  # type: ignore[method-assign]
        from openai import OpenAI

        result = OpenAI(
            api_key=os.environ["OPENAI_API_KEY"],
            base_url=os.environ["OPENAI_BASEURL"],
        ).chat.completions.create(
            model=os.environ["VERIPLANPT_MODEL_LABEL"],
            messages=[{"role": "user", "content": prompt}],
            max_tokens=int(os.environ.get("VERIPLANPT_MAX_OUTPUT_TOKENS", "2048")),
        )
        return str(result.choices[0].message.content or "")
    raise RuntimeError(f"unsupported baseline framework: {framework}")


def main() -> int:
    framework, invocation, output = _load()
    prompt = _prompt(invocation)
    response = _call(framework, prompt)
    evidence = {
        "schema_version": "1.0.0",
        "mode": "actual-sdk-adapter",
        "stage": os.environ.get("VERIPLANPT_STAGE", ""),
        "framework": framework,
        "public_task_hash": hashlib.sha256(
            json.dumps(invocation["task"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "generated_config_hash": os.environ.get("VERIPLANPT_GENERATED_CONFIG_HASH", ""),
        "provider_response_count": 1,
        "phases": ["public_task_request"],
        "outcome": "completed",
        "response_sha256": hashlib.sha256(response.encode()).hexdigest(),
    }
    output.joinpath("driver-evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    output.joinpath("driver-response.json").write_text(
        json.dumps({"text": response}, sort_keys=True) + "\n", encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
