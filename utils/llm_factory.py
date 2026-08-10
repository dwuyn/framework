import json
import logging
import os
import sys
from abc import ABC, abstractmethod
from typing import Any, Dict, Mapping

from langchain_core.messages import AIMessage

logger = logging.getLogger(__name__)


def _content_text(value: Any) -> str:
    """Serialize LangChain prompts without exposing a direct provider client."""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return json.dumps(dict(value), sort_keys=True, default=str)
    if isinstance(value, (list, tuple)):
        parts: list[str] = []
        for item in value:
            if isinstance(item, Mapping):
                role = str(item.get("role", "user"))
                content = _content_text(item.get("content", ""))
            else:
                role = str(getattr(item, "type", "user"))
                content = _content_text(getattr(item, "content", item))
            if content:
                parts.append(f"[{role}]\n{content}")
        return "\n\n".join(parts)
    return str(value)


def _tool_text(tools: tuple[Any, ...]) -> str:
    if not tools:
        return ""
    descriptions: list[str] = []
    for tool in tools:
        name = str(getattr(tool, "name", "tool"))
        schema = getattr(tool, "args_schema", None)
        schema_value: Any = {}
        if schema is not None:
            model_schema = getattr(schema, "model_json_schema", None)
            if callable(model_schema):
                schema_value = model_schema()
            else:
                schema_value = getattr(schema, "schema", lambda: {})()
        descriptions.append(json.dumps({"name": name, "args": schema_value}, sort_keys=True, default=str))
    return (
        "\n\nAvailable tools (emit exactly one JSON object when a tool is needed):\n"
        + "\n".join(descriptions)
        + "\nUse the form {\"tool\":\"<name>\",\"args\":{...}}."
    )


class GatewayLLM:
    """Minimal LangChain-compatible model bound exclusively to provider_shim."""

    def __init__(self, config: Mapping[str, Any], tools: tuple[Any, ...] = ()) -> None:
        self.config = dict(config)
        self.tools = tuple(tools)

    def bind_tools(self, tools: Any, **_kwargs: Any) -> "GatewayLLM":
        return GatewayLLM(self.config, tuple(tools or ()))

    def invoke(self, prompt: Any, **_kwargs: Any) -> AIMessage:
        adapter_dir = "/opt/adapter"
        if adapter_dir not in sys.path:
            sys.path.insert(0, adapter_dir)
        from provider_shim import request  # type: ignore[import-not-found]

        contents = _content_text(prompt) + _tool_text(self.tools)
        response = request({"contents": contents})
        if not isinstance(response, Mapping):
            raise RuntimeError("provider shim returned a non-object response")
        text = response.get("text")
        usage = response.get("usage")
        if not isinstance(text, str) or not isinstance(usage, Mapping):
            raise RuntimeError("provider shim response is missing text or usage")
        usage_metadata = {
            "input_tokens": int(usage.get("input_tokens", 0)),
            "output_tokens": int(usage.get("output_tokens", 0)),
            "total_tokens": int(usage.get("total_tokens", 0)),
        }
        return AIMessage(
            content=text,
            usage_metadata=usage_metadata,
            response_metadata={"usage": dict(usage), "model_name": self.config.get("model", "")},
        )

class BaseLLMProvider(ABC):
    @abstractmethod
    def create_llm(self, config: Dict[str, Any]) -> Any:
        pass

    @abstractmethod
    def validate_config(self, config: Dict[str, Any]) -> bool:
        pass

class GeminiProvider(BaseLLMProvider):
    def validate_config(self, config: Dict[str, Any]) -> bool:
        return 'api_key' in config and 'model' in config

    def create_llm(self, config: Dict[str, Any]) -> Any:
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            api_key=config['api_key'],
            model=config['model'],
            temperature=config.get('temperature', 0),
            max_tokens=config.get('max_tokens'),
            streaming=config.get('streaming', False),
            timeout=config.get('timeout', 300),
            max_retries=2,
        )

class VertexAIProvider(BaseLLMProvider):
    def validate_config(self, config: Dict[str, Any]) -> bool:
        return 'model' in config

    def create_llm(self, config: Dict[str, Any]) -> Any:
        from langchain_google_vertexai import ChatVertexAI
        return ChatVertexAI(
            model_name=config['model'],
            project=config.get('project'),
            location=config.get('location'),
            temperature=config.get('temperature', 0),
            max_output_tokens=config.get('max_tokens'),
            streaming=config.get('streaming', False),
            max_retries=2,
        )

class OpenAIProvider(BaseLLMProvider):
    def validate_config(self, config: Dict[str, Any]) -> bool:
        return 'api_key' in config and 'model' in config

    def create_llm(self, config: Dict[str, Any]) -> Any:
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            api_key=config['api_key'],
            model=config['model'],
            base_url=config.get('base_url'),
            temperature=config.get('temperature', 0),
            max_tokens=config.get('max_tokens'),
            streaming=config.get('streaming', False),
            timeout=config.get('timeout', 300),
            max_retries=2,
        )

class DeepSeekProvider(BaseLLMProvider):
    def validate_config(self, config: Dict[str, Any]) -> bool:
        return 'api_key' in config and 'model' in config

    def create_llm(self, config: Dict[str, Any]) -> Any:
        from langchain_deepseek import ChatDeepSeek
        return ChatDeepSeek(
            api_key=config['api_key'],
            model=config['model'],
            temperature=config.get('temperature', 0),
            max_tokens=config.get('max_tokens'),
            streaming=config.get('streaming', False),
            timeout=config.get('timeout', 300),
        )

class OllamaProvider(BaseLLMProvider):
    def validate_config(self, config: Dict[str, Any]) -> bool:
        return 'model' in config and 'base_url' in config

    def create_llm(self, config: Dict[str, Any]) -> Any:
        from langchain_ollama import ChatOllama
        timeout = config.get('timeout', 300)
        client_kwargs = dict(config.get('client_kwargs') or {})
        sync_client_kwargs = dict(config.get('sync_client_kwargs') or {})
        async_client_kwargs = dict(config.get('async_client_kwargs') or {})

        if timeout is not None:
            client_kwargs.setdefault('timeout', timeout)
            sync_client_kwargs.setdefault('timeout', timeout)
            async_client_kwargs.setdefault('timeout', timeout)

        return ChatOllama(
            model=config['model'],
            base_url=config['base_url'],
            temperature=config.get('temperature', 0),
            num_predict=config.get('max_tokens'),
            client_kwargs=client_kwargs,
            sync_client_kwargs=sync_client_kwargs,
            async_client_kwargs=async_client_kwargs,
        )

class LLMFactory:
    _providers = {
        'openai': OpenAIProvider(),
        'deepseek': DeepSeekProvider(),
        'gemini': GeminiProvider(),
        'ollama': OllamaProvider(),
        'vertexai': VertexAIProvider()
    }

    @classmethod
    def create_llm(cls, provider: str, config: Dict[str, Any]) -> Any:
        if provider not in cls._providers:
            raise ValueError(f"Unsupported provider: {provider}")
        return cls._providers[provider].create_llm(config)

class LLMManager:
    def __init__(self):
        self._llms = {}
        self._configs = {}

    def create_llm(self, name: str, provider: str, config: Dict[str, Any]) -> Any:
        llm = LLMFactory.create_llm(provider, config)
        self._llms[name] = llm
        self._configs[name] = {'provider': provider, 'config': config}
        return llm

    def get_llm(self, name: str):
        return self._llms.get(name)

llm_manager = LLMManager()

def create_llm_from_config(config: Dict[str, Any]) -> Any:
    if os.environ.get("VERIPLANPT_GATEWAY_LIVE", "").lower() == "true":
        return GatewayLLM(config)
    provider = config.get('provider', 'openai')
    name = config.get('name', 'default')
    clean_config = {k: v for k, v in config.items() if k not in ['provider', 'name']}
    return llm_manager.create_llm(name, provider, clean_config)
