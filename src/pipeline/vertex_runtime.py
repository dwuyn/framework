"""Fail-closed Vertex model resolution and provider invocation contracts.

The module deliberately keeps network clients outside the contract layer.  A
caller supplies metadata and a transport, which makes the resolver and the
usage/evidence rules testable without a Vertex or paid request.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.llm_budget import NormalizedUsage, normalize_usage

LOCKED_MODEL_INVOCATIONS: dict[str, dict[str, str]] = {
    "gemini-3.5-flash": {
        "api_family": "google_genai",
        "model_id": "gemini-3.5-flash",
        "location": "global",
    },
    "gemini-3.6-flash": {
        "api_family": "google_genai",
        "model_id": "gemini-3.6-flash",
        "location": "global",
    },
    "gemma-4-26b-a4b-it": {
        "api_family": "vertex_openai_compatible",
        "model_id": "google/gemma-4-26b-a4b-it-maas",
        "location": "global",
    },
}

_NON_PINNED_REVISIONS = {"", "latest", "default", "unknown", "benchmark-pinned"}


class VertexContractError(ValueError):
    """The model or provider response cannot be safely admitted."""


def _canonical_hash(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PricingSnapshot:
    """Hashable pricing input; prices must come from an external snapshot."""

    source_url: str
    retrieved_at: str
    effective_at: str
    model_prices: Mapping[str, Mapping[str, float]]

    REQUIRED_KEYS = frozenset({
        "input_per_million",
        "cached_input_per_million",
        "output_per_million",
        "thinking_per_million",
    })

    def __post_init__(self) -> None:
        if not self.source_url.strip() or not self.retrieved_at.strip() or not self.effective_at.strip():
            raise VertexContractError("pricing snapshot requires source and timestamps")
        if not self.model_prices:
            raise VertexContractError("pricing snapshot must contain model prices")
        for label, prices in self.model_prices.items():
            missing = self.REQUIRED_KEYS.difference(prices)
            if missing:
                raise VertexContractError(
                    f"pricing for {label} is missing: {', '.join(sorted(missing))}"
                )
            if any(float(prices[key]) <= 0 for key in self.REQUIRED_KEYS):
                raise VertexContractError(f"pricing for {label} must be positive")

    @property
    def snapshot_hash(self) -> str:
        return _canonical_hash(self.to_dict(include_hash=False))

    def pricing_for(self, logical_label: str) -> dict[str, float]:
        if logical_label not in self.model_prices:
            raise VertexContractError(f"pricing snapshot has no entry for {logical_label}")
        return {key: float(value) for key, value in self.model_prices[logical_label].items()}

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": "1.0.0",
            "source_url": self.source_url,
            "retrieved_at": self.retrieved_at,
            "effective_at": self.effective_at,
            "currency": "USD",
            "billing_basis": "per_million_tokens",
            "model_prices": {label: dict(prices) for label, prices in self.model_prices.items()},
        }
        if include_hash:
            result["snapshot_hash"] = self.snapshot_hash
        return result


@dataclass(frozen=True)
class ResolvedModel:
    """Metadata-only identity returned by a resolver."""

    logical_label: str
    model_id: str
    resource_id: str
    resource_revision: str
    location: str
    api_family: str
    metadata_hash: str

    def to_dict(self) -> dict[str, str]:
        return {
            "logical_label": self.logical_label,
            "model_id": self.model_id,
            "resource_id": self.resource_id,
            "resource_revision": self.resource_revision,
            "location": self.location,
            "api_family": self.api_family,
            "metadata_hash": self.metadata_hash,
        }

    def to_model_profile(self, pricing: Mapping[str, float], *, pricing_effective_at: str) -> ModelProfile:
        """Build a profile only after identity and pricing are both pinned."""
        if not pricing_effective_at.strip():
            raise VertexContractError("pricing_effective_at is required")
        return ModelProfile.from_dict(
            {
                "logical_label": self.logical_label,
                "provider": "vertexai",
                "location": self.location,
                "resource_id": self.resource_id,
                "resource_revision": self.resource_revision,
                "pricing": dict(pricing),
                "pricing_effective_at": pricing_effective_at,
                "usage_semantics": {
                    "input_includes_cached": "true",
                    "total_formula": "input+output+thinking",
                },
            }
        )


class ModelResolver:
    """Resolve externally verified metadata; never invent an identity."""

    def __init__(self, catalog: Mapping[str, Mapping[str, str]] | None = None) -> None:
        self.catalog = dict(catalog or LOCKED_MODEL_INVOCATIONS)

    def resolve(self, logical_label: str, metadata: Mapping[str, Any]) -> ResolvedModel:
        expected = self.catalog.get(logical_label)
        if expected is None:
            raise VertexContractError(f"model label is not preregistered: {logical_label}")
        model_id = str(metadata.get("model_id") or "")
        resource_id = str(metadata.get("resource_id") or "")
        revision = str(metadata.get("resource_revision") or metadata.get("version") or "")
        location = str(metadata.get("location") or "")
        api_family = str(metadata.get("api_family") or "")
        missing = [
            name for name, value in (
                ("model_id", model_id),
                ("resource_id", resource_id),
                ("resource_revision", revision),
                ("location", location),
                ("api_family", api_family),
            ) if not value.strip()
        ]
        if missing:
            raise VertexContractError(
                f"model metadata for {logical_label} is missing: {', '.join(missing)}"
            )
        if model_id != expected["model_id"]:
            raise VertexContractError(
                f"model ID mismatch for {logical_label}: expected {expected['model_id']!r}"
            )
        if location != expected["location"]:
            raise VertexContractError(
                f"location mismatch for {logical_label}: expected {expected['location']!r}"
            )
        if revision.lower() in _NON_PINNED_REVISIONS:
            raise VertexContractError(f"model revision for {logical_label} is not immutable")
        if resource_id in {logical_label, model_id} or not resource_id.startswith("projects/"):
            raise VertexContractError(f"model resource_id for {logical_label} is not a full Vertex resource")
        if api_family != expected["api_family"]:
            raise VertexContractError(f"provider surface mismatch for {logical_label}")
        canonical_metadata = {key: value for key, value in metadata.items() if key != "metadata_hash"}
        computed_hash = _canonical_hash(canonical_metadata)
        supplied_hash = str(metadata.get("metadata_hash") or computed_hash)
        if supplied_hash != computed_hash:
            raise VertexContractError("metadata_hash does not match supplied metadata")
        metadata_hash = supplied_hash
        if len(metadata_hash) != 64 or any(char not in "0123456789abcdef" for char in metadata_hash):
            raise VertexContractError("metadata_hash must be a SHA-256 hex digest")
        return ResolvedModel(
            logical_label=logical_label,
            model_id=model_id,
            resource_id=resource_id,
            resource_revision=revision,
            location=location,
            api_family=api_family,
            metadata_hash=metadata_hash,
        )

    def resolve_all(self, inventory: Mapping[str, Mapping[str, Any]]) -> list[ResolvedModel]:
        expected_labels = set(self.catalog)
        if set(inventory) != expected_labels:
            raise VertexContractError(
                f"model inventory must contain exactly {sorted(expected_labels)}"
            )
        return [self.resolve(label, inventory[label]) for label in sorted(expected_labels)]


class GeminiTransport(Protocol):
    def generate(
        self, *, model_id: str, contents: Any, generation_parameters: Mapping[str, Any]
    ) -> Any:
        """Return a provider response without changing the response shape."""


class OpenAICompatibleTransport(Protocol):
    def generate(
        self, *, model_id: str, messages: Sequence[Mapping[str, str]], generation_parameters: Mapping[str, Any]
    ) -> Any:
        """Return a provider response without changing the response shape."""


class GoogleGenAITransport:
    """Production transport wrapper; constructing it performs no network call."""

    def __init__(self, client: Any) -> None:
        self.client = client

    def generate(
        self, *, model_id: str, contents: Any, generation_parameters: Mapping[str, Any]
    ) -> Any:
        kwargs: dict[str, Any] = {"model": model_id, "contents": contents}
        if generation_parameters:
            kwargs["config"] = dict(generation_parameters)
        return self.client.models.generate_content(**kwargs)


class OpenAICompatibleClientTransport:
    """Production transport wrapper for Vertex OpenAI-compatible endpoints."""

    def __init__(self, client: Any) -> None:
        self.client = client

    def generate(
        self, *, model_id: str, messages: Sequence[Mapping[str, str]], generation_parameters: Mapping[str, Any]
    ) -> Any:
        kwargs: dict[str, Any] = {"model": model_id, "messages": list(messages)}
        kwargs.update(dict(generation_parameters))
        return self.client.chat.completions.create(**kwargs)


def _response_mapping(response: Any) -> Mapping[str, Any]:
    if isinstance(response, Mapping):
        return response
    for method_name in ("model_dump", "to_dict", "to_json_dict"):
        method = getattr(response, method_name, None)
        if callable(method):
            value = method()
            if isinstance(value, Mapping):
                return value
    raise VertexContractError("provider response must expose a mapping for evidence hashing")


def _response_text(response: Any, payload: Mapping[str, Any]) -> str:
    direct = payload.get("text")
    if isinstance(direct, str):
        return direct
    choices = payload.get("choices")
    if isinstance(choices, Sequence) and not isinstance(choices, (str, bytes)) and choices:
        first = choices[0]
        if isinstance(first, Mapping):
            message = first.get("message")
            if isinstance(message, Mapping) and isinstance(message.get("content"), str):
                return str(message["content"])
            if isinstance(first.get("text"), str):
                return str(first["text"])
    value = getattr(response, "text", None)
    if isinstance(value, str):
        return value
    raise VertexContractError("provider response has no text content")


@dataclass(frozen=True)
class InvocationResult:
    text: str
    usage: NormalizedUsage
    response_hash: str
    model_id: str
    resource_revision: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "usage": self.usage.to_dict(),
            "response_hash": self.response_hash,
            "model_id": self.model_id,
            "resource_revision": self.resource_revision,
        }


class GeminiExecutor:
    """Adapter for the Google GenAI Vertex surface using an injected transport."""

    def __init__(self, transport: GeminiTransport) -> None:
        self.transport = transport

    def invoke(self, profile: ModelProfile, contents: Any) -> InvocationResult:
        expected = LOCKED_MODEL_INVOCATIONS.get(profile.logical_label)
        if expected is None or expected["api_family"] != "google_genai":
            raise VertexContractError("profile does not identify a Gemini model")
        started = time.monotonic()
        response = self.transport.generate(
            model_id=expected["model_id"],
            contents=contents,
            generation_parameters=profile.generation_parameters,
        )
        latency_ms = (time.monotonic() - started) * 1000.0
        payload = _response_mapping(response)
        usage = normalize_usage(payload, profile, latency_ms=latency_ms)
        return InvocationResult(
            text=_response_text(response, payload),
            usage=usage,
            response_hash=_canonical_hash(dict(payload)),
            model_id=expected["model_id"],
            resource_revision=profile.resource_revision,
        )


class GemmaMaaSExecutor:
    """Adapter for Vertex's OpenAI-compatible Gemma MaaS surface."""

    def __init__(self, transport: OpenAICompatibleTransport) -> None:
        self.transport = transport

    def invoke(self, profile: ModelProfile, messages: Sequence[Mapping[str, str]]) -> InvocationResult:
        expected = LOCKED_MODEL_INVOCATIONS.get(profile.logical_label)
        if expected is None or expected["api_family"] != "vertex_openai_compatible":
            raise VertexContractError("profile does not identify the Gemma MaaS model")
        started = time.monotonic()
        response = self.transport.generate(
            model_id=expected["model_id"],
            messages=messages,
            generation_parameters=profile.generation_parameters,
        )
        latency_ms = (time.monotonic() - started) * 1000.0
        payload = _response_mapping(response)
        usage = normalize_usage(payload, profile, latency_ms=latency_ms)
        return InvocationResult(
            text=_response_text(response, payload),
            usage=usage,
            response_hash=_canonical_hash(dict(payload)),
            model_id=expected["model_id"],
            resource_revision=profile.resource_revision,
        )
