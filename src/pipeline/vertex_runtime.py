"""Fail-closed Vertex model resolution and provider invocation contracts.

The module deliberately keeps network clients outside the contract layer.  A
caller supplies metadata and a transport, which makes the resolver and the
usage/evidence rules testable without a Vertex or paid request.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.llm_budget import NormalizedUsage, normalize_usage

LOCKED_MODEL_INVOCATIONS: dict[str, dict[str, str]] = {
    "gemini-3.5-flash": {
        "api_family": "google_genai",
        "model_id": "gemini-3.5-flash",
        "catalog_name": "publishers/google/models/gemini-3.5-flash",
        "location": "global",
    },
    "gemini-3.6-flash": {
        "api_family": "google_genai",
        "model_id": "gemini-3.6-flash",
        "catalog_name": "publishers/google/models/gemini-3.6-flash",
        "location": "global",
    },
    "gemma-4-26b-a4b-it": {
        "api_family": "vertex_openai_compatible",
        "model_id": "google/gemma-4-26b-a4b-it-maas",
        "catalog_name": "publishers/google/models/gemma-4-26b-a4b-it-maas",
        "location": "global",
    },
}

_NON_PINNED_REVISIONS = {"", "latest", "unknown", "benchmark-pinned"}


class VertexContractError(ValueError):
    """The model or provider response cannot be safely admitted."""


class RetryExhausted(RuntimeError):
    """A provider transport exhausted its bounded retry policy."""


def invoke_with_retry(
    operation: Any, *, max_attempts: int = 2, backoff_seconds: float = 0.0,
    sleep: Any = time.sleep,
) -> Any:
    """Retry only transient provider failures; never retry auth failures."""
    if max_attempts < 1:
        raise ValueError("retry policy max_attempts must be positive")
    last: BaseException | None = None
    for attempt in range(max_attempts):
        try:
            return operation()
        except Exception as exc:  # transport implementations expose status_code when available
            last = exc
            status = getattr(exc, "status_code", getattr(exc, "code", None))
            try:
                status_value = int(status) if status is not None else None
            except (TypeError, ValueError):
                status_value = None
            if status_value in {401, 403}:
                raise
            transient = status_value in {408, 425, 429, 500, 502, 503, 504} or status_value is None
            if not transient or attempt + 1 >= max_attempts:
                break
            if backoff_seconds > 0:
                sleep(backoff_seconds * (2 ** attempt))
    raise RetryExhausted(f"provider retry policy exhausted after {max_attempts} attempts") from last


def _canonical_hash(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def validate_resolution_fields(
    logical_label: str,
    resource_revision: str,
    resolution_mode: str = "immutable",
    resolution_evidence_hash: str = "",
    resolution_resolved_at: str = "",
) -> None:
    """Validate resolution identity on profiles, matrix rows and evidence."""
    if resolution_mode not in {"immutable", "provider_alias"}:
        raise VertexContractError("resolution_mode must be immutable or provider_alias")
    revision = resource_revision.lower()
    if revision in _NON_PINNED_REVISIONS:
        raise VertexContractError("model revision is not immutable")
    if revision != "default":
        if resolution_mode == "provider_alias":
            raise VertexContractError("provider_alias requires resource_revision=default")
        return
    if logical_label not in {"gemini-3.5-flash", "gemini-3.6-flash"}:
        raise VertexContractError("default alias is allowed only for locked Gemini models")
    if resolution_mode != "provider_alias":
        raise VertexContractError("default model revision requires explicit provider_alias mode")
    if len(resolution_evidence_hash) != 64 or any(
        char not in "0123456789abcdef" for char in resolution_evidence_hash.lower()
    ):
        raise VertexContractError("provider_alias requires a resolution evidence SHA-256")
    if not resolution_resolved_at.strip():
        raise VertexContractError("provider_alias requires resolution_resolved_at")


@dataclass(frozen=True)
class PricingSnapshot:
    """Hashable pricing input; prices must come from an external snapshot."""

    source_url: str
    retrieved_at: str
    effective_at: str
    model_prices: Mapping[str, Mapping[str, float]]
    region: str = "global"
    package: str = "Standard"
    unit: str = "USD/token"
    billing_semantics: str = "reasoning_billed_once_with_output"
    thinking_enabled: Mapping[str, bool] | None = None

    REQUIRED_KEYS = frozenset({
        "input_per_million",
        "cached_input_per_million",
        "output_per_million",
    })
    TOKEN_KEYS = frozenset({
        "input_usd_per_token",
        "cached_input_usd_per_token",
        "output_usd_per_token",
    })

    def __post_init__(self) -> None:
        if not self.source_url.strip() or not self.retrieved_at.strip() or not self.effective_at.strip():
            raise VertexContractError("pricing snapshot requires source and timestamps")
        if self.region != "global" or self.package != "Standard" or self.unit != "USD/token":
            raise VertexContractError("pricing snapshot must be global Standard USD/token")
        if self.billing_semantics != "reasoning_billed_once_with_output":
            raise VertexContractError("pricing snapshot billing semantics are unsupported")
        if not self.model_prices:
            raise VertexContractError("pricing snapshot must contain model prices")
        for label, prices in self.model_prices.items():
            names = set(prices)
            if self.REQUIRED_KEYS <= names:
                normalized = {key: float(prices[key]) for key in self.REQUIRED_KEYS}
            elif self.TOKEN_KEYS <= names:
                normalized = {
                    key.replace("_usd_per_token", "_per_million"): float(prices[key]) * 1_000_000
                    for key in self.TOKEN_KEYS
                }
            else:
                missing = self.REQUIRED_KEYS.difference(names)
                raise VertexContractError(
                    f"pricing for {label} is missing: {', '.join(sorted(missing))}"
                )
            if any(not math.isfinite(value) or value <= 0 for value in normalized.values()):
                raise VertexContractError(f"pricing for {label} must be positive and finite")
            if self.thinking_enabled and label not in self.thinking_enabled:
                raise VertexContractError(f"pricing thinking_enabled is missing {label}")
            if self.thinking_enabled and label == "gemma-4-26b-a4b-it" and self.thinking_enabled[label]:
                raise VertexContractError("Gemma thinking must be disabled")

    @property
    def snapshot_hash(self) -> str:
        return _canonical_hash(self.to_dict(include_hash=False))

    def pricing_for(self, logical_label: str) -> dict[str, float]:
        if logical_label not in self.model_prices:
            raise VertexContractError(f"pricing snapshot has no entry for {logical_label}")
        prices = self.model_prices[logical_label]
        if self.REQUIRED_KEYS <= set(prices):
            return {key: float(prices[key]) for key in prices}
        return {
            key.replace("_usd_per_token", "_per_million"): float(prices[key]) * 1_000_000
            for key in prices
            if key in self.TOKEN_KEYS
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PricingSnapshot":
        raw_prices = value.get("model_prices")
        if not isinstance(raw_prices, Mapping):
            raise VertexContractError("pricing snapshot model_prices must be an object")
        thinking = value.get("thinking_enabled")
        return cls(
            source_url=str(value.get("source_url", "")),
            retrieved_at=str(value.get("retrieved_at", "")),
            effective_at=str(value.get("effective_at", "")),
            model_prices={
                str(label): {str(key): float(price) for key, price in dict(prices).items()}
                for label, prices in raw_prices.items() if isinstance(prices, Mapping)
            },
            region=str(value.get("region", "global")),
            package=str(value.get("package", "Standard")),
            unit=str(value.get("unit", "USD/token")),
            billing_semantics=str(value.get("billing_semantics", "reasoning_billed_once_with_output")),
            thinking_enabled={str(label): bool(enabled) for label, enabled in dict(thinking).items()}
            if isinstance(thinking, Mapping) else None,
        )

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": "1.0.0",
            "source_url": self.source_url,
            "retrieved_at": self.retrieved_at,
            "effective_at": self.effective_at,
            "region": self.region,
            "package": self.package,
            "currency": "USD",
            "billing_basis": "per_token",
            "unit": self.unit,
            "billing_semantics": self.billing_semantics,
            "thinking_enabled": dict(self.thinking_enabled or {}),
            "model_prices": {
                label: {
                    key.replace("_per_million", "_usd_per_token"): float(value) / 1_000_000
                    for key, value in self.pricing_for(label).items()
                    if key in self.REQUIRED_KEYS
                }
                for label in self.model_prices
            },
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
    resolution_mode: str
    resolution_evidence_hash: str
    resolution_resolved_at: str
    endpoint_url: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "logical_label": self.logical_label,
            "model_id": self.model_id,
            "resource_id": self.resource_id,
            "resource_revision": self.resource_revision,
            "location": self.location,
            "api_family": self.api_family,
            "metadata_hash": self.metadata_hash,
            "resolution_mode": self.resolution_mode,
            "resolution_evidence_hash": self.resolution_evidence_hash,
            "resolution_resolved_at": self.resolution_resolved_at,
            "endpoint_url": self.endpoint_url,
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
                "resolution_mode": self.resolution_mode,
                "resolution_evidence_hash": self.resolution_evidence_hash,
                "resolution_resolved_at": self.resolution_resolved_at,
                "endpoint_url": self.endpoint_url,
                "pricing": dict(pricing),
                "pricing_effective_at": pricing_effective_at,
                "usage_semantics": {
                    "input_includes_cached": "true",
                    "total_formula": "input+output",
                    "output_includes_reasoning": "true",
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
        resolution_mode = str(metadata.get("resolution_mode") or "immutable")
        resolution_evidence_hash = str(metadata.get("resolution_evidence_hash") or "")
        resolution_resolved_at = str(metadata.get("resolution_resolved_at") or "")
        endpoint_url = str(metadata.get("endpoint_url") or metadata.get("inference_endpoint") or "")
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
        if resolution_mode not in {"immutable", "provider_alias"}:
            raise VertexContractError("resolution_mode must be immutable or provider_alias")
        if revision.lower() == "default":
            if logical_label not in {"gemini-3.5-flash", "gemini-3.6-flash"}:
                raise VertexContractError("default alias is allowed only for locked Gemini models")
            if resolution_mode != "provider_alias":
                raise VertexContractError("default model revision requires explicit provider_alias mode")
            if len(resolution_evidence_hash) != 64 or any(
                char not in "0123456789abcdef" for char in resolution_evidence_hash.lower()
            ):
                raise VertexContractError("provider_alias requires a resolution evidence SHA-256")
            if not resolution_resolved_at.strip():
                raise VertexContractError("provider_alias requires resolution_resolved_at")
        elif resolution_mode == "provider_alias":
            raise VertexContractError("provider_alias requires resource_revision=default")
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
            resolution_mode=resolution_mode,
            resolution_evidence_hash=resolution_evidence_hash,
            resolution_resolved_at=resolution_resolved_at,
            endpoint_url=endpoint_url,
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
