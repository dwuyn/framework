from __future__ import annotations

import pytest

from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.vertex_runtime import (
    GeminiExecutor,
    GemmaMaaSExecutor,
    ModelResolver,
    PricingSnapshot,
    VertexContractError,
)


def _profile(label: str, resource_id: str = "projects/p/locations/global/publishers/google/models/x") -> ModelProfile:
    return ModelProfile.from_dict(
        {
            "logical_label": label,
            "location": "global",
            "resource_id": resource_id,
            "resource_revision": "v20260805",
            "pricing": {
                "input_per_million": 1.0,
                "cached_input_per_million": 0.5,
                "output_per_million": 2.0,
                "thinking_per_million": 2.0,
            },
            "pricing_effective_at": "2026-08-05T00:00:00Z",
            "usage_semantics": {
                "input_includes_cached": "true",
                "total_formula": "input+output+thinking",
            },
        }
    )


def _metadata(label: str) -> dict[str, str]:
    model_id = label if label != "gemma-4-26b-a4b-it" else "google/gemma-4-26b-a4b-it-maas"
    api_family = "vertex_openai_compatible" if label == "gemma-4-26b-a4b-it" else "google_genai"
    return {
        "model_id": model_id,
        "resource_id": f"projects/p/locations/global/publishers/google/models/{label}",
        "resource_revision": "v20260805",
        "location": "global",
        "api_family": api_family,
    }


def test_resolver_requires_exact_locked_inventory() -> None:
    resolved = ModelResolver().resolve_all({label: _metadata(label) for label in ModelResolver().catalog})
    assert [item.logical_label for item in resolved] == sorted(ModelResolver().catalog)
    assert all(len(item.metadata_hash) == 64 for item in resolved)


def test_resolver_rejects_alias_and_fake_resource() -> None:
    metadata = _metadata("gemini-3.6-flash")
    metadata["resource_revision"] = "latest"
    with pytest.raises(VertexContractError, match="not immutable"):
        ModelResolver().resolve("gemini-3.6-flash", metadata)


def test_resolver_allows_explicit_gemini_provider_alias() -> None:
    metadata = _metadata("gemini-3.6-flash")
    metadata.update({
        "resource_revision": "default",
        "resolution_mode": "provider_alias",
        "resolution_evidence_hash": "a" * 64,
        "resolution_resolved_at": "2026-08-05T00:00:00Z",
    })
    resolved = ModelResolver().resolve("gemini-3.6-flash", metadata)
    assert resolved.resolution_mode == "provider_alias"
    profile = resolved.to_model_profile(
        {"input_per_million": 1.0, "cached_input_per_million": 0.5,
         "output_per_million": 2.0, "thinking_per_million": 2.0},
        pricing_effective_at="2026-08-05T00:00:00Z",
    )
    assert profile.resolution_mode == "provider_alias"


def test_resolver_rejects_alias_without_explicit_exception() -> None:
    metadata = _metadata("gemini-3.6-flash")
    metadata["resource_revision"] = "default"
    with pytest.raises(VertexContractError, match="provider_alias"):
        ModelResolver().resolve("gemini-3.6-flash", metadata)
    metadata["resource_revision"] = "v20260805"
    metadata["resource_id"] = "gemini-3.6-flash"
    with pytest.raises(VertexContractError, match="full Vertex resource"):
        ModelResolver().resolve("gemini-3.6-flash", metadata)


def test_resolver_rejects_model_surface_mismatch() -> None:
    metadata = _metadata("gemini-3.6-flash")
    metadata["api_family"] = "vertex_openai_compatible"
    with pytest.raises(VertexContractError, match="provider surface"):
        ModelResolver().resolve("gemini-3.6-flash", metadata)


def test_resolver_rejects_tampered_metadata_hash() -> None:
    metadata = _metadata("gemini-3.6-flash")
    metadata["metadata_hash"] = "0" * 64
    with pytest.raises(VertexContractError, match="metadata_hash"):
        ModelResolver().resolve("gemini-3.6-flash", metadata)


def test_pricing_snapshot_is_hashable_and_profile_ready() -> None:
    snapshot = PricingSnapshot(
        source_url="https://cloud.google.com/vertex-ai/generative-ai/pricing",
        retrieved_at="2026-08-05T00:00:00Z",
        effective_at="2026-08-05T00:00:00Z",
        model_prices={
            "gemini-3.6-flash": {
                "input_per_million": 1.0,
                "cached_input_per_million": 0.5,
                "output_per_million": 2.0,
                "thinking_per_million": 2.0,
            }
        },
    )
    profile = ModelResolver().resolve("gemini-3.6-flash", _metadata("gemini-3.6-flash"))
    built = profile.to_model_profile(
        snapshot.pricing_for("gemini-3.6-flash"),
        pricing_effective_at=snapshot.effective_at,
    )
    assert built.profile_hash
    assert len(snapshot.snapshot_hash) == 64


class _GeminiTransport:
    def generate(self, *, model_id, contents, generation_parameters):
        assert model_id == "gemini-3.6-flash"
        assert contents == "ping"
        assert generation_parameters == {}
        return {"text": "pong", "usage": {"input_tokens": 4, "output_tokens": 2}}


class _GemmaTransport:
    def generate(self, *, model_id, messages, generation_parameters):
        assert model_id == "google/gemma-4-26b-a4b-it-maas"
        assert messages == [{"role": "user", "content": "ping"}]
        assert generation_parameters == {}
        return {
            "choices": [{"message": {"content": "pong"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
        }


def test_gemini_executor_normalizes_fake_response() -> None:
    result = GeminiExecutor(_GeminiTransport()).invoke(_profile("gemini-3.6-flash"), "ping")
    assert result.text == "pong"
    assert result.usage.input_tokens == 4
    assert result.usage.output_tokens == 2
    assert result.model_id == "gemini-3.6-flash"
    assert len(result.response_hash) == 64


def test_gemma_executor_normalizes_openai_response() -> None:
    result = GemmaMaaSExecutor(_GemmaTransport()).invoke(
        _profile("gemma-4-26b-a4b-it"), [{"role": "user", "content": "ping"}]
    )
    assert result.text == "pong"
    assert result.usage.total_tokens == 8
    assert result.model_id == "google/gemma-4-26b-a4b-it-maas"


def test_executor_rejects_wrong_provider_surface() -> None:
    with pytest.raises(VertexContractError, match="Gemini"):
        GeminiExecutor(_GeminiTransport()).invoke(_profile("gemma-4-26b-a4b-it"), "ping")
